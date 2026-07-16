from __future__ import annotations

import ast
import io
import json
import pickletools
import struct
import zipfile
from pathlib import Path

from ..models import Finding, Severity


DANGEROUS_PICKLE_OPS = {
    "GLOBAL": Severity.HIGH,
    "STACK_GLOBAL": Severity.HIGH,
    "REDUCE": Severity.HIGH,
    "INST": Severity.HIGH,
    "OBJ": Severity.HIGH,
    "NEWOBJ": Severity.MEDIUM,
    "NEWOBJ_EX": Severity.MEDIUM,
    "EXT1": Severity.MEDIUM,
    "EXT2": Severity.MEDIUM,
    "EXT4": Severity.MEDIUM,
}

SUSPICIOUS_GLOBALS = {
    "os system", "posix system", "subprocess popen", "builtins eval",
    "builtins exec", "builtins compile", "nt system", "marshal loads",
}


def _scan_pickle_bytes(data: bytes, virtual_path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        for opcode, argument, position in pickletools.genops(data):
            severity = DANGEROUS_PICKLE_OPS.get(opcode.name)
            if severity is not None:
                argument_text = str(argument or "")
                if opcode.name == "GLOBAL" and argument_text.lower() in SUSPICIOUS_GLOBALS:
                    severity = Severity.CRITICAL
                findings.append(Finding(
                    scanner="Pickle",
                    severity=severity,
                    title=f"Pickle opcode {opcode.name}",
                    description="This opcode can participate in object construction or callable execution during deserialization.",
                    path=virtual_path,
                    rule_id=f"PKL-{opcode.name}",
                    evidence=f"offset={position}; argument={argument_text}",
                    recommendation="Do not load the file in a trusted environment until provenance and expected globals are verified.",
                ))
    except Exception as exc:
        findings.append(Finding(
            scanner="Pickle",
            severity=Severity.LOW,
            title="Pickle stream could not be fully parsed",
            description=str(exc),
            path=virtual_path,
            rule_id="PKL-PARSE",
        ))
    return findings


def _read_npy_header(handle: io.BufferedReader | io.BytesIO, virtual_path: str) -> list[Finding]:
    findings: list[Finding] = []
    magic = handle.read(6)
    if magic != b"\x93NUMPY":
        return findings
    version = handle.read(2)
    if len(version) != 2:
        return findings
    major = version[0]
    length_size = 2 if major == 1 else 4
    length_raw = handle.read(length_size)
    if len(length_raw) != length_size:
        return findings
    header_len = struct.unpack("<H" if length_size == 2 else "<I", length_raw)[0]
    if header_len > 1024 * 1024:
        return [Finding(
            scanner="Tensor",
            severity=Severity.MEDIUM,
            title="Unusually large NPY header",
            description=f"Header length: {header_len} bytes.",
            path=virtual_path,
            rule_id="NPY-HEADER-SIZE",
        )]
    header_text = handle.read(header_len).decode("latin-1", errors="replace")
    try:
        header = ast.literal_eval(header_text.strip())
        if header.get("descr", "").startswith("|O") or "O" in str(header.get("descr", "")):
            findings.append(Finding(
                scanner="Tensor",
                severity=Severity.HIGH,
                title="NPY object array may require Pickle",
                description="The NumPy dtype indicates Python objects. Loading may invoke Pickle when allow_pickle is enabled.",
                path=virtual_path,
                rule_id="NPY-OBJECT",
            ))
    except Exception as exc:
        findings.append(Finding(
            scanner="Tensor",
            severity=Severity.LOW,
            title="NPY header could not be parsed",
            description=str(exc),
            path=virtual_path,
            rule_id="NPY-HEADER",
        ))
    return findings


def _scan_zip(path: Path, max_entries: int, max_member_bytes: int) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > max_entries:
                findings.append(Finding(
                    scanner="Archive",
                    severity=Severity.MEDIUM,
                    title="Archive entry limit exceeded",
                    description=f"Archive contains {len(infos)} entries; only the first {max_entries} are inspected.",
                    path=str(path),
                    rule_id="ARC-ENTRY-LIMIT",
                ))
                infos = infos[:max_entries]
            total_uncompressed = sum(info.file_size for info in infos)
            total_compressed = max(sum(info.compress_size for info in infos), 1)
            if total_uncompressed / total_compressed > 200:
                findings.append(Finding(
                    scanner="Archive",
                    severity=Severity.HIGH,
                    title="High archive expansion ratio",
                    description="The archive has a zip-bomb-like compression ratio.",
                    path=str(path),
                    rule_id="ARC-RATIO",
                ))

            for info in infos:
                name = info.filename
                lowered = name.lower()
                if ".." in Path(name).parts or Path(name).is_absolute():
                    findings.append(Finding(
                        scanner="Archive",
                        severity=Severity.HIGH,
                        title="Archive path traversal entry",
                        description="An entry could escape a naïve extraction directory.",
                        path=f"{path}!{name}",
                        rule_id="ARC-TRAVERSAL",
                    ))
                if info.file_size > max_member_bytes:
                    continue
                if lowered.endswith((".pkl", ".pickle", "data.pkl")):
                    with archive.open(info) as member:
                        findings.extend(_scan_pickle_bytes(member.read(max_member_bytes + 1), f"{path}!{name}"))
                elif lowered.endswith(".npy"):
                    with archive.open(info) as member:
                        findings.extend(_read_npy_header(io.BytesIO(member.read(min(info.file_size, 1024 * 1024))), f"{path}!{name}"))
                elif path.suffix.lower() == ".keras" and lowered.endswith("config.json"):
                    with archive.open(info) as member:
                        data = member.read(min(info.file_size, max_member_bytes))
                    try:
                        config = json.loads(data.decode("utf-8", errors="replace"))
                        text = json.dumps(config)
                        if '"class_name": "Lambda"' in text or '"class_name":"Lambda"' in text:
                            findings.append(Finding(
                                scanner="Tensor",
                                severity=Severity.HIGH,
                                title="Keras Lambda layer",
                                description="Lambda layers may embed executable Python behavior or non-portable code.",
                                path=f"{path}!{name}",
                                rule_id="KERAS-LAMBDA",
                            ))
                    except json.JSONDecodeError:
                        pass
    except (OSError, zipfile.BadZipFile) as exc:
        findings.append(Finding(
            scanner="Archive",
            severity=Severity.LOW,
            title="Archive could not be inspected",
            description=str(exc),
            path=str(path),
            rule_id="ARC-READ",
        ))
    return findings


def scan_pickle_and_model_file(path: Path, max_file_bytes: int, max_entries: int) -> list[Finding]:
    suffix = path.suffix.lower()
    try:
        size = path.stat().st_size
    except OSError:
        return []

    if size > max_file_bytes:
        return [Finding(
            scanner="Model",
            severity=Severity.INFO,
            title="Model file skipped because of size limit",
            description=f"The file is {size} bytes.",
            path=str(path),
            rule_id="MODEL-SIZE",
        )]

    if suffix in {".pkl", ".pickle", ".joblib", ".sav"}:
        try:
            return _scan_pickle_bytes(path.read_bytes(), str(path))
        except OSError as exc:
            return [Finding(
                scanner="Pickle",
                severity=Severity.LOW,
                title="Pickle candidate could not be read",
                description=str(exc),
                path=str(path),
                rule_id="PKL-READ",
            )]

    if suffix in {".pt", ".pth", ".ckpt", ".bin", ".npz", ".keras"}:
        if zipfile.is_zipfile(path):
            return _scan_zip(path, max_entries, max_file_bytes)
        if suffix in {".pt", ".pth", ".ckpt", ".bin"}:
            try:
                return _scan_pickle_bytes(path.read_bytes(), str(path))
            except OSError:
                return []

    if suffix == ".npy":
        try:
            with path.open("rb") as handle:
                return _read_npy_header(handle, str(path))
        except OSError:
            return []

    if suffix == ".safetensors":
        try:
            with path.open("rb") as handle:
                raw = handle.read(8)
                if len(raw) != 8:
                    raise ValueError("Missing SafeTensors header length")
                header_len = struct.unpack("<Q", raw)[0]
                if header_len > min(size, 100 * 1024 * 1024):
                    return [Finding(
                        scanner="Tensor",
                        severity=Severity.HIGH,
                        title="Invalid or excessive SafeTensors header",
                        description=f"Declared header length: {header_len}",
                        path=str(path),
                        rule_id="SAFE-HEADER",
                    )]
                header = json.loads(handle.read(header_len).decode("utf-8"))
                if "__metadata__" in header:
                    return [Finding(
                        scanner="Tensor",
                        severity=Severity.INFO,
                        title="SafeTensors metadata present",
                        description="Metadata was parsed without loading tensor payloads.",
                        path=str(path),
                        rule_id="SAFE-METADATA",
                    )]
        except Exception as exc:
            return [Finding(
                scanner="Tensor",
                severity=Severity.MEDIUM,
                title="SafeTensors structure could not be validated",
                description=str(exc),
                path=str(path),
                rule_id="SAFE-PARSE",
            )]
    return []
