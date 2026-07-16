from __future__ import annotations

import hashlib
import mimetypes
import os
from pathlib import Path
from typing import Callable, Iterable

from ..models import Finding, Severity


SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
NATIVE_EXTENSIONS = {".exe", ".dll", ".pyd", ".sys", ".scr", ".com"}
MODEL_EXTENSIONS = {
    ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib", ".sav", ".bin",
    ".npy", ".npz", ".safetensors", ".keras", ".h5", ".hdf5",
}


def enumerate_files(root: Path, follow_symlinks: bool = False) -> Iterable[Path]:
    stack = [root]
    visited: set[tuple[int, int]] = set()
    while stack:
        current = stack.pop()
        try:
            stat = current.stat(follow_symlinks=follow_symlinks)
        except (OSError, PermissionError):
            continue
        marker = (getattr(stat, "st_dev", 0), getattr(stat, "st_ino", 0))
        if marker in visited:
            continue
        visited.add(marker)

        if current.is_file():
            yield current
            continue
        try:
            entries = list(os.scandir(current))
        except (OSError, PermissionError):
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_symlink() and not follow_symlinks:
                    continue
                if entry.is_dir(follow_symlinks=follow_symlinks):
                    stack.append(path)
                elif entry.is_file(follow_symlinks=follow_symlinks):
                    yield path
            except OSError:
                continue


def sha256_file(path: Path, cancel_check: Callable[[], bool]) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            if cancel_check():
                return ""
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_inventory(
    files: list[Path],
    hashes: bool,
    max_file_bytes: int,
    cancel_check: Callable[[], bool],
    progress: Callable[[int, int, str], None],
) -> tuple[list[dict], list[Finding]]:
    inventory: list[dict] = []
    findings: list[Finding] = []
    total = max(len(files), 1)

    for index, path in enumerate(files, 1):
        if cancel_check():
            break
        try:
            size = path.stat().st_size
        except OSError as exc:
            findings.append(Finding(
                scanner="Inventory",
                severity=Severity.LOW,
                title="File could not be read",
                description=str(exc),
                path=str(path),
                rule_id="INV-READ",
            ))
            progress(index, total, str(path))
            continue

        suffix = path.suffix.lower()
        record = {
            "path": str(path),
            "size": size,
            "suffix": suffix,
            "mime": mimetypes.guess_type(path.name)[0] or "",
            "sha256": "",
        }
        if hashes and size <= max_file_bytes:
            try:
                record["sha256"] = sha256_file(path, cancel_check)
            except (OSError, PermissionError) as exc:
                findings.append(Finding(
                    scanner="Inventory",
                    severity=Severity.LOW,
                    title="Hash calculation failed",
                    description=str(exc),
                    path=str(path),
                    rule_id="INV-HASH",
                ))
        elif hashes and size > max_file_bytes:
            record["hash_skipped"] = "file-size-limit"

        if suffix in NATIVE_EXTENSIONS:
            findings.append(Finding(
                scanner="Inventory",
                severity=Severity.INFO,
                title="Native executable component",
                description="Native code cannot be meaningfully reviewed by Python AST scanners.",
                path=str(path),
                rule_id="INV-NATIVE",
                recommendation="Review provenance, signature and antivirus results.",
            ))
        elif suffix in SCRIPT_EXTENSIONS:
            findings.append(Finding(
                scanner="Inventory",
                severity=Severity.INFO,
                title="Auxiliary script present",
                description="The application contains a shell or script-host file.",
                path=str(path),
                rule_id="INV-SCRIPT",
            ))
        elif suffix in MODEL_EXTENSIONS:
            record["model_candidate"] = True

        inventory.append(record)
        progress(index, total, str(path))

    return inventory, findings
