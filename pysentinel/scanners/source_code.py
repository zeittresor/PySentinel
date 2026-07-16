from __future__ import annotations

import ast
import math
import re
from collections import Counter
from pathlib import Path

from ..models import Finding, Severity


CALL_RULES = {
    "eval": (Severity.HIGH, "Dynamic eval()", "SRC-EVAL"),
    "exec": (Severity.HIGH, "Dynamic exec()", "SRC-EXEC"),
    "compile": (Severity.MEDIUM, "Dynamic compile()", "SRC-COMPILE"),
    "os.system": (Severity.HIGH, "Shell command through os.system", "SRC-OS-SYSTEM"),
    "pickle.load": (Severity.HIGH, "Unsafe Pickle deserialization", "SRC-PICKLE"),
    "pickle.loads": (Severity.HIGH, "Unsafe Pickle deserialization", "SRC-PICKLE"),
    "dill.load": (Severity.HIGH, "Dill deserialization", "SRC-DILL"),
    "dill.loads": (Severity.HIGH, "Dill deserialization", "SRC-DILL"),
    "marshal.loads": (Severity.HIGH, "marshal.loads usage", "SRC-MARSHAL"),
    "ctypes.CDLL": (Severity.MEDIUM, "Native library loading", "SRC-CTYPES"),
    "ctypes.WinDLL": (Severity.MEDIUM, "Native Windows library loading", "SRC-CTYPES"),
    "importlib.import_module": (Severity.LOW, "Dynamic module import", "SRC-DYNIMPORT"),
}

TEXT_RULES = [
    (re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.I), Severity.MEDIUM, "PowerShell invocation string", "SRC-POWERSHELL"),
    (re.compile(r"\b(?:schtasks|reg\s+add|runonce|startup)\b", re.I), Severity.MEDIUM, "Persistence-related command string", "SRC-PERSIST"),
    (re.compile(r"\b(?:certutil|bitsadmin|mshta|rundll32)\b", re.I), Severity.HIGH, "Living-off-the-land utility reference", "SRC-LOLBIN"),
    (re.compile(r"(?:from_char_code|base64\.b64decode|codecs\.decode)", re.I), Severity.LOW, "Encoded payload helper", "SRC-ENCODING"),
    (re.compile(r"(?:discord(?:app)?\.com/api/webhooks|api\.telegram\.org)", re.I), Severity.MEDIUM, "Webhook or bot endpoint", "SRC-WEBHOOK"),
]


def _qualname(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualname(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    size = len(text)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def scan_source_file(path: Path, max_bytes: int) -> list[Finding]:
    findings: list[Finding] = []
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return [Finding(
                scanner="Source",
                severity=Severity.INFO,
                title="Source file skipped because of size limit",
                description=f"The file is {size} bytes.",
                path=str(path),
                rule_id="SRC-SIZE",
            )]
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [Finding(
            scanner="Source",
            severity=Severity.LOW,
            title="Source file could not be read",
            description=str(exc),
            path=str(path),
            rule_id="SRC-READ",
        )]

    for pattern, severity, title, rule_id in TEXT_RULES:
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            findings.append(Finding(
                scanner="Source",
                severity=severity,
                title=title,
                description="A security-relevant string pattern was found. Context determines whether it is legitimate.",
                path=str(path),
                line=line,
                rule_id=rule_id,
                evidence=match.group(0),
            ))

    long_strings = re.findall(r"['\"]([A-Za-z0-9+/=_-]{300,})['\"]", text)
    if any(_entropy(item) > 4.5 for item in long_strings):
        findings.append(Finding(
            scanner="Source",
            severity=Severity.MEDIUM,
            title="High-entropy embedded string",
            description="A long encoded or compressed-looking string is embedded in source code.",
            path=str(path),
            rule_id="SRC-ENTROPY",
            recommendation="Inspect how the string is decoded and used.",
        ))

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        findings.append(Finding(
            scanner="Source",
            severity=Severity.LOW,
            title="Python source could not be parsed",
            description=str(exc),
            path=str(path),
            line=exc.lineno,
            rule_id="SRC-SYNTAX",
        ))
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _qualname(node.func)
            if name in CALL_RULES:
                severity, title, rule_id = CALL_RULES[name]
                findings.append(Finding(
                    scanner="Source",
                    severity=severity,
                    title=title,
                    description=f"Call to `{name}` found. This may be legitimate but is security-sensitive.",
                    path=str(path),
                    line=getattr(node, "lineno", None),
                    rule_id=rule_id,
                ))
            if name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"}:
                shell_true = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
                findings.append(Finding(
                    scanner="Source",
                    severity=Severity.HIGH if shell_true else Severity.LOW,
                    title="Subprocess execution" + (" with shell=True" if shell_true else ""),
                    description="The application starts an external process.",
                    path=str(path),
                    line=getattr(node, "lineno", None),
                    rule_id="SRC-SUBPROCESS-SHELL" if shell_true else "SRC-SUBPROCESS",
                ))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            module = ""
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
            else:
                module = ",".join(alias.name for alias in node.names)
            if any(part in module for part in ("winreg", "ctypes", "socket")):
                findings.append(Finding(
                    scanner="Source",
                    severity=Severity.INFO,
                    title="Security-relevant module imported",
                    description=f"Import: {module}",
                    path=str(path),
                    line=getattr(node, "lineno", None),
                    rule_id="SRC-IMPORT",
                ))
    return findings
