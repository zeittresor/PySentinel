from __future__ import annotations

import json
import os
import shutil
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from .models import Finding, Severity


def _tool_command(name: str) -> list[str] | None:
    executable = shutil.which(name)
    if executable:
        return [executable]
    module_names = {
        "bandit": "bandit",
        "pip-audit": "pip_audit",
        "modelscan": "modelscan",
        "fickling": "fickling",
    }
    module = module_names.get(name)
    if module:
        return [sys.executable, "-m", module]
    return None


def run_process(
    command: list[str],
    cancel_check: Callable[[], bool],
    pause_wait: Callable[[], None],
    log: Callable[[str], None],
    cwd: Path | None = None,
) -> tuple[int, str]:
    """Run a child process without blocking the scan worker on stdout reads."""
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        command,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
        bufsize=1,
    )
    output_queue: queue.Queue[str | None] = queue.Queue()
    lines: list[str] = []

    def reader() -> None:
        try:
            if process.stdout:
                for line in iter(process.stdout.readline, ""):
                    output_queue.put(line)
        finally:
            output_queue.put(None)

    reader_thread = threading.Thread(target=reader, name="PySentinelProcessReader", daemon=True)
    reader_thread.start()
    reader_done = False

    while True:
        pause_wait()
        if cancel_check():
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
            return 130, "\n".join(lines)

        try:
            item = output_queue.get(timeout=0.1)
            if item is None:
                reader_done = True
            else:
                line = item.rstrip()
                if line:
                    lines.append(line)
                    log(line)
        except queue.Empty:
            pass

        if process.poll() is not None and reader_done and output_queue.empty():
            break

    return process.returncode, "\n".join(lines)


def run_bandit(
    target: Path,
    cancel_check: Callable[[], bool],
    pause_wait: Callable[[], None],
    log: Callable[[str], None],
) -> tuple[list[Finding], str]:
    base = _tool_command("bandit")
    if not base:
        return [], "not installed"
    with tempfile.TemporaryDirectory(prefix="pysentinel_") as temp_dir:
        report = Path(temp_dir) / "bandit.json"
        code, output = run_process(base + ["-r", str(target), "-f", "json", "-o", str(report)], cancel_check, pause_wait, log)
        findings: list[Finding] = []
        if report.exists():
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
                severity_map = {
                    "LOW": Severity.LOW,
                    "MEDIUM": Severity.MEDIUM,
                    "HIGH": Severity.HIGH,
                }
                for item in data.get("results", []):
                    findings.append(Finding(
                        scanner="Bandit",
                        severity=severity_map.get(item.get("issue_severity", ""), Severity.LOW),
                        title=item.get("issue_text", "Bandit finding"),
                        description=item.get("issue_text", ""),
                        path=item.get("filename", ""),
                        line=item.get("line_number"),
                        rule_id=item.get("test_id", ""),
                        evidence=item.get("code", ""),
                        metadata={"confidence": item.get("issue_confidence", "")},
                    ))
            except (OSError, json.JSONDecodeError) as exc:
                findings.append(Finding(
                    scanner="Bandit",
                    severity=Severity.LOW,
                    title="Bandit report parse failure",
                    description=str(exc),
                    rule_id="BANDIT-PARSE",
                ))
        return findings, f"exit={code}; output={output[-400:]}"


def run_pip_audit(
    dependencies: list[dict[str, str]],
    cancel_check: Callable[[], bool],
    pause_wait: Callable[[], None],
    log: Callable[[str], None],
) -> tuple[list[Finding], str]:
    base = _tool_command("pip-audit")
    if not base:
        return [], "not installed"
    usable = [d for d in dependencies if d.get("name") and d.get("version")]
    if not usable:
        return [], "skipped: no dependency metadata"
    with tempfile.TemporaryDirectory(prefix="pysentinel_") as temp_dir:
        req = Path(temp_dir) / "requirements.txt"
        report = Path(temp_dir) / "audit.json"
        req.write_text("\n".join(f"{d['name']}=={d['version']}" for d in usable), encoding="utf-8")
        code, output = run_process(
            base + ["-r", str(req), "-f", "json", "-o", str(report), "--no-deps"],
            cancel_check, pause_wait, log,
        )
        findings: list[Finding] = []
        if report.exists():
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    audited_dependencies = data.get("dependencies", [])
                elif isinstance(data, list):
                    audited_dependencies = data
                else:
                    audited_dependencies = []
                for dep in audited_dependencies:
                    for vuln in dep.get("vulns", []):
                        findings.append(Finding(
                            scanner="pip-audit",
                            severity=Severity.HIGH,
                            title=f"Known vulnerability in {dep.get('name', 'package')}",
                            description=vuln.get("description") or vuln.get("id", "Known vulnerability"),
                            rule_id=vuln.get("id", "CVE"),
                            evidence=f"{dep.get('name')} {dep.get('version')}",
                            recommendation=f"Fix versions: {', '.join(vuln.get('fix_versions', [])) or 'see advisory'}",
                        ))
            except (OSError, json.JSONDecodeError) as exc:
                findings.append(Finding(
                    scanner="pip-audit",
                    severity=Severity.LOW,
                    title="pip-audit report parse failure",
                    description=str(exc),
                    rule_id="PIP-AUDIT-PARSE",
                ))
        return findings, f"exit={code}; output={output[-400:]}"


def run_modelscan(
    target: Path,
    cancel_check: Callable[[], bool],
    pause_wait: Callable[[], None],
    log: Callable[[str], None],
) -> tuple[list[Finding], str]:
    base = _tool_command("modelscan")
    if not base:
        return [], "not installed"
    code, output = run_process(base + ["-p", str(target), "--show-skipped"], cancel_check, pause_wait, log)
    severity = Severity.HIGH if code not in (0, 3) else Severity.INFO
    findings = []
    if output.strip():
        findings.append(Finding(
            scanner="ModelScan",
            severity=severity,
            title="ModelScan result",
            description="Review the captured ModelScan output in the evidence field.",
            path=str(target),
            rule_id="MODELSCAN",
            evidence=output[-12000:],
        ))
    return findings, f"exit={code}"


def run_fickling(
    model_files: list[Path],
    cancel_check: Callable[[], bool],
    pause_wait: Callable[[], None],
    log: Callable[[str], None],
    progress: Callable[[int, int, str], None],
) -> tuple[list[Finding], str]:
    base = _tool_command("fickling")
    if not base:
        return [], "not installed"
    candidates = [p for p in model_files if p.suffix.lower() in {".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin"}]
    findings: list[Finding] = []
    total = max(len(candidates), 1)
    for index, path in enumerate(candidates, 1):
        if cancel_check():
            return findings, "cancelled"
        code, output = run_process(base + ["--check-safety", "-p", str(path)], cancel_check, pause_wait, log)
        if code != 0 or "unsafe" in output.lower() or "suspicious" in output.lower():
            findings.append(Finding(
                scanner="Fickling",
                severity=Severity.HIGH,
                title="Fickling flagged or could not validate a model",
                description="The external Pickle analyzer returned a non-clean result.",
                path=str(path),
                rule_id="FICKLING",
                evidence=output[-8000:],
            ))
        progress(index, total, str(path))
    return findings, f"scanned={len(candidates)}"


def run_defender(
    target: Path,
    cancel_check: Callable[[], bool],
    pause_wait: Callable[[], None],
    log: Callable[[str], None],
) -> tuple[list[Finding], str]:
    if os.name != "nt":
        return [], "not available on this operating system"
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return [], "PowerShell not found"
    escaped_target = str(target).replace("'", "''")
    command = [
        powershell, "-NoProfile", "-NonInteractive", "-Command",
        f"Start-MpScan -ScanType CustomScan -ScanPath '{escaped_target}'",
    ]
    code, output = run_process(command, cancel_check, pause_wait, log)
    findings = []
    if code != 0:
        findings.append(Finding(
            scanner="Microsoft Defender",
            severity=Severity.MEDIUM,
            title="Defender scan did not complete successfully",
            description=f"Exit code: {code}",
            path=str(target),
            rule_id="DEFENDER-ERROR",
            evidence=output[-8000:],
        ))
    return findings, f"exit={code}"
