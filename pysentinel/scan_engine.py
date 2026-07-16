from __future__ import annotations

import threading
import time
import traceback
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal

from .external_tools import run_bandit, run_defender, run_fickling, run_modelscan, run_pip_audit
from .logging_utils import append_text, utc_now, write_json_atomic
from .models import Finding, ScanOptions, ScanResult
from .reporting import write_report_bundle
from .scanners import build_inventory, scan_dependencies, scan_pickle_and_model_file, scan_source_file
from .scanners.inventory import enumerate_files


class ScanWorker(QThread):
    overall_progress = pyqtSignal(int)
    phase_progress = pyqtSignal(int)
    phase_indeterminate = pyqtSignal(bool)
    phase_changed = pyqtSignal(str)
    current_item = pyqtSignal(str)
    log_message = pyqtSignal(str)
    finding_found = pyqtSignal(object)
    result_ready = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, options: ScanOptions) -> None:
        super().__init__()
        self.options = options
        self._cancel = threading.Event()
        self._pause = threading.Event()
        self._pause.set()
        self._result: ScanResult | None = None
        self._scan_log = Path(options.scan_log_path) if options.scan_log_path else None

    def _log(self, message: str, level: str = "INFO") -> None:
        rendered = f"{utc_now()} | {level.upper()} | {message}"
        if self._scan_log is not None:
            try:
                append_text(self._scan_log, rendered)
            except OSError:
                pass
        self.log_message.emit(rendered)

    def cancel(self) -> None:
        self._log("Cancellation requested", "WARNING")
        self._cancel.set()
        self._pause.set()

    def pause(self) -> None:
        self._log("Pause requested")
        self._pause.clear()

    def resume(self) -> None:
        self._log("Resume requested")
        self._pause.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def pause_wait(self) -> None:
        while not self._pause.wait(timeout=0.1):
            if self._cancel.is_set():
                return

    def _emit_finding(self, finding: Finding) -> None:
        assert self._result is not None
        self._result.findings.append(finding)
        self.finding_found.emit(finding)

    def _set_progress(self, completed: int, total: int, item: str = "") -> None:
        self.pause_wait()
        if item:
            self.current_item.emit(item)
        value = 100 if total <= 0 else max(0, min(100, int(completed * 100 / total)))
        self.phase_progress.emit(value)

    def _set_overall(self, value: int) -> None:
        self.overall_progress.emit(max(0, min(100, value)))

    def run(self) -> None:
        try:
            target = Path(self.options.target).expanduser().resolve()
            if not target.exists():
                raise FileNotFoundError(f"Target does not exist: {target}")

            self._result = ScanResult.new(str(target))
            max_bytes = self.options.max_file_mib * 1024 * 1024
            self._log(f"Worker started; target={target}")
            self._log(f"Profile={self.options.profile}; max_file_mib={self.options.max_file_mib}")

            phases: list[str] = ["files"]
            if self.options.dependency_scan:
                phases.append("dependencies")
            if self.options.source_scan:
                phases.append("source")
            if self.options.pickle_scan or self.options.archive_scan:
                phases.append("models")
            if self.options.external_bandit:
                phases.append("bandit")
            if self.options.external_pip_audit:
                phases.append("pip-audit")
            if self.options.external_modelscan:
                phases.append("modelscan")
            if self.options.external_fickling:
                phases.append("fickling")
            if self.options.defender_scan:
                phases.append("defender")
            phases.append("reports")

            phase_index = 0

            def begin_phase(name: str, indeterminate: bool = False) -> None:
                nonlocal phase_index
                phase_index += 1
                self.phase_changed.emit(name)
                self.phase_indeterminate.emit(indeterminate)
                self.phase_progress.emit(0)
                self._set_overall(int((phase_index - 1) * 100 / max(len(phases), 1)))
                self._log(f"Phase started: {name}")

            files: list[Path] = []
            if self.options.inventory:
                begin_phase("File discovery and inventory", True)
                bytes_seen = 0
                for discovered in enumerate_files(target, self.options.follow_symlinks):
                    self.pause_wait()
                    if self.is_cancelled():
                        break
                    files.append(discovered)
                    try:
                        bytes_seen += discovered.stat().st_size
                    except OSError:
                        pass
                    if len(files) == 1 or len(files) % 100 == 0:
                        self.current_item.emit(f"{discovered}  ({len(files)} files)")
                self.phase_indeterminate.emit(False)
                self.phase_progress.emit(0)
                self._result.files_seen = len(files)
                self._result.bytes_seen = bytes_seen
                inventory, findings = build_inventory(
                    files,
                    hashes=self.options.hashes,
                    max_file_bytes=max_bytes,
                    cancel_check=self.is_cancelled,
                    progress=self._set_progress,
                )
                self._result.inventory = inventory
                for finding in findings:
                    self._emit_finding(finding)
            else:
                begin_phase("File discovery", True)
                for discovered in enumerate_files(target, self.options.follow_symlinks):
                    self.pause_wait()
                    if self.is_cancelled():
                        break
                    files.append(discovered)
                self.phase_indeterminate.emit(False)
                self.phase_progress.emit(100)
                self._result.files_seen = len(files)

            if self.is_cancelled():
                self._result.finish(cancelled=True)
                self._finalize_reports()
                self.result_ready.emit(self._result)
                return

            if self.options.dependency_scan:
                begin_phase("Dependency inventory")
                deps, findings = scan_dependencies(target, self.is_cancelled, self._set_progress)
                self._result.dependencies = deps
                for finding in findings:
                    self._emit_finding(finding)

            if self.options.source_scan and not self.is_cancelled():
                begin_phase("Python source analysis")
                source_files = [p for p in files if p.suffix.lower() == ".py"]
                total = max(len(source_files), 1)
                for index, path in enumerate(source_files, 1):
                    self.pause_wait()
                    if self.is_cancelled():
                        break
                    for finding in scan_source_file(path, max_bytes):
                        self._emit_finding(finding)
                    self._set_progress(index, total, str(path))

            model_files = [
                p for p in files
                if p.suffix.lower() in {
                    ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib", ".sav",
                    ".bin", ".npy", ".npz", ".safetensors", ".keras", ".h5", ".hdf5",
                }
            ]
            if (self.options.pickle_scan or self.options.archive_scan) and not self.is_cancelled():
                begin_phase("Pickle and tensor/model inspection")
                total = max(len(model_files), 1)
                for index, path in enumerate(model_files, 1):
                    self.pause_wait()
                    if self.is_cancelled():
                        break
                    for finding in scan_pickle_and_model_file(
                        path,
                        max_bytes,
                        self.options.max_archive_entries,
                    ):
                        self._emit_finding(finding)
                    self._set_progress(index, total, str(path))

            if self.options.external_bandit and not self.is_cancelled():
                begin_phase("Bandit", True)
                findings, status = run_bandit(
                    target,
                    self.is_cancelled,
                    self.pause_wait,
                    self._log,
                )
                self._result.tool_status["Bandit"] = status
                for finding in findings:
                    self._emit_finding(finding)
                self.phase_indeterminate.emit(False)
                self.phase_progress.emit(100)

            if self.options.external_pip_audit and not self.is_cancelled():
                begin_phase("pip-audit", True)
                findings, status = run_pip_audit(
                    self._result.dependencies,
                    self.is_cancelled,
                    self.pause_wait,
                    self._log,
                )
                self._result.tool_status["pip-audit"] = status
                for finding in findings:
                    self._emit_finding(finding)
                self.phase_indeterminate.emit(False)
                self.phase_progress.emit(100)

            if self.options.external_modelscan and not self.is_cancelled():
                begin_phase("ModelScan", True)
                findings, status = run_modelscan(
                    target,
                    self.is_cancelled,
                    self.pause_wait,
                    self._log,
                )
                self._result.tool_status["ModelScan"] = status
                for finding in findings:
                    self._emit_finding(finding)
                self.phase_indeterminate.emit(False)
                self.phase_progress.emit(100)

            if self.options.external_fickling and not self.is_cancelled():
                begin_phase("Fickling")
                findings, status = run_fickling(
                    model_files,
                    self.is_cancelled,
                    self.pause_wait,
                    self._log,
                    self._set_progress,
                )
                self._result.tool_status["Fickling"] = status
                for finding in findings:
                    self._emit_finding(finding)

            if self.options.defender_scan and not self.is_cancelled():
                begin_phase("Microsoft Defender", True)
                findings, status = run_defender(
                    target,
                    self.is_cancelled,
                    self.pause_wait,
                    self._log,
                )
                self._result.tool_status["Microsoft Defender"] = status
                for finding in findings:
                    self._emit_finding(finding)
                self.phase_indeterminate.emit(False)
                self.phase_progress.emit(100)

            self._result.finish(cancelled=self.is_cancelled())
            self._finalize_reports()
            self._set_overall(100)
            self._log(
                f"Worker completed; files={self._result.files_seen}; "
                f"findings={len(self._result.findings)}; "
                f"cancelled={self._result.cancelled}"
            )
            self.result_ready.emit(self._result)
        except Exception as exc:
            formatted = traceback.format_exc()
            self._log(f"Worker exception: {type(exc).__name__}: {exc}", "ERROR")
            if self.options.scan_dir:
                try:
                    scan_dir = Path(self.options.scan_dir)
                    append_text(
                        scan_dir / "error.txt",
                        f"{utc_now()} | WORKER EXCEPTION\n{formatted}",
                    )
                    write_json_atomic(
                        scan_dir / "completion.json",
                        {
                            "status": "failed",
                            "timestamp_utc": utc_now(),
                            "target": self.options.target,
                            "exception_type": type(exc).__name__,
                            "exception": str(exc),
                            "scan_log": self.options.scan_log_path,
                        },
                    )
                except OSError:
                    pass
            self.failed.emit(f"{type(exc).__name__}: {exc}\n\n{formatted}")

    def _finalize_reports(self) -> None:
        assert self._result is not None
        begin_name = "Writing reports and logs"
        self.phase_changed.emit(begin_name)
        self.phase_indeterminate.emit(True)
        self._log(f"Phase started: {begin_name}")

        scan_dir = Path(self.options.scan_dir) if self.options.scan_dir else Path.cwd()
        report_dir = scan_dir / "reports"
        mirror_dir = (
            Path(self.options.output_dir).expanduser()
            if self.options.output_dir.strip()
            else None
        )
        stem = time.strftime("pysentinel_%Y%m%d_%H%M%S")
        artifacts, warnings = write_report_bundle(
            self._result,
            report_dir=report_dir,
            stem=stem,
            mirror_dir=mirror_dir,
        )
        self._result.artifacts.update(artifacts)
        self._result.artifacts["scan_dir"] = str(scan_dir)
        if self.options.scan_log_path:
            self._result.artifacts["scan_log"] = self.options.scan_log_path

        for warning in warnings:
            self._log(warning, "WARNING")

        write_json_atomic(
            scan_dir / "completion.json",
            {
                "target": self._result.target,
                "started_at": self._result.started_at,
                "finished_at": self._result.finished_at,
                "cancelled": self._result.cancelled,
                "files_seen": self._result.files_seen,
                "bytes_seen": self._result.bytes_seen,
                "findings": len(self._result.findings),
                "tool_status": self._result.tool_status,
                "artifacts": self._result.artifacts,
                "warnings": warnings,
            },
        )
        self.phase_indeterminate.emit(False)
        self.phase_progress.emit(100)
