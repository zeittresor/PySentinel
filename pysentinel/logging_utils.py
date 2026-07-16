from __future__ import annotations

import faulthandler
import json
import logging
import logging.handlers
import os
import platform
import re
import sys
import tempfile
import threading
import traceback
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


APP_LOGGER_NAME = "pysentinel"
_CRASH_HANDLE = None
_WRITE_LOCK = threading.RLock()


@dataclass(slots=True)
class RuntimePaths:
    data_dir: Path
    logs_dir: Path
    app_logs_dir: Path
    scans_dir: Path
    app_log: Path
    crash_log: Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "PySentinel"
    xdg = os.environ.get("XDG_STATE_HOME") or os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "PySentinel"
    return Path.home() / ".local" / "share" / "PySentinel"


def _safe_name(value: str, fallback: str = "scan") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._-")
    return (cleaned or fallback)[:80]


def initialize_logging() -> RuntimePaths:
    global _CRASH_HANDLE

    data_dir = default_data_dir()
    try:
        logs_dir = data_dir / "logs"
        app_logs_dir = logs_dir / "app"
        scans_dir = logs_dir / "scans"
        for directory in (data_dir, logs_dir, app_logs_dir, scans_dir):
            directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        data_dir = Path(tempfile.gettempdir()) / "PySentinel"
        logs_dir = data_dir / "logs"
        app_logs_dir = logs_dir / "app"
        scans_dir = logs_dir / "scans"
        for directory in (data_dir, logs_dir, app_logs_dir, scans_dir):
            directory.mkdir(parents=True, exist_ok=True)

    app_log = app_logs_dir / "pysentinel_app.log"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    crash_log = app_logs_dir / f"faulthandler_{timestamp}.log"

    logger = logging.getLogger(APP_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(threadName)s | %(name)s | %(message)s"
        )
        file_handler = logging.handlers.RotatingFileHandler(
            app_log,
            maxBytes=5 * 1024 * 1024,
            backupCount=8,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    try:
        _CRASH_HANDLE = crash_log.open("a", encoding="utf-8", buffering=1)
        _CRASH_HANDLE.write(
            f"{utc_now()} | faulthandler initialized | executable={sys.executable}\n"
        )
        faulthandler.enable(file=_CRASH_HANDLE, all_threads=True)
    except OSError:
        logger.exception("Could not initialize faulthandler output")

    logger.info("PySentinel logging initialized")
    logger.info("Data directory: %s", data_dir)
    logger.info("App log: %s", app_log)
    logger.info("Crash log: %s", crash_log)

    return RuntimePaths(
        data_dir=data_dir,
        logs_dir=logs_dir,
        app_logs_dir=app_logs_dir,
        scans_dir=scans_dir,
        app_log=app_log,
        crash_log=crash_log,
    )


def install_exception_hooks(
    ui_callback: Callable[[str, str], None] | None = None,
) -> None:
    logger = logging.getLogger(APP_LOGGER_NAME)

    def handle_exception(exc_type, exc_value, exc_tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return

        formatted = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logger.critical("Unhandled Python exception\n%s", formatted)

        try:
            if _CRASH_HANDLE is not None:
                _CRASH_HANDLE.write(
                    f"\n{utc_now()} | UNHANDLED PYTHON EXCEPTION\n{formatted}\n"
                )
                _CRASH_HANDLE.flush()
        except Exception:
            pass

        if ui_callback is not None:
            try:
                ui_callback("Unhandled application error", formatted)
            except Exception:
                logger.exception("The UI exception callback failed")

    sys.excepthook = handle_exception

    if hasattr(threading, "excepthook"):
        def thread_exception(args: threading.ExceptHookArgs) -> None:
            handle_exception(args.exc_type, args.exc_value, args.exc_traceback)
        threading.excepthook = thread_exception


def environment_snapshot() -> dict[str, Any]:
    return {
        "timestamp_utc": utc_now(),
        "platform": platform.platform(),
        "python_version": sys.version,
        "python_executable": sys.executable,
        "python_prefix": sys.prefix,
        "cwd": str(Path.cwd()),
        "process_id": os.getpid(),
        "architecture": platform.architecture(),
    }


def safe_json_data(value: Any) -> Any:
    if is_dataclass(value):
        return safe_json_data(asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): safe_json_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [safe_json_data(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(safe_json_data(data), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary.replace(path)


def append_text(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = message.rstrip("\r\n")
    with _WRITE_LOCK:
        with path.open("a", encoding="utf-8", errors="replace") as handle:
            handle.write(line + "\n")


class ScanLogSession:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.log_path = directory / "scan.log"
        self.error_path = directory / "error.txt"
        self.options_path = directory / "scan_options.json"
        self.environment_path = directory / "environment.json"
        self.completion_path = directory / "completion.json"
        self.reports_dir = directory / "reports"

    @classmethod
    def create(
        cls,
        scans_root: Path,
        target: str,
        options: Any,
    ) -> "ScanLogSession":
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        target_name = _safe_name(Path(target).name or "root")
        directory = scans_root / f"{timestamp}_{target_name}"
        directory.mkdir(parents=True, exist_ok=False)

        session = cls(directory)
        session.reports_dir.mkdir(parents=True, exist_ok=True)
        write_json_atomic(session.options_path, options)
        write_json_atomic(
            session.environment_path,
            {
                **environment_snapshot(),
                "target": str(Path(target).expanduser()),
                "scan_directory": str(directory),
            },
        )
        session.append(f"{utc_now()} | INFO | Scan session created")
        session.append(f"{utc_now()} | INFO | Target: {target}")
        return session

    def append(self, message: str, level: str = "INFO") -> None:
        if re.match(r"^\d{4}-\d{2}-\d{2}T", message):
            append_text(self.log_path, message)
        else:
            append_text(self.log_path, f"{utc_now()} | {level.upper()} | {message}")

    def write_error(self, context: str, error: BaseException | str) -> None:
        if isinstance(error, BaseException):
            detail = "".join(
                traceback.format_exception(type(error), error, error.__traceback__)
            )
        else:
            detail = str(error)
        text = (
            f"{utc_now()} | ERROR | {context}\n"
            f"{detail.rstrip()}\n"
        )
        append_text(self.error_path, text)
        self.append(f"{context}: {detail.splitlines()[-1] if detail else ''}", "ERROR")

    def finalize(self, data: dict[str, Any]) -> None:
        write_json_atomic(self.completion_path, data)
        self.append("Scan session finalized")
