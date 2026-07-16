from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass(slots=True)
class Finding:
    scanner: str
    severity: Severity
    title: str
    description: str
    path: str = ""
    line: int | None = None
    rule_id: str = ""
    evidence: str = ""
    recommendation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data


@dataclass(slots=True)
class ScanOptions:
    target: str
    profile: str = "standard"
    inventory: bool = True
    hashes: bool = True
    source_scan: bool = True
    dependency_scan: bool = True
    pickle_scan: bool = True
    archive_scan: bool = True
    external_bandit: bool = True
    external_pip_audit: bool = True
    external_modelscan: bool = True
    external_fickling: bool = True
    defender_scan: bool = False
    follow_symlinks: bool = False
    max_file_mib: int = 256
    max_archive_entries: int = 10000
    output_dir: str = ""
    scan_dir: str = ""
    scan_log_path: str = ""


@dataclass(slots=True)
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    cancelled: bool = False
    files_seen: int = 0
    bytes_seen: int = 0
    dependencies: list[dict[str, str]] = field(default_factory=list)
    inventory: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tool_status: dict[str, str] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)

    @classmethod
    def new(cls, target: str) -> "ScanResult":
        return cls(
            target=str(Path(target).resolve()),
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    def finish(self, cancelled: bool = False) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()
        self.cancelled = cancelled

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "cancelled": self.cancelled,
            "files_seen": self.files_seen,
            "bytes_seen": self.bytes_seen,
            "dependencies": self.dependencies,
            "inventory": self.inventory,
            "findings": [finding.to_dict() for finding in self.findings],
            "tool_status": self.tool_status,
            "artifacts": self.artifacts,
        }
