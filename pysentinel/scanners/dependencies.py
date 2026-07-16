from __future__ import annotations

from email.parser import Parser
from pathlib import Path
from typing import Callable

from ..models import Finding, Severity


def _site_package_roots(target: Path) -> list[Path]:
    candidates = [
        target / "Lib" / "site-packages",
        target / "lib" / "site-packages",
        target / ".venv" / "Lib" / "site-packages",
        target / "venv" / "Lib" / "site-packages",
        target / "env" / "Lib" / "site-packages",
    ]
    for lib_dir in [target / ".venv" / "lib", target / "venv" / "lib", target / "env" / "lib", target / "lib"]:
        if lib_dir.exists():
            candidates.extend(lib_dir.glob("python*/site-packages"))
    if target.name.lower() == "site-packages":
        candidates.append(target)
    result: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        if path.exists():
            key = str(path.resolve())
            if key not in seen:
                seen.add(key)
                result.append(path)
    return result


def scan_dependencies(
    target: Path,
    cancel_check: Callable[[], bool],
    progress: Callable[[int, int, str], None],
) -> tuple[list[dict[str, str]], list[Finding]]:
    roots = _site_package_roots(target)
    metadata_files: list[Path] = []
    for root in roots:
        metadata_files.extend(root.glob("*.dist-info/METADATA"))
    if not metadata_files:
        # Fallback for embedded Python layouts and applications with a custom venv name.
        metadata_files.extend(target.rglob("*.dist-info/METADATA"))
    metadata_files = sorted(set(metadata_files))
    dependencies: list[dict[str, str]] = []
    findings: list[Finding] = []
    total = max(len(metadata_files), 1)

    if not metadata_files:
        findings.append(Finding(
            scanner="Dependencies",
            severity=Severity.INFO,
            title="No dist-info metadata found",
            description="PySentinel could not locate a conventional site-packages directory below the target.",
            path=str(target),
            rule_id="DEP-NONE",
        ))
        progress(1, 1, str(target))
        return dependencies, findings

    for index, metadata_path in enumerate(sorted(metadata_files), 1):
        if cancel_check():
            break
        try:
            message = Parser().parsestr(metadata_path.read_text(encoding="utf-8", errors="replace"))
            name = message.get("Name", metadata_path.parent.name)
            version = message.get("Version", "")
            dependencies.append({
                "name": name,
                "version": version,
                "location": str(metadata_path.parent),
            })
            direct_url = metadata_path.parent / "direct_url.json"
            if direct_url.exists():
                findings.append(Finding(
                    scanner="Dependencies",
                    severity=Severity.INFO,
                    title="Direct URL installation metadata",
                    description="This package was installed from a direct URL or local source.",
                    path=str(direct_url),
                    rule_id="DEP-DIRECT-URL",
                    recommendation="Verify the source URL and expected commit or hash.",
                ))
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(
                scanner="Dependencies",
                severity=Severity.LOW,
                title="Dependency metadata could not be parsed",
                description=str(exc),
                path=str(metadata_path),
                rule_id="DEP-METADATA",
            ))
        progress(index, total, str(metadata_path))
    return dependencies, findings
