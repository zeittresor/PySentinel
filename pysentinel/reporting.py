from __future__ import annotations

import html
import json
import shutil
from pathlib import Path

from .logging_utils import write_json_atomic
from .models import ScanResult


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def write_json(result: ScanResult, path: Path) -> None:
    write_json_atomic(path, result.to_dict())


def write_markdown(result: ScanResult, path: Path) -> None:
    lines = [
        "# PySentinel Scan Report",
        "",
        f"- Target: `{result.target}`",
        f"- Started: {result.started_at}",
        f"- Finished: {result.finished_at}",
        f"- Cancelled: {result.cancelled}",
        f"- Files: {result.files_seen}",
        f"- Bytes: {result.bytes_seen}",
        f"- Findings: {len(result.findings)}",
        "",
        "## Tool status",
        "",
    ]
    for tool, status in sorted(result.tool_status.items()):
        lines.append(f"- **{tool}:** {status}")

    lines += ["", "## Findings", ""]
    if not result.findings:
        lines.append("No findings were recorded.")
    else:
        for index, finding in enumerate(result.findings, 1):
            location = finding.path
            if finding.line:
                location += f":{finding.line}"
            lines += [
                f"### {index}. [{finding.severity.label}] {finding.title}",
                "",
                f"- Scanner: `{finding.scanner}`",
                f"- Rule: `{finding.rule_id}`",
                f"- Location: `{location}`",
                "",
                finding.description,
                "",
            ]
            if finding.evidence:
                lines += ["```text", finding.evidence[:4000], "```", ""]
            if finding.recommendation:
                lines += [f"**Recommendation:** {finding.recommendation}", ""]

    lines += ["", "## Dependencies", "", "| Name | Version | Location |", "|---|---:|---|"]
    for dep in result.dependencies:
        lines.append(
            f"| {dep.get('name','')} | {dep.get('version','')} | {dep.get('location','')} |"
        )

    _write_text_atomic(path, "\n".join(lines))


def write_html(result: ScanResult, path: Path) -> None:
    rows = []
    for finding in result.findings:
        location = finding.path + (f":{finding.line}" if finding.line else "")
        rows.append(
            "<tr>"
            f"<td class='sev {html.escape(finding.severity.label.lower())}'>{html.escape(finding.severity.label)}</td>"
            f"<td>{html.escape(finding.scanner)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(location)}</td>"
            f"<td>{html.escape(finding.description)}</td>"
            "</tr>"
        )
    dep_rows = [
        f"<tr><td>{html.escape(d.get('name',''))}</td><td>{html.escape(d.get('version',''))}</td>"
        f"<td>{html.escape(d.get('location',''))}</td></tr>"
        for d in result.dependencies
    ]
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PySentinel Scan Report</title>
<style>
body {{ font-family: Segoe UI, sans-serif; margin: 2rem; background:#111827; color:#e5e7eb; }}
h1,h2 {{ color:#93c5fd; }}
.card {{ background:#1f2937; padding:1rem; border-radius:.7rem; margin-bottom:1rem; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ border-bottom:1px solid #374151; padding:.55rem; text-align:left; vertical-align:top; }}
.sev {{ font-weight:700; }}
.critical {{ color:#ff6b6b; }} .high {{ color:#ff9f43; }} .medium {{ color:#ffd166; }}
.low {{ color:#7dd3fc; }} .info {{ color:#a7f3d0; }}
code {{ word-break:break-all; }}
</style>
</head>
<body>
<h1>PySentinel Scan Report</h1>
<div class="card">
<p><b>Target:</b> <code>{html.escape(result.target)}</code></p>
<p><b>Started:</b> {html.escape(result.started_at)}<br>
<b>Finished:</b> {html.escape(result.finished_at)}<br>
<b>Files:</b> {result.files_seen}<br>
<b>Findings:</b> {len(result.findings)}</p>
</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Scanner</th><th>Title</th><th>Location</th><th>Description</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Dependencies</h2>
<table><thead><tr><th>Name</th><th>Version</th><th>Location</th></tr></thead>
<tbody>{''.join(dep_rows)}</tbody></table>
</body></html>"""
    _write_text_atomic(path, document)


def write_report_bundle(
    result: ScanResult,
    report_dir: Path,
    stem: str,
    mirror_dir: Path | None = None,
) -> tuple[dict[str, str], list[str]]:
    report_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "json": report_dir / f"{stem}.json",
        "markdown": report_dir / f"{stem}.md",
        "html": report_dir / f"{stem}.html",
    }
    warnings: list[str] = []

    write_json(result, outputs["json"])
    write_markdown(result, outputs["markdown"])
    write_html(result, outputs["html"])

    artifacts = {key: str(path) for key, path in outputs.items()}
    artifacts["report_dir"] = str(report_dir)

    if mirror_dir:
        try:
            mirror_dir.mkdir(parents=True, exist_ok=True)
            for key, source in outputs.items():
                destination = mirror_dir / source.name
                shutil.copy2(source, destination)
                artifacts[f"mirror_{key}"] = str(destination)
            artifacts["mirror_report_dir"] = str(mirror_dir)
        except OSError as exc:
            warnings.append(f"Additional report directory could not be written: {exc}")

    return artifacts, warnings
