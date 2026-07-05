"""Human-readable table output (default format)."""

from __future__ import annotations

from phantom.models import ScanResult


def render(result: ScanResult) -> str:
    lines = [
        f"phantom scan: {result.package}=={result.version} [{result.ecosystem}]",
        f"source: {_source_line(result)}",
        "",
    ]
    if not result.findings:
        lines.append(
            f"no findings — {result.files_scanned} file(s) verified against source"
        )
        return "\n".join(lines)

    headers = ("SEVERITY", "TYPE", "CONFIDENCE", "PATH")
    rows = [
        (
            f.severity.value.upper(),
            f.type.value,
            f.confidence.value,
            f.path or "-",
        )
        for f in result.findings
    ]
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))
    ]
    lines.append("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    lines.append("  ".join("-" * w for w in widths))
    for finding, row in zip(result.findings, rows):
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        lines.append(f"    reason: {finding.reason}")
        if finding.execution_vectors:
            lines.append(f"    vectors: {', '.join(finding.execution_vectors)}")
    summary = result.to_dict()["summary"]
    lines.append("")
    lines.append(
        f"{summary['total_findings']} finding(s) "
        f"({summary['phantom_files']} phantom file(s)), "
        f"highest severity: {summary['highest_severity']}, "
        f"{summary['files_scanned']} file(s) scanned"
    )
    return "\n".join(lines)


def _source_line(result: ScanResult) -> str:
    if result.source_ref:
        return f"{result.source_repo}@{result.source_ref}"
    if result.source_repo:
        return f"{result.source_repo} (ref not found: {result.source_status.value})"
    return f"unresolved ({result.source_status.value})"
