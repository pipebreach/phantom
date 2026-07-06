"""Human-readable table output (default format)."""

from __future__ import annotations

from phantom.models import AuditResult, AuditStatus, ScanResult


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
            (f.path or "-")
            + (f":{f.start_line}-{f.end_line}" if f.start_line else ""),
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


def render_audit(result: AuditResult) -> str:
    lines = [f"phantom audit: {result.lockfile} [{result.ecosystem}]", ""]
    for entry in result.entries:
        if entry.status == AuditStatus.SCANNED and entry.result:
            highest = entry.result.highest_severity
            status = highest.value.upper() if highest else "clean"
        else:
            status = entry.status.value
        lines.append(f"  {entry.package}=={entry.version}  {status}")
        if entry.detail:
            lines.append(f"    {entry.detail}")
        if entry.result and entry.result.findings:
            for finding in entry.result.findings:
                location = finding.path or "-"
                if finding.start_line:
                    location += f":{finding.start_line}-{finding.end_line}"
                lines.append(
                    f"    [{finding.severity.value.upper()}] "
                    f"{finding.type.value} {location}"
                )
                lines.append(f"      reason: {finding.reason}")
    summary = result.to_dict()["summary"]
    lines.append("")
    lines.append(
        f"{summary['packages']} package(s): {summary['scanned']} scanned, "
        f"{summary['out_of_scope']} out of scope, {summary['error']} error(s), "
        f"{summary['skipped']} skipped; "
        f"{summary['packages_with_findings']} with findings, "
        f"highest severity: {summary['highest_severity']}"
    )
    return "\n".join(lines)


def _source_line(result: ScanResult) -> str:
    if result.source_ref:
        return f"{result.source_repo}@{result.source_ref}"
    if result.source_repo:
        return f"{result.source_repo} (ref not found: {result.source_status.value})"
    return f"unresolved ({result.source_status.value})"
