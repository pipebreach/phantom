"""SARIF 2.1.0 output for GitHub code scanning integration."""

from __future__ import annotations

import json

from phantom import __version__
from phantom.models import AuditResult, Finding, ScanResult, Severity

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json"

_RULE_DESCRIPTIONS = {
    "phantom_file": "File in the published artifact whose content does not exist in the declared source",
    "phantom_span": "Code injected into an artifact file that does exist in the declared source",
    "suspicious_pth": ".pth file shipped inside a wheel (executes at interpreter startup)",
    "no_source_declared": "Package declares no source repository; artifact is unverifiable",
    "source_ref_not_found": "No tag matching the published version was found in the declared repository",
}


def render(result: ScanResult) -> str:
    findings = [(f, None) for f in result.findings]
    return _render_sarif(findings)


def render_audit(result: AuditResult) -> str:
    findings = [
        (finding, f"{entry.package}=={entry.version}")
        for entry in result.entries
        if entry.result
        for finding in entry.result.findings
    ]
    return _render_sarif(findings)


def _render_sarif(findings: list[tuple[Finding, str | None]]) -> str:
    rule_ids = sorted({f.type.value for f, _ in findings})
    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "phantom",
                        "version": __version__,
                        "informationUri": "https://github.com/pipebreach/phantom",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {
                                    "text": _RULE_DESCRIPTIONS.get(rule_id, rule_id)
                                },
                            }
                            for rule_id in rule_ids
                        ],
                    }
                },
                "results": [_to_sarif_result(f, pkg) for f, pkg in findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _to_sarif_result(finding: Finding, package: str | None) -> dict:
    message = finding.reason
    if package:
        message = f"[{package}] {message}"
    result: dict = {
        "ruleId": finding.type.value,
        "level": _level(finding.severity),
        "message": {"text": message},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "execution_vectors": list(finding.execution_vectors),
        },
    }
    if package:
        result["properties"]["package"] = package
    if finding.path:
        location: dict = {"artifactLocation": {"uri": finding.path}}
        if finding.start_line:
            location["region"] = {
                "startLine": finding.start_line,
                "endLine": finding.end_line or finding.start_line,
            }
        result["locations"] = [{"physicalLocation": location}]
    return result


def _level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"
