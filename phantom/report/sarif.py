"""SARIF 2.1.0 output for GitHub code scanning integration."""

from __future__ import annotations

import json

from phantom import __version__
from phantom.models import Finding, ScanResult, Severity

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json"

_RULE_DESCRIPTIONS = {
    "phantom_file": "File in the published artifact whose content does not exist in the declared source",
    "suspicious_pth": ".pth file shipped inside a wheel (executes at interpreter startup)",
    "no_source_declared": "Package declares no source repository; artifact is unverifiable",
    "source_ref_not_found": "No tag matching the published version was found in the declared repository",
}


def render(result: ScanResult) -> str:
    rule_ids = sorted({f.type.value for f in result.findings})
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
                "results": [_to_sarif_result(f) for f in result.findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _to_sarif_result(finding: Finding) -> dict:
    result: dict = {
        "ruleId": finding.type.value,
        "level": _level(finding.severity),
        "message": {"text": finding.reason},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "execution_vectors": list(finding.execution_vectors),
        },
    }
    if finding.path:
        result["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": finding.path}}}
        ]
    return result


def _level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"
