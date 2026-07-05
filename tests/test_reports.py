"""Contract tests for the three output formats (FR-8, NFR-5)."""

from __future__ import annotations

import json

from phantom import core
from phantom.models import SCHEMA_VERSION
from phantom.report import json_report, sarif_report, table_report

TOP_LEVEL_KEYS = {
    "schema_version",
    "package",
    "version",
    "ecosystem",
    "source_status",
    "source_repo",
    "source_ref",
    "findings",
    "summary",
}
FINDING_KEYS = {"type", "path", "severity", "confidence", "reason", "execution_vectors"}
SUMMARY_KEYS = {"files_scanned", "total_findings", "phantom_files", "highest_severity"}


def test_json_schema_contract(injected_ecosystem):
    result = core.scan("mypkg", "1.0.0", injected_ecosystem)
    payload = json.loads(json_report.render(result))
    assert payload["schema_version"] == SCHEMA_VERSION
    assert set(payload) == TOP_LEVEL_KEYS
    assert payload["summary"].keys() == SUMMARY_KEYS
    assert payload["summary"]["highest_severity"] == "critical"
    assert payload["summary"]["phantom_files"] == 1
    for finding in payload["findings"]:
        assert set(finding) == FINDING_KEYS


def test_json_is_deterministic(injected_ecosystem):
    first = json_report.render(core.scan("mypkg", "1.0.0", injected_ecosystem))
    second = json_report.render(core.scan("mypkg", "1.0.0", injected_ecosystem))
    assert first == second


def test_sarif_structure(injected_ecosystem):
    result = core.scan("mypkg", "1.0.0", injected_ecosystem)
    sarif = json.loads(sarif_report.render(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "phantom"
    assert len(run["results"]) == 1
    sarif_result = run["results"][0]
    assert sarif_result["ruleId"] == "phantom_file"
    assert sarif_result["level"] == "error"
    location = sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location["uri"] == "mypkg/_telemetry.py"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "phantom_file" in rule_ids


def test_table_output(benign_ecosystem, injected_ecosystem):
    clean = table_report.render(core.scan("mypkg", "1.0.0", benign_ecosystem))
    assert "no findings" in clean

    dirty = table_report.render(core.scan("mypkg", "1.0.0", injected_ecosystem))
    assert "CRITICAL" in dirty
    assert "mypkg/_telemetry.py" in dirty
    assert "vectors:" in dirty
