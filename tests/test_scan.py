"""End-to-end core.scan tests over local fixtures."""

from __future__ import annotations

from pathlib import Path

from conftest import FIXTURES, FakeEcosystem, FakeFetcher, FakeSourceResolver, NoSourceResolver

from phantom import core
from phantom.models import (
    Confidence,
    FileEntry,
    FindingType,
    Severity,
    SourceStatus,
)


def test_benign_produces_no_findings(benign_ecosystem):
    result = core.scan("mypkg", "1.0.0", benign_ecosystem)
    assert result.findings == []
    assert result.source_status == SourceStatus.RESOLVED
    assert result.files_scanned == 2  # the two .py files; dist-info skipped
    assert core.exit_code_for(result) == 0


def test_injected_flags_phantom_file_as_critical(injected_ecosystem):
    result = core.scan("mypkg", "1.0.0", injected_ecosystem)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.type == FindingType.PHANTOM_FILE
    assert finding.path == "mypkg/_telemetry.py"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == Confidence.HIGH
    assert any(v.startswith("env-read:") for v in finding.execution_vectors)
    assert any(v.startswith("network:") for v in finding.execution_vectors)
    assert core.exit_code_for(result) == 1


def test_pth_file_is_always_flagged():
    root = FIXTURES / "benign"
    pth = FileEntry(path="hook.pth", data=b"import mypkg_hook\n")
    ecosystem = FakeEcosystem(
        FakeFetcher(root / "wheel", extra_files=[pth]),
        FakeSourceResolver(root / "source"),
    )
    result = core.scan("mypkg", "1.0.0", ecosystem)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.type == FindingType.SUSPICIOUS_PTH
    assert finding.severity == Severity.CRITICAL  # contains an import line
    assert core.exit_code_for(result) == 1


def test_no_source_declared_is_a_high_finding():
    root = FIXTURES / "benign"
    ecosystem = FakeEcosystem(
        FakeFetcher(root / "wheel"),
        NoSourceResolver(FindingType.NO_SOURCE_DECLARED),
    )
    result = core.scan("mypkg", "1.0.0", ecosystem)
    assert result.source_status == SourceStatus.NO_SOURCE_DECLARED
    assert result.source_repo is None
    assert [f.type for f in result.findings] == [FindingType.NO_SOURCE_DECLARED]
    assert result.findings[0].severity == Severity.HIGH
    assert core.exit_code_for(result) == 1


def test_source_ref_not_found_is_a_medium_finding():
    root = FIXTURES / "benign"
    ecosystem = FakeEcosystem(
        FakeFetcher(root / "wheel"),
        NoSourceResolver(FindingType.SOURCE_REF_NOT_FOUND),
    )
    result = core.scan("mypkg", "1.0.0", ecosystem)
    assert result.source_status == SourceStatus.REF_NOT_FOUND
    assert result.source_repo == "https://github.com/example/mypkg"
    assert [f.type for f in result.findings] == [FindingType.SOURCE_REF_NOT_FOUND]
    assert result.findings[0].severity == Severity.MEDIUM
    assert core.exit_code_for(result) == 0


def test_likely_generated_file_gets_low_confidence():
    root = FIXTURES / "benign"
    generated = FileEntry(
        path="mypkg/_version.py", data=b"__version__ = '1.0.0'\n"
    )
    ecosystem = FakeEcosystem(
        FakeFetcher(root / "wheel", extra_files=[generated]),
        FakeSourceResolver(root / "source"),
    )
    result = core.scan("mypkg", "1.0.0", ecosystem)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.type == FindingType.PHANTOM_FILE
    assert finding.confidence == Confidence.LOW
    assert "generated" in finding.reason
