"""Orchestrator and library entry point: drives the ``Ecosystem`` interfaces
only, holds no state."""

from __future__ import annotations

from phantom import differ
from phantom.ecosystems.base import Ecosystem
from phantom.models import (
    Confidence,
    Finding,
    FindingType,
    NoSource,
    ScanResult,
    Severity,
    SourceStatus,
)


def scan(package: str, version: str, ecosystem: Ecosystem) -> ScanResult:
    """Scan one package version for source/artifact divergence.

    Propagates fetcher errors; unresolvable source is a finding, not an error.
    """
    artifact = ecosystem.fetcher.fetch_artifact(package, version)
    source = ecosystem.source_resolver.resolve_source(
        package, version, artifact.metadata
    )

    if isinstance(source, NoSource):
        return _no_source_result(package, version, ecosystem.name, source)

    outcome = differ.diff(artifact, source, ecosystem.normalizers)
    return ScanResult(
        package=package,
        version=version,
        ecosystem=ecosystem.name,
        source_status=SourceStatus.RESOLVED,
        source_repo=source.repo_url,
        source_ref=source.ref,
        findings=outcome.findings,
        files_scanned=outcome.files_scanned,
    )


def exit_code_for(result: ScanResult) -> int:
    """Return 1 if any finding is high or critical, else 0."""
    if any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in result.findings):
        return 1
    return 0


def _no_source_result(
    package: str, version: str, ecosystem: str, source: NoSource
) -> ScanResult:
    if source.finding_type == FindingType.NO_SOURCE_DECLARED:
        # Unverifiable by construction: a risk in itself.
        status = SourceStatus.NO_SOURCE_DECLARED
        severity = Severity.HIGH
        confidence = Confidence.HIGH
    else:
        # A repo exists but no tag convention matched; flag softly.
        status = SourceStatus.REF_NOT_FOUND
        severity = Severity.MEDIUM
        confidence = Confidence.MEDIUM
    finding = Finding(
        type=source.finding_type,
        path=None,
        severity=severity,
        confidence=confidence,
        reason=source.detail,
    )
    return ScanResult(
        package=package,
        version=version,
        ecosystem=ecosystem,
        source_status=status,
        source_repo=source.repo_url,
        source_ref=None,
        findings=[finding],
        files_scanned=0,
    )
