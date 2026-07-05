"""Compares artifact files against a source hash index.

Content-based and path-agnostic: a wheel file matches if its normalized hash
exists anywhere in the source tree, so build-time moves and renames do not
cause false positives.
"""

from __future__ import annotations

from dataclasses import dataclass

from phantom import risk
from phantom.models import (
    Artifact,
    Confidence,
    FileEntry,
    Finding,
    FindingType,
    Severity,
    SourceTree,
)
from phantom.normalizers.base import Normalizer

# Commonly generated at build time (setuptools-scm, hatch-vcs); a phantom
# hit on these gets low confidence.
_LIKELY_GENERATED_BASENAMES = {"_version.py", "version.py", "_version_meta.py"}


@dataclass
class DiffOutcome:
    findings: list[Finding]
    files_scanned: int


def diff(
    artifact: Artifact, source: SourceTree, normalizers: list[Normalizer]
) -> DiffOutcome:
    source_hashes = _build_index(source.files, normalizers)
    findings: list[Finding] = []
    files_scanned = 0

    for file in artifact.files:
        if _is_packaging_metadata(file.path):
            continue
        if file.path.endswith(".pth"):
            files_scanned += 1
            findings.append(_pth_finding(file))
            continue
        normalizer = _normalizer_for(file, normalizers)
        if normalizer is None:
            continue
        files_scanned += 1
        if normalizer.normalized_hash(file) in source_hashes:
            continue
        findings.append(_phantom_finding(file, source))

    findings.sort(key=lambda f: (-f.severity.rank, f.path or ""))
    return DiffOutcome(findings=findings, files_scanned=files_scanned)


def _build_index(files: list[FileEntry], normalizers: list[Normalizer]) -> set[str]:
    index: set[str] = set()
    for file in files:
        normalizer = _normalizer_for(file, normalizers)
        if normalizer is not None:
            index.add(normalizer.normalized_hash(file))
    return index


def _normalizer_for(
    file: FileEntry, normalizers: list[Normalizer]
) -> Normalizer | None:
    for normalizer in normalizers:
        if normalizer.applies_to(file):
            return normalizer
    return None


def _is_packaging_metadata(path: str) -> bool:
    first = path.split("/", 1)[0]
    return first.endswith(".dist-info") or first.endswith(".data")


def _pth_finding(file: FileEntry) -> Finding:
    # .pth import lines execute at every interpreter startup.
    has_import = any(
        line.lstrip().startswith("import ")
        for line in file.data.decode("utf-8", errors="replace").splitlines()
    )
    return Finding(
        type=FindingType.SUSPICIOUS_PTH,
        path=file.path,
        severity=Severity.CRITICAL if has_import else Severity.HIGH,
        confidence=Confidence.HIGH,
        reason=(
            ".pth file shipped inside a wheel; "
            + (
                "it contains import lines that execute code at every "
                "interpreter startup"
                if has_import
                else "legitimate wheels almost never include .pth files"
            )
        ),
        execution_vectors=["startup:.pth-import"] if has_import else [],
    )


def _phantom_finding(file: FileEntry, source: SourceTree) -> Finding:
    assessment = risk.assess(file)
    basename = file.path.rsplit("/", 1)[-1]
    confidence = Confidence.HIGH
    reason = (
        f"content of {file.path} has no normalized-hash match anywhere in "
        f"{source.repo_url}@{source.ref}; {assessment.detail}"
    )
    if basename in _LIKELY_GENERATED_BASENAMES:
        confidence = Confidence.LOW
        reason += (
            "; note: this filename is commonly generated at build time "
            "(e.g. setuptools-scm), so this may be legitimate generated code"
        )
    return Finding(
        type=FindingType.PHANTOM_FILE,
        path=file.path,
        severity=assessment.severity,
        confidence=confidence,
        reason=reason,
        execution_vectors=assessment.vectors,
    )
