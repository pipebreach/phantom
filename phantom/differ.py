"""Compares artifact files against a source hash index.

Content-based and path-agnostic: a wheel file matches if its normalized hash
exists anywhere in the source tree, so build-time moves and renames do not
cause false positives.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from phantom import bytecode, risk, sourcemaps, spans
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

_JS_EXTENSIONS = (".js", ".mjs", ".cjs")

# Commonly generated at build time (setuptools-scm, hatch-vcs); a phantom
# hit on these gets low confidence.
_LIKELY_GENERATED_BASENAMES = {"_version.py", "version.py", "_version_meta.py"}

# Build/bundle output locations; divergence there is expected until build
# normalizers exist, so confidence drops to low.
_LIKELY_BUILD_PREFIXES = ("dist/", "build/", "out/")
_LIKELY_BUILD_SUFFIXES = (".min.js", ".bundle.js")


@dataclass
class DiffOutcome:
    findings: list[Finding]
    files_scanned: int


@dataclass(frozen=True)
class _Context:
    """Shared lookups a diverging-file finding may need beyond the file itself."""

    source: SourceTree
    artifact_by_path: dict[str, FileEntry]
    source_raw_hashes: frozenset[str]


def diff(
    artifact: Artifact, source: SourceTree, normalizers: list[Normalizer]
) -> DiffOutcome:
    source_hashes = _build_index(source.files, normalizers)
    ctx = _Context(
        source=source,
        artifact_by_path={file.path: file for file in artifact.files},
        source_raw_hashes=frozenset(_raw_hash(file.data) for file in source.files),
    )
    findings: list[Finding] = []
    files_scanned = 0

    for file in artifact.files:
        if _is_packaging_metadata(file.path):
            continue
        if file.path.endswith(".pth"):
            files_scanned += 1
            findings.append(_pth_finding(file))
            continue
        if bytecode.is_pyc(file.path):
            files_scanned += 1
            finding = _pyc_finding(file, source)
            if finding is not None:
                findings.append(finding)
            continue
        normalizer = _normalizer_for(file, normalizers)
        if normalizer is None:
            continue
        files_scanned += 1
        if normalizer.normalized_hash(file) in source_hashes:
            continue
        findings.extend(_diverging_file_findings(file, ctx))

    findings.sort(key=lambda f: (-f.severity.rank, f.path or "", f.start_line or 0))
    return DiffOutcome(findings=findings, files_scanned=files_scanned)


def _raw_hash(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _diverging_file_findings(file: FileEntry, ctx: _Context) -> list[Finding]:
    """A diverging Python file with a source counterpart gets span-level
    localization; anything else is a whole phantom file."""
    if file.path.endswith(".py"):
        counterpart = spans.find_source_counterpart(file, ctx.source.files)
        if counterpart is not None:
            found = spans.find_spans(file, counterpart[0])
            if found is not None:
                return _span_findings(file, counterpart, found, ctx.source)
    return [_phantom_finding(file, ctx)]


def _span_findings(
    file: FileEntry,
    counterpart: tuple[FileEntry, str],
    found: list[spans.Span],
    source: SourceTree,
) -> list[Finding]:
    source_file, matched_by = counterpart
    confidence = Confidence.HIGH if matched_by == "path" else Confidence.MEDIUM
    if not found:
        # Only deletions or reordering: divergent, but nothing was added.
        return [
            Finding(
                type=FindingType.PHANTOM_FILE,
                path=file.path,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                reason=(
                    f"{file.path} diverges from {source_file.path} in "
                    f"{source.repo_url}@{source.ref}, but no injected code was "
                    f"found; only removed or reordered statements"
                ),
            )
        ]
    findings = []
    for span in found:
        assessment = risk.assess(FileEntry(file.path, span.segment.encode("utf-8")))
        label = f" `{span.name}`" if span.name else ""
        findings.append(
            Finding(
                type=FindingType.PHANTOM_SPAN,
                path=file.path,
                severity=assessment.severity,
                confidence=confidence,
                reason=(
                    f"{span.kind} top-level code{label} at lines "
                    f"{span.start_line}-{span.end_line} of {file.path} is not "
                    f"present in {source_file.path} of {source.repo_url}@"
                    f"{source.ref}; {assessment.detail}"
                ),
                execution_vectors=assessment.vectors,
                start_line=span.start_line,
                end_line=span.end_line,
            )
        )
    return findings


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


def _pyc_finding(file: FileEntry, source: SourceTree) -> Finding | None:
    """Flag compiled bytecode that has no declared source to audit against.

    Returns None when a source module plausibly exists (the .pyc is just a
    compiled form of source verified through its own .py).
    """
    module_path = bytecode.source_module_path(file.path)
    if bytecode.has_source_counterpart(module_path, source.files):
        return None
    return Finding(
        type=FindingType.PHANTOM_FILE,
        path=file.path,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        reason=(
            f"compiled bytecode {file.path} has no corresponding source module "
            f"({module_path}) in {source.repo_url}@{source.ref}; executable "
            f"content shipped only as bytecode cannot be audited against source"
        ),
        execution_vectors=["bytecode:no-source"],
    )


def _phantom_finding(file: FileEntry, ctx: _Context) -> Finding:
    source = ctx.source
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
    else:
        source_map = _sourcemap_note(file, ctx)
        if source_map is not None:
            confidence, note = source_map
            reason += note
        elif file.path.startswith(_LIKELY_BUILD_PREFIXES) or file.path.endswith(
            _LIKELY_BUILD_SUFFIXES
        ):
            confidence = Confidence.LOW
            reason += (
                "; note: this path looks like build/bundle output, which cannot "
                "be verified against the source until build normalizers exist"
            )
    return Finding(
        type=FindingType.PHANTOM_FILE,
        path=file.path,
        severity=assessment.severity,
        confidence=confidence,
        reason=reason,
        execution_vectors=assessment.vectors,
    )


def _sourcemap_note(file: FileEntry, ctx: _Context) -> tuple[Confidence, str] | None:
    """Use a built JS file's source map to relate it to the declared source.

    Returns a (confidence, reason-suffix) pair, or None when there is no usable
    source map. All embedded originals present in the repo means the built
    output is accounted for (low confidence); originals absent from the repo is
    a provenance signal (medium confidence).
    """
    if not file.path.endswith(_JS_EXTENSIONS):
        return None
    source_map = sourcemaps.find_source_map(file, ctx.artifact_by_path)
    if source_map is None:
        return None
    originals = sourcemaps.embedded_originals(source_map)
    if not originals:
        return None
    missing = sum(
        1
        for original in originals
        if _raw_hash(original.encode("utf-8")) not in ctx.source_raw_hashes
    )
    if missing == 0:
        return (
            Confidence.LOW,
            f"; note: built output, and all {len(originals)} source-map "
            f"original(s) are present in the declared source",
        )
    return (
        Confidence.MEDIUM,
        f"; note: this built file's source map references {missing} of "
        f"{len(originals)} original source file(s) not present in the declared "
        f"source",
    )
