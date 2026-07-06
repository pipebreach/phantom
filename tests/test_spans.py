"""Phantom span detection: intra-file AST diff."""

from __future__ import annotations

from phantom import core, spans
from phantom.models import FileEntry, FindingType, Severity


def test_injected_function_produces_span():
    source = FileEntry("mypkg/mod.py", b"def f(x):\n    return x\n")
    artifact = FileEntry(
        "mypkg/mod.py",
        b"def f(x):\n    return x\n\n\ndef evil():\n    import socket\n    return socket\n",
    )
    found = spans.find_spans(artifact, source)
    assert len(found) == 1
    span = found[0]
    assert span.kind == "injected"
    assert span.name == "evil"
    assert span.start_line == 5
    assert span.end_line == 7


def test_modified_function_is_marked_modified():
    source = FileEntry("m.py", b"def f(x):\n    return x\n")
    artifact = FileEntry("m.py", b"def f(x):\n    return x + 1\n")
    found = spans.find_spans(artifact, source)
    assert len(found) == 1
    assert found[0].kind == "modified"
    assert found[0].name == "f"


def test_deletion_only_produces_no_spans():
    source = FileEntry("m.py", b"def f(x):\n    return x\n\n\ndef g():\n    pass\n")
    artifact = FileEntry("m.py", b"def f(x):\n    return x\n")
    assert spans.find_spans(artifact, source) == []


def test_unparseable_side_returns_none():
    good = FileEntry("m.py", b"x = 1\n")
    broken = FileEntry("m.py", b"def broken(:\n")
    assert spans.find_spans(broken, good) is None
    assert spans.find_spans(good, broken) is None


def test_counterpart_prefers_path_suffix_over_basename():
    files = [
        FileEntry("src/mypkg/core.py", b""),
        FileEntry("scripts/core.py", b""),
    ]
    match = spans.find_source_counterpart(FileEntry("mypkg/core.py", b""), files)
    assert match == (files[0], "path")


def test_counterpart_falls_back_to_unique_basename():
    files = [FileEntry("somewhere/else/util.py", b"")]
    match = spans.find_source_counterpart(FileEntry("mypkg/util.py", b""), files)
    assert match == (files[0], "basename")

    ambiguous = files + [FileEntry("other/util.py", b"")]
    assert (
        spans.find_source_counterpart(FileEntry("mypkg/util.py", b""), ambiguous)
        is None
    )


def test_scan_localizes_injected_span(span_injected_ecosystem):
    result = core.scan("mypkg", "1.0.0", span_injected_ecosystem)
    assert result.findings
    assert all(f.type == FindingType.PHANTOM_SPAN for f in result.findings)
    beacon = result.findings[0]
    assert beacon.severity == Severity.CRITICAL
    assert beacon.path == "mypkg/core.py"
    assert beacon.start_line == 10
    assert beacon.end_line == 15
    assert any(v.startswith("env-read:") for v in beacon.execution_vectors)
    assert any(v.startswith("network:") for v in beacon.execution_vectors)
    assert core.exit_code_for(result) == 1
