"""Compiled-bytecode detection: path mapping and source-counterpart checks."""

from __future__ import annotations

import pytest

from conftest import FIXTURES, FakeEcosystem, FakeFetcher, FakeSourceResolver

from phantom import bytecode, core
from phantom.models import Confidence, FileEntry, FindingType, Severity


@pytest.mark.parametrize(
    ("pyc", "expected"),
    [
        ("mypkg/__pycache__/core.cpython-312.pyc", "mypkg/core.py"),
        ("mypkg/__pycache__/core.cpython-312.opt-2.pyc", "mypkg/core.py"),
        ("mypkg/__pycache__/core.pypy39-pp73.pyc", "mypkg/core.py"),
        ("core.cpython-311.pyc", "core.py"),
        ("legacy.pyc", "legacy.py"),
    ],
)
def test_source_module_path(pyc, expected):
    assert bytecode.source_module_path(pyc) == expected


def test_has_source_counterpart():
    source = [FileEntry("src/mypkg/core.py", b""), FileEntry("mypkg/util.py", b"")]
    assert bytecode.has_source_counterpart("mypkg/core.py", source)  # suffix
    assert bytecode.has_source_counterpart("mypkg/util.py", source)  # exact-ish
    assert bytecode.has_source_counterpart("elsewhere/util.py", source)  # basename
    assert not bytecode.has_source_counterpart("mypkg/secret.py", source)


def _ecosystem_with(extra: list[FileEntry]) -> FakeEcosystem:
    root = FIXTURES / "benign"
    return FakeEcosystem(
        FakeFetcher(root / "wheel", extra_files=extra),
        FakeSourceResolver(root / "source"),
    )


def test_bytecode_without_source_is_flagged():
    pyc = FileEntry("mypkg/__pycache__/stealth.cpython-312.pyc", b"\x00fake-bytecode")
    result = core.scan("mypkg", "1.0.0", _ecosystem_with([pyc]))
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.type == FindingType.PHANTOM_FILE
    assert finding.path == "mypkg/__pycache__/stealth.cpython-312.pyc"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.HIGH
    assert "bytecode:no-source" in finding.execution_vectors


def test_bytecode_with_source_is_not_flagged():
    # core.py exists in the benign source tree, so its compiled form is fine.
    pyc = FileEntry("mypkg/__pycache__/core.cpython-312.pyc", b"\x00fake-bytecode")
    result = core.scan("mypkg", "1.0.0", _ecosystem_with([pyc]))
    assert result.findings == []
