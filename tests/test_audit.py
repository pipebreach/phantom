"""Lockfile audit: parsing, aggregation and exit codes."""

from __future__ import annotations

from pathlib import Path

import pytest

from phantom import audit, cli
from phantom.ecosystems.base import Fetcher
from phantom.errors import NotFoundError, OutOfScopeError, PhantomError
from phantom.models import Artifact, AuditStatus, Severity
from phantom.registry import Registry

from conftest import FIXTURES, FakeEcosystem, FakeFetcher, FakeSourceResolver, load_tree


class MultiFetcher(Fetcher):
    """Routes each package to a fixture wheel dir or a raised error."""

    def __init__(self, mapping: dict[str, Path | Exception]):
        self.mapping = mapping

    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        target = self.mapping[pkg]
        if isinstance(target, Exception):
            raise target
        return Artifact(
            pkg, version, f"{pkg}-{version}-py3-none-any.whl", load_tree(target), {}
        )


def _audit_ecosystem() -> FakeEcosystem:
    mapping = {
        "goodpkg": FIXTURES / "benign" / "wheel",
        "badpkg": FIXTURES / "injected" / "wheel",
        "binpkg": OutOfScopeError("binpkg==1.0.0: only an sdist is published"),
        "gonepkg": NotFoundError("gonepkg==1.0.0 not found on PyPI"),
    }
    return FakeEcosystem(
        MultiFetcher(mapping), FakeSourceResolver(FIXTURES / "benign" / "source")
    )


def test_requirements_parsing(tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text(
        "# deps\n"
        "goodpkg==1.0.0\n"
        "extras[full]==2.0.0  # inline comment\n"
        "marked==3.0.0 ; python_version >= '3.11'\n"
        "-r other.txt\n"
        "unpinned>=2\n"
        "\n"
    )
    pins, skipped = audit.parse_lockfile(lockfile)
    assert pins == [("goodpkg", "1.0.0"), ("extras", "2.0.0"), ("marked", "3.0.0")]
    assert skipped == ["unpinned>=2"]


def test_poetry_lock_parsing(tmp_path):
    lockfile = tmp_path / "poetry.lock"
    lockfile.write_text(
        '[[package]]\nname = "goodpkg"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "otherpkg"\nversion = "2.1.0"\n'
    )
    pins, skipped = audit.parse_lockfile(lockfile)
    assert pins == [("goodpkg", "1.0.0"), ("otherpkg", "2.1.0")]
    assert skipped == []


def test_missing_lockfile_raises(tmp_path):
    with pytest.raises(PhantomError):
        audit.parse_lockfile(tmp_path / "nope.txt")


def test_audit_aggregates_statuses(tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text(
        "goodpkg==1.0.0\nbadpkg==1.0.0\nbinpkg==1.0.0\ngonepkg==1.0.0\nloose>=1\n"
    )
    result = audit.audit(lockfile, _audit_ecosystem())
    by_package = {e.package: e for e in result.entries}

    assert by_package["goodpkg"].status == AuditStatus.SCANNED
    assert by_package["goodpkg"].result.findings == []
    assert by_package["badpkg"].result.highest_severity == Severity.CRITICAL
    assert by_package["binpkg"].status == AuditStatus.OUT_OF_SCOPE
    assert by_package["gonepkg"].status == AuditStatus.ERROR
    assert by_package["loose>=1"].status == AuditStatus.SKIPPED

    # Findings dominate errors in the exit code.
    assert audit.exit_code_for(result) == 1


def test_audit_exit_codes(tmp_path):
    ecosystem = _audit_ecosystem()

    clean = tmp_path / "clean.txt"
    clean.write_text("goodpkg==1.0.0\n")
    assert audit.exit_code_for(audit.audit(clean, ecosystem)) == 0

    erroring = tmp_path / "erroring.txt"
    erroring.write_text("goodpkg==1.0.0\ngonepkg==1.0.0\n")
    assert audit.exit_code_for(audit.audit(erroring, ecosystem)) == 2


def test_audit_cli_json(tmp_path, capsys):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("goodpkg==1.0.0\nbadpkg==1.0.0\n")
    registry = Registry()
    registry.register(_audit_ecosystem())
    code = cli.run(["audit", str(lockfile), "--json"], registry=registry)
    assert code == 1
    out = capsys.readouterr().out
    assert '"schema_version"' in out
    assert '"badpkg"' in out


def test_audit_cli_missing_lockfile(tmp_path, capsys):
    registry = Registry()
    registry.register(
        FakeEcosystem(
            FakeFetcher(FIXTURES / "benign" / "wheel"),
            FakeSourceResolver(FIXTURES / "benign" / "source"),
        )
    )
    code = cli.run(["audit", str(tmp_path / "nope.txt")], registry=registry)
    assert code == 2
    assert "error" in capsys.readouterr().err
