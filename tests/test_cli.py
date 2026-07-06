"""Exit-code coverage for the CLI (FR-8): every code in its condition."""

from __future__ import annotations

from conftest import FIXTURES, FakeEcosystem, FakeSourceResolver

from phantom import cli
from phantom.ecosystems.base import Fetcher
from phantom.errors import OutOfScopeError
from phantom.models import Artifact
from phantom.registry import Registry


def _registry(ecosystem) -> Registry:
    registry = Registry()
    registry.register(ecosystem)
    return registry


class OutOfScopeFetcher(Fetcher):
    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        raise OutOfScopeError(f"{pkg}=={version}: only an sdist is published")


def test_exit_0_on_clean_scan(benign_ecosystem, capsys):
    code = cli.run(["scan", "mypkg==1.0.0"], registry=_registry(benign_ecosystem))
    assert code == 0
    assert "no findings" in capsys.readouterr().out


def test_exit_1_on_critical_finding(injected_ecosystem, capsys):
    code = cli.run(["scan", "mypkg==1.0.0"], registry=_registry(injected_ecosystem))
    assert code == 1
    assert "CRITICAL" in capsys.readouterr().out


def test_exit_2_on_bad_spec(capsys):
    code = cli.run(["scan", "mypkg"], registry=Registry())
    assert code == 2
    assert "invalid spec" in capsys.readouterr().err


def test_exit_3_on_out_of_scope(capsys):
    ecosystem = FakeEcosystem(
        OutOfScopeFetcher(), FakeSourceResolver(FIXTURES / "benign" / "source")
    )
    code = cli.run(["scan", "mypkg==1.0.0"], registry=_registry(ecosystem))
    assert code == 3
    assert "out of scope" in capsys.readouterr().err


def test_json_flag_emits_schema(injected_ecosystem, capsys):
    code = cli.run(
        ["scan", "mypkg==1.0.0", "--json"], registry=_registry(injected_ecosystem)
    )
    assert code == 1
    assert '"schema_version"' in capsys.readouterr().out


def test_sarif_flag_emits_sarif(injected_ecosystem, capsys):
    code = cli.run(
        ["scan", "mypkg==1.0.0", "--sarif"], registry=_registry(injected_ecosystem)
    )
    assert code == 1
    assert '"2.1.0"' in capsys.readouterr().out
