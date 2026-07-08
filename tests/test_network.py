"""Optional integration tests against real PyPI/GitHub (brief, section 6).

Run with: PHANTOM_NETWORK_TESTS=1 pytest -m network
"""

from __future__ import annotations

import os

import pytest

from phantom import core
from phantom.cache import DiskCache
from phantom.models import Severity
from phantom.registry import build_default_registry

pytestmark = [
    pytest.mark.network,
    pytest.mark.skipif(
        not os.environ.get("PHANTOM_NETWORK_TESTS"),
        reason="set PHANTOM_NETWORK_TESTS=1 to run network integration tests",
    ),
]


@pytest.fixture
def pypi(tmp_path):
    return build_default_registry(DiskCache(tmp_path / "cache")).get("pypi")


def test_known_clean_package(pypi):
    # six 1.16.0: pure wheel, GitHub repo, tag "1.16.0".
    result = core.scan("six", "1.16.0", pypi)
    assert result.source_ref is not None
    assert not any(
        f.severity in (Severity.HIGH, Severity.CRITICAL) for f in result.findings
    )


def test_scan_is_deterministic_across_runs(pypi):
    first = core.scan("six", "1.16.0", pypi).to_dict()
    second = core.scan("six", "1.16.0", pypi).to_dict()
    assert first == second


def test_known_clean_npm_package(tmp_path):
    npm = build_default_registry(DiskCache(tmp_path / "cache")).get("npm")
    # mime-db publishes its files verbatim and tags releases as v{version}.
    result = core.scan("mime-db", "1.52.0", npm)
    assert result.source_ref == "v1.52.0"
    assert not any(
        f.severity in (Severity.HIGH, Severity.CRITICAL) for f in result.findings
    )


def test_gitlab_tag_tree_fetch():
    from phantom.ecosystems import forges

    repo = forges.parse_repo("https://gitlab.com/gitlab-org/gitlab-svgs")
    tree = repo.forge.fetch_tag_tree(repo, "3.146.0", None)
    assert tree.ref == "v3.146.0"
    assert tree.files


def test_calver_date_padding_resolves(pypi):
    # certifi ships 2026.6.17 but tags 2026.06.17; the variant probe finds it.
    result = core.scan("certifi", "2026.6.17", pypi)
    assert result.source_ref == "2026.06.17"
    assert not result.findings
