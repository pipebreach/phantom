"""Unit tests for PyPI-specific logic that needs no network."""

from __future__ import annotations

import pytest

from phantom.ecosystems import forges
from phantom.ecosystems.pypi import PyPIFetcher, PyPISourceResolver


def _resolve(metadata: dict):
    return forges.find_repo(PyPISourceResolver._candidate_urls(metadata))


def test_parse_github_repo_variants():
    assert forges.parse_repo("https://github.com/BerriAI/litellm").owner == "BerriAI"
    assert forges.parse_repo("https://github.com/psf/requests.git").name == "requests"
    assert forges.parse_repo("https://www.github.com/psf/requests/").name == "requests"
    assert forges.parse_repo("https://example.com") is None


def test_find_github_repo_prefers_source_over_homepage():
    metadata = {
        "project_urls": {
            "Homepage": "https://github.com/wrong/homepage-mirror",
            "Source": "https://github.com/right/repo",
        }
    }
    repo = _resolve(metadata)
    assert (repo.owner, repo.name) == ("right", "repo")


def test_find_github_repo_falls_back_to_home_page():
    metadata = {
        "project_urls": {"Docs": "https://example.com"},
        "home_page": "https://github.com/owner/repo",
    }
    repo = _resolve(metadata)
    assert (repo.owner, repo.name) == ("owner", "repo")


def test_find_github_repo_none_when_absent():
    assert _resolve({"project_urls": None}) is None


def test_index_url_override():
    default = PyPIFetcher()
    assert default.index_url == "https://pypi.org/pypi"
    custom = PyPIFetcher(index_url="https://test.pypi.org/pypi/")
    assert custom.index_url == "https://test.pypi.org/pypi"


def test_pick_pure_wheel():
    releases = [
        {"packagetype": "sdist", "filename": "pkg-1.0.tar.gz"},
        {
            "packagetype": "bdist_wheel",
            "filename": "pkg-1.0-cp312-cp312-manylinux_x86_64.whl",
        },
        {"packagetype": "bdist_wheel", "filename": "pkg-1.0-py3-none-any.whl"},
    ]
    picked = PyPIFetcher._pick_pure_wheel(releases)
    assert picked["filename"] == "pkg-1.0-py3-none-any.whl"


@pytest.mark.parametrize(
    ("releases", "fragment"),
    [
        ([{"packagetype": "sdist", "filename": "p.tar.gz"}], "sdist"),
        (
            [{"packagetype": "bdist_wheel", "filename": "p-cp312-linux.whl"}],
            "compiled",
        ),
        ([], "no distribution files"),
    ],
)
def test_out_of_scope_reasons(releases, fragment):
    assert PyPIFetcher._pick_pure_wheel(releases) is None
    assert fragment in PyPIFetcher._out_of_scope_reason("p", "1.0", releases)
