"""Unit tests for PyPI-specific logic that needs no network."""

from __future__ import annotations

import pytest

from phantom.ecosystems.github import parse_repo_url
from phantom.ecosystems.pypi import PyPIFetcher, PyPISourceResolver


def test_parse_github_repo_variants():
    assert parse_repo_url("https://github.com/BerriAI/litellm") == (
        "BerriAI",
        "litellm",
    )
    assert parse_repo_url("https://github.com/psf/requests.git") == (
        "psf",
        "requests",
    )
    assert parse_repo_url("https://www.github.com/psf/requests/") == (
        "psf",
        "requests",
    )
    assert parse_repo_url("https://gitlab.com/owner/repo") is None
    assert parse_repo_url("https://example.com") is None


def test_find_github_repo_prefers_source_over_homepage():
    metadata = {
        "project_urls": {
            "Homepage": "https://github.com/wrong/homepage-mirror",
            "Source": "https://github.com/right/repo",
        }
    }
    assert PyPISourceResolver._find_github_repo(metadata) == ("right", "repo")


def test_find_github_repo_falls_back_to_home_page():
    metadata = {
        "project_urls": {"Docs": "https://example.com"},
        "home_page": "https://github.com/owner/repo",
    }
    assert PyPISourceResolver._find_github_repo(metadata) == ("owner", "repo")


def test_find_github_repo_none_when_absent():
    assert PyPISourceResolver._find_github_repo({"project_urls": None}) is None


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
