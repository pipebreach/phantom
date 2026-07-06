"""Forge dispatch: URL parsing and tag-archive URLs for GitHub and GitLab."""

from __future__ import annotations

import pytest

from phantom.ecosystems import forges
from phantom.ecosystems.forges import GitHubForge, GitLabForge


@pytest.mark.parametrize(
    ("url", "host", "owner", "name"),
    [
        ("https://github.com/psf/requests", "github.com", "psf", "requests"),
        ("git+https://github.com/psf/requests.git", "github.com", "psf", "requests"),
        ("git@github.com:psf/requests.git", "github.com", "psf", "requests"),
        ("github:psf/requests", "github.com", "psf", "requests"),
        ("https://gitlab.com/group/project", "gitlab.com", "group", "project"),
        ("https://gitlab.com/g/sub/project.git", "gitlab.com", "g/sub", "project"),
        (
            "https://gitlab.com/g/project/-/tree/main",
            "gitlab.com",
            "g",
            "project",
        ),
    ],
)
def test_parse_repo(url, host, owner, name):
    repo = forges.parse_repo(url)
    assert (repo.host, repo.owner, repo.name) == (host, owner, name)


def test_unknown_host_is_none():
    assert forges.parse_repo("https://bitbucket.org/o/r") is None
    assert forges.parse_repo("https://example.com") is None


def test_find_repo_returns_first_recognized():
    repo = forges.find_repo(
        ["https://example.com/docs", "", "https://github.com/o/r"]
    )
    assert (repo.host, repo.owner, repo.name) == ("github.com", "o", "r")
    assert forges.find_repo(["https://example.com"]) is None


def test_archive_urls():
    gh = GitHubForge().match("https://github.com/o/r")
    assert GitHubForge()._archive_url(gh, "v1.2.3") == (
        "https://codeload.github.com/o/r/tar.gz/refs/tags/v1.2.3"
    )
    gl = GitLabForge().match("https://gitlab.com/g/sub/r")
    assert GitLabForge()._archive_url(gl, "v1.2.3") == (
        "https://gitlab.com/api/v4/projects/g%2Fsub%2Fr"
        "/repository/archive.tar.gz?sha=v1.2.3"
    )
