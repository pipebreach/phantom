"""GitHub source resolution shared by ecosystems: repo URL parsing, tag
probing and in-memory tarball extraction."""

from __future__ import annotations

import io
import re
import tarfile

from phantom.cache import DiskCache, http_get
from phantom.errors import FetchError, NotFoundError
from phantom.models import FileEntry, SourceTree

# codeload serves public tag tarballs without the API rate limit.
TARBALL_URL = "https://codeload.github.com/{owner}/{repo}/tar.gz/refs/tags/{tag}"

# Tag conventions tried in order.
TAG_PATTERNS = ("v{version}", "{version}", "release-{version}")

_GITHUB_RE = re.compile(
    r"https?://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
)
_SHORTHAND_RE = re.compile(r"^(?:github:)?(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$")


def parse_repo_url(url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from the GitHub URL forms found in package
    metadata: https, git+https, git://, ssh, and the npm ``github:o/r`` /
    ``o/r`` shorthands."""
    url = url.strip().removeprefix("git+")
    url = re.sub(r"^git://", "https://", url)
    url = re.sub(r"^(?:ssh://)?git@github\.com[:/]", "https://github.com/", url)
    match = _GITHUB_RE.match(url) or _SHORTHAND_RE.match(url)
    if not match:
        return None
    return match.group("owner"), match.group("repo").removesuffix(".git")


def fetch_tag_tree(
    owner: str, repo: str, version: str, cache: DiskCache | None
) -> SourceTree | list[str]:
    """Probe tag conventions for a version and fetch the matching tree.

    Returns the ``SourceTree`` on success, or the list of tags tried when no
    tag matched (for the ``SOURCE_REF_NOT_FOUND`` finding detail).
    """
    tried = []
    for pattern in TAG_PATTERNS:
        tag = pattern.format(version=version)
        tried.append(tag)
        try:
            data = http_get(TARBALL_URL.format(owner=owner, repo=repo, tag=tag), cache)
        except NotFoundError:
            continue
        return SourceTree(
            repo_url=f"https://github.com/{owner}/{repo}",
            ref=tag,
            files=untar(data),
        )
    return tried


def untar(data: bytes) -> list[FileEntry]:
    """Extract a gzipped tarball in memory, stripping the top-level directory
    (GitHub's ``{repo}-{tag}/``, npm's ``package/``)."""
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except tarfile.TarError as exc:
        raise FetchError(f"downloaded tarball is invalid: {exc}") from exc
    entries = []
    with archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = member.name.split("/", 1)[1] if "/" in member.name else member.name
            handle = archive.extractfile(member)
            if handle is None:
                continue
            entries.append(FileEntry(path=path, data=handle.read()))
    return entries
