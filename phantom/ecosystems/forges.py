"""Source forges: parse a repository URL and fetch a tag's tree.

A forge is a host matcher plus a tag-archive fetcher. Ecosystem source
resolvers hand a list of candidate URLs (from package metadata) to
``find_repo``, then call ``repo.forge.fetch_tag_tree``. Adding a forge is one
class in the ``_FORGES`` tuple; the resolvers do not change.
"""

from __future__ import annotations

import io
import re
import tarfile
import urllib.parse
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass

from phantom.cache import DiskCache, http_get
from phantom.errors import FetchError, NotFoundError
from phantom.models import FileEntry, SourceTree

# Tag conventions tried in order.
TAG_PATTERNS = ("v{version}", "{version}", "release-{version}")


def _version_variants(version: str) -> list[str]:
    """Alternate spellings of a version to probe as tags.

    Handles date-based CalVer where the published version drops zero-padding
    but the git tag keeps it (or vice versa), e.g. certifi ships ``2026.6.17``
    but tags ``2026.06.17``. Only applies to numeric dotted versions whose
    first segment is a 4-digit year, so semver probing is unaffected.
    """
    variants = [version]
    segments = version.split(".")
    if (
        len(segments) >= 2
        and len(segments[0]) == 4
        and all(segment.isdigit() for segment in segments)
    ):
        for variant in (
            ".".join(segment.zfill(2) for segment in segments),
            ".".join(str(int(segment)) for segment in segments),
        ):
            if variant not in variants:
                variants.append(variant)
    return variants


def _normalize_url(url: str) -> str:
    """Reduce the git/ssh/shorthand URL forms found in metadata to https."""
    url = url.strip().removeprefix("git+")
    url = re.sub(r"^git://", "https://", url)
    url = re.sub(r"^(?:ssh://)?git@([\w.-]+)[:/]", r"https://\1/", url)
    return url


@dataclass(frozen=True)
class Repo:
    forge: "Forge"
    host: str
    owner: str
    name: str

    @property
    def url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.name}"


class Forge(ABC):
    @abstractmethod
    def match(self, url: str) -> Repo | None:
        """Return a ``Repo`` if this forge recognizes the URL, else None."""

    @abstractmethod
    def _archive_url(self, repo: Repo, tag: str) -> str:
        """URL of the gzipped source tarball for a given tag."""

    def fetch_tag_tree(
        self, repo: Repo, version: str, cache: DiskCache | None
    ) -> SourceTree | list[str]:
        """Probe tag conventions and fetch the matching tree.

        Returns the ``SourceTree`` on success, or the list of tags tried when
        none matched (for the ``SOURCE_REF_NOT_FOUND`` finding detail).
        """
        tried = []
        for variant in _version_variants(version):
            for pattern in TAG_PATTERNS:
                tag = pattern.format(version=variant)
                if tag in tried:
                    continue
                tried.append(tag)
                try:
                    data = http_get(self._archive_url(repo, tag), cache)
                except NotFoundError:
                    continue
                return SourceTree(repo_url=repo.url, ref=tag, files=untar(data))
        return tried


class GitHubForge(Forge):
    _URL_RE = re.compile(
        r"https?://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
    )
    _SHORTHAND_RE = re.compile(r"^(?:github:)?(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$")

    def match(self, url: str) -> Repo | None:
        normalized = _normalize_url(url)
        match = self._URL_RE.match(normalized) or self._SHORTHAND_RE.match(normalized)
        if not match:
            return None
        return Repo(
            self, "github.com", match.group("owner"),
            match.group("repo").removesuffix(".git"),
        )

    def _archive_url(self, repo: Repo, tag: str) -> str:
        # codeload serves public tag tarballs without the API rate limit.
        return (
            f"https://codeload.github.com/{repo.owner}/{repo.name}"
            f"/tar.gz/refs/tags/{tag}"
        )


class GitLabForge(Forge):
    """GitLab, including subgroups (``gitlab.com/group/subgroup/project``)."""

    def match(self, url: str) -> Repo | None:
        parsed = urllib.parse.urlparse(_normalize_url(url))
        if parsed.netloc.lower().removeprefix("www.") != "gitlab.com":
            return None
        # Strip GitLab web suffixes like /-/tree/main before splitting.
        path = parsed.path.strip("/").split("/-/")[0].removesuffix(".git")
        if "/" not in path:
            return None
        owner, _, name = path.rpartition("/")
        return Repo(self, "gitlab.com", owner, name)

    def _archive_url(self, repo: Repo, tag: str) -> str:
        project = urllib.parse.quote(f"{repo.owner}/{repo.name}", safe="")
        return (
            f"https://gitlab.com/api/v4/projects/{project}"
            f"/repository/archive.tar.gz?sha={tag}"
        )


_FORGES: tuple[Forge, ...] = (GitHubForge(), GitLabForge())


def parse_repo(url: str) -> Repo | None:
    """Return the first forge that recognizes ``url``, or None."""
    for forge in _FORGES:
        repo = forge.match(url)
        if repo is not None:
            return repo
    return None


def find_repo(candidate_urls: Iterable[str]) -> Repo | None:
    """Return the first candidate URL that resolves to a known forge repo."""
    for url in candidate_urls:
        if not url:
            continue
        repo = parse_repo(url)
        if repo is not None:
            return repo
    return None


def untar(data: bytes) -> list[FileEntry]:
    """Extract a gzipped tarball in memory, stripping the single top-level
    directory (GitHub's ``{repo}-{tag}/``, GitLab's ``{repo}-{tag}-{sha}/``,
    npm's ``package/``)."""
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
