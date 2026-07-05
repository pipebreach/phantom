"""PyPI ecosystem: wheels from the JSON API, sources from GitHub tag
tarballs. Only pure-Python wheels (``*-none-any.whl``) are in scope."""

from __future__ import annotations

import io
import json
import re
import tarfile
import zipfile

from phantom.cache import DiskCache, http_get
from phantom.ecosystems.base import Ecosystem, Fetcher, SourceResolver
from phantom.errors import FetchError, NotFoundError, OutOfScopeError
from phantom.models import Artifact, FileEntry, FindingType, NoSource, SourceTree
from phantom.normalizers.base import Normalizer
from phantom.normalizers.python_ast import PythonASTNormalizer

PYPI_JSON_URL = "https://pypi.org/pypi/{pkg}/{version}/json"
# codeload serves public tag tarballs without the API rate limit.
GITHUB_TARBALL_URL = "https://codeload.github.com/{owner}/{repo}/tar.gz/refs/tags/{tag}"

# Tag conventions tried in order.
TAG_PATTERNS = ("v{version}", "{version}", "release-{version}")

# project_urls keys checked in priority order.
_SOURCE_URL_KEYS = ("source", "source code", "repository", "code", "github", "homepage")

_GITHUB_RE = re.compile(
    r"https?://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
)


def _parse_github_repo(url: str) -> tuple[str, str] | None:
    match = _GITHUB_RE.match(url.strip())
    if not match:
        return None
    owner = match.group("owner")
    repo = match.group("repo").removesuffix(".git")
    return owner, repo


class PyPIFetcher(Fetcher):
    def __init__(self, cache: DiskCache | None = None) -> None:
        self.cache = cache

    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        url = PYPI_JSON_URL.format(pkg=pkg, version=version)
        try:
            metadata = json.loads(http_get(url, self.cache))
        except NotFoundError as exc:
            raise NotFoundError(f"{pkg}=={version} not found on PyPI") from exc

        releases = metadata.get("urls", [])
        wheel = self._pick_pure_wheel(releases)
        if wheel is None:
            raise OutOfScopeError(self._out_of_scope_reason(pkg, version, releases))

        data = http_get(wheel["url"], self.cache)
        files = self._unpack_wheel(data)
        return Artifact(
            package=pkg,
            version=version,
            filename=wheel["filename"],
            files=files,
            metadata=metadata.get("info", {}),
        )

    @staticmethod
    def _pick_pure_wheel(releases: list[dict]) -> dict | None:
        for release in releases:
            if release.get("packagetype") == "bdist_wheel" and release.get(
                "filename", ""
            ).endswith("-none-any.whl"):
                return release
        return None

    @staticmethod
    def _out_of_scope_reason(pkg: str, version: str, releases: list[dict]) -> str:
        kinds = sorted({r.get("packagetype", "?") for r in releases})
        if "bdist_wheel" in kinds:
            detail = "only platform-specific (compiled) wheels are published"
        elif "sdist" in kinds:
            detail = "only an sdist is published"
        else:
            detail = "no distribution files found"
        return (
            f"{pkg}=={version}: {detail}. M1 only supports pure-Python wheels "
            f"(*-none-any.whl)."
        )

    @staticmethod
    def _unpack_wheel(data: bytes) -> list[FileEntry]:
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            raise FetchError(f"downloaded wheel is not a valid zip: {exc}") from exc
        entries = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            entries.append(FileEntry(path=info.filename, data=archive.read(info)))
        return entries


class PyPISourceResolver(SourceResolver):
    def __init__(self, cache: DiskCache | None = None) -> None:
        self.cache = cache

    def resolve_source(
        self, pkg: str, version: str, metadata: dict
    ) -> SourceTree | NoSource:
        repo = self._find_github_repo(metadata)
        if repo is None:
            return NoSource(
                finding_type=FindingType.NO_SOURCE_DECLARED,
                detail=(
                    f"{pkg} declares no GitHub source repository in its PyPI "
                    f"metadata (project_urls/home_page). The published artifact "
                    f"cannot be verified against any source."
                ),
            )
        owner, name = repo
        repo_url = f"https://github.com/{owner}/{name}"
        tried = []
        for pattern in TAG_PATTERNS:
            tag = pattern.format(version=version)
            tried.append(tag)
            try:
                data = http_get(
                    GITHUB_TARBALL_URL.format(owner=owner, repo=name, tag=tag),
                    self.cache,
                )
            except NotFoundError:
                continue
            return SourceTree(repo_url=repo_url, ref=tag, files=_untar(data))
        return NoSource(
            finding_type=FindingType.SOURCE_REF_NOT_FOUND,
            detail=(
                f"no tag matching version {version} found in {repo_url} "
                f"(tried: {', '.join(tried)})"
            ),
            repo_url=repo_url,
        )

    @staticmethod
    def _find_github_repo(metadata: dict) -> tuple[str, str] | None:
        project_urls = {
            key.lower(): value
            for key, value in (metadata.get("project_urls") or {}).items()
            if value
        }
        candidates = [
            project_urls[key] for key in _SOURCE_URL_KEYS if key in project_urls
        ]
        candidates += [v for v in project_urls.values() if v not in candidates]
        if metadata.get("home_page"):
            candidates.append(metadata["home_page"])
        for url in candidates:
            repo = _parse_github_repo(url)
            if repo is not None:
                return repo
        return None


def _untar(data: bytes) -> list[FileEntry]:
    """Extract a tarball in memory, stripping GitHub's top-level directory."""
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except tarfile.TarError as exc:
        raise FetchError(f"downloaded source tarball is invalid: {exc}") from exc
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


class PyPIEcosystem(Ecosystem):
    name = "pypi"

    def __init__(self, cache: DiskCache | None = None) -> None:
        self._fetcher = PyPIFetcher(cache)
        self._source_resolver = PyPISourceResolver(cache)
        self._normalizers: list[Normalizer] = [PythonASTNormalizer()]

    @property
    def fetcher(self) -> Fetcher:
        return self._fetcher

    @property
    def source_resolver(self) -> SourceResolver:
        return self._source_resolver

    @property
    def normalizers(self) -> list[Normalizer]:
        return self._normalizers
