"""PyPI ecosystem: wheels from the JSON API, sources from forge tag tarballs.
Only pure-Python wheels (``*-none-any.whl``) are in scope."""

from __future__ import annotations

import io
import json
import zipfile

from phantom.cache import DiskCache, http_get
from phantom.ecosystems import forges
from phantom.ecosystems.base import Ecosystem, Fetcher, SourceResolver
from phantom.errors import FetchError, NotFoundError, OutOfScopeError
from phantom.models import Artifact, FileEntry, FindingType, NoSource, SourceTree
from phantom.normalizers.base import Normalizer
from phantom.normalizers.python_ast import PythonASTNormalizer

DEFAULT_INDEX_URL = "https://pypi.org/pypi"

# project_urls keys checked in priority order.
_SOURCE_URL_KEYS = ("source", "source code", "repository", "code", "github", "homepage")


class PyPIFetcher(Fetcher):
    def __init__(
        self, cache: DiskCache | None = None, index_url: str | None = None
    ) -> None:
        self.cache = cache
        self.index_url = (index_url or DEFAULT_INDEX_URL).rstrip("/")

    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        url = f"{self.index_url}/{pkg}/{version}/json"
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

    def fetch_sdist(self, pkg: str, version: str) -> bytes | None:
        """Download the sdist tarball for a version, or None if none is
        published. Used by assisted rebuild."""
        url = f"{self.index_url}/{pkg}/{version}/json"
        metadata = json.loads(http_get(url, self.cache))
        for release in metadata.get("urls", []):
            if release.get("packagetype") == "sdist" and release.get(
                "filename", ""
            ).endswith(".tar.gz"):
                return http_get(release["url"], self.cache)
        return None

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
            f"{pkg}=={version}: {detail}. Only pure-Python wheels "
            f"(*-none-any.whl) are supported."
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
        repo = forges.find_repo(self._candidate_urls(metadata))
        if repo is None:
            return NoSource(
                finding_type=FindingType.NO_SOURCE_DECLARED,
                detail=(
                    f"{pkg} declares no supported source repository in its PyPI "
                    f"metadata (project_urls/home_page). The published artifact "
                    f"cannot be verified against any source."
                ),
            )
        tree = repo.forge.fetch_tag_tree(repo, version, self.cache)
        if isinstance(tree, SourceTree):
            return tree
        return NoSource(
            finding_type=FindingType.SOURCE_REF_NOT_FOUND,
            detail=(
                f"no tag matching version {version} found in {repo.url} "
                f"(tried: {', '.join(tree)})"
            ),
            repo_url=repo.url,
        )

    @staticmethod
    def _candidate_urls(metadata: dict) -> list[str]:
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
        return candidates


class PyPIEcosystem(Ecosystem):
    name = "pypi"

    def __init__(
        self, cache: DiskCache | None = None, index_url: str | None = None
    ) -> None:
        self._fetcher = PyPIFetcher(cache, index_url)
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
