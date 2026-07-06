"""npm ecosystem: tarballs from the npm registry, sources from GitHub tag
tarballs via the ``repository`` field of the package manifest.

JS files are compared by raw (line-ending-normalized) content: packages that
publish sources verbatim verify cleanly; built/minified output diverges by
construction and is reported at low confidence until build normalizers land.
"""

from __future__ import annotations

import json
import urllib.parse

from phantom.cache import DiskCache, http_get
from phantom.ecosystems import github
from phantom.ecosystems.base import Ecosystem, Fetcher, SourceResolver
from phantom.errors import NotFoundError
from phantom.models import Artifact, FindingType, NoSource, SourceTree
from phantom.normalizers.base import Normalizer
from phantom.normalizers.raw import RawNormalizer

NPM_META_URL = "https://registry.npmjs.org/{pkg}/{version}"

JS_EXTENSIONS = (".js", ".mjs", ".cjs")


class NpmFetcher(Fetcher):
    def __init__(self, cache: DiskCache | None = None) -> None:
        self.cache = cache

    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        # Scoped names keep the "@" but need the "/" encoded (@scope%2fname).
        quoted = urllib.parse.quote(pkg, safe="@")
        url = NPM_META_URL.format(pkg=quoted, version=version)
        try:
            metadata = json.loads(http_get(url, self.cache))
        except NotFoundError as exc:
            raise NotFoundError(f"{pkg}@{version} not found on the npm registry") from exc

        tarball_url = metadata["dist"]["tarball"]
        data = http_get(tarball_url, self.cache)
        return Artifact(
            package=pkg,
            version=version,
            filename=tarball_url.rsplit("/", 1)[-1],
            files=github.untar(data),  # npm tarballs root at "package/"
            metadata=metadata,
        )


class NpmSourceResolver(SourceResolver):
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
                    f"{pkg} declares no GitHub repository in its manifest "
                    f"(repository/homepage). The published artifact cannot be "
                    f"verified against any source."
                ),
            )
        owner, name = repo
        tree = github.fetch_tag_tree(owner, name, version, self.cache)
        if isinstance(tree, SourceTree):
            return tree
        return NoSource(
            finding_type=FindingType.SOURCE_REF_NOT_FOUND,
            detail=(
                f"no tag matching version {version} found in "
                f"https://github.com/{owner}/{name} (tried: {', '.join(tree)})"
            ),
            repo_url=f"https://github.com/{owner}/{name}",
        )

    @staticmethod
    def _find_github_repo(metadata: dict) -> tuple[str, str] | None:
        repository = metadata.get("repository")
        candidates = []
        if isinstance(repository, dict) and repository.get("url"):
            candidates.append(repository["url"])
        elif isinstance(repository, str):
            candidates.append(repository)
        if metadata.get("homepage"):
            candidates.append(metadata["homepage"])
        for url in candidates:
            repo = github.parse_repo_url(url)
            if repo is not None:
                return repo
        return None


class NpmEcosystem(Ecosystem):
    name = "npm"

    def __init__(self, cache: DiskCache | None = None) -> None:
        self._fetcher = NpmFetcher(cache)
        self._source_resolver = NpmSourceResolver(cache)
        self._normalizers: list[Normalizer] = [RawNormalizer(JS_EXTENSIONS)]

    @property
    def fetcher(self) -> Fetcher:
        return self._fetcher

    @property
    def source_resolver(self) -> SourceResolver:
        return self._source_resolver

    @property
    def normalizers(self) -> list[Normalizer]:
        return self._normalizers
