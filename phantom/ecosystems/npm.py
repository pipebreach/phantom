"""npm ecosystem: tarballs from the npm registry, sources from forge tag
tarballs via the ``repository`` field of the package manifest.

JS files are compared by raw (line-ending-normalized) content: packages that
publish sources verbatim verify cleanly; built/minified output diverges by
construction and is reported at low confidence until build normalizers land.
"""

from __future__ import annotations

import json
import urllib.parse

from phantom.cache import DiskCache, http_get
from phantom.ecosystems import forges
from phantom.ecosystems.base import Ecosystem, Fetcher, SourceResolver
from phantom.errors import NotFoundError
from phantom.models import Artifact, FindingType, NoSource, SourceTree
from phantom.normalizers.base import Normalizer
from phantom.normalizers.raw import RawNormalizer

DEFAULT_REGISTRY_URL = "https://registry.npmjs.org"

JS_EXTENSIONS = (".js", ".mjs", ".cjs")


class NpmFetcher(Fetcher):
    def __init__(
        self, cache: DiskCache | None = None, registry_url: str | None = None
    ) -> None:
        self.cache = cache
        self.registry_url = (registry_url or DEFAULT_REGISTRY_URL).rstrip("/")

    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        # Scoped names keep the "@" but need the "/" encoded (@scope%2fname).
        quoted = urllib.parse.quote(pkg, safe="@")
        url = f"{self.registry_url}/{quoted}/{version}"
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
            files=forges.untar(data),  # npm tarballs root at "package/"
            metadata=metadata,
        )


class NpmSourceResolver(SourceResolver):
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
                    f"{pkg} declares no supported source repository in its "
                    f"manifest (repository/homepage). The published artifact "
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
        repository = metadata.get("repository")
        candidates = []
        if isinstance(repository, dict) and repository.get("url"):
            candidates.append(repository["url"])
        elif isinstance(repository, str):
            candidates.append(repository)
        if metadata.get("homepage"):
            candidates.append(metadata["homepage"])
        return candidates


class NpmEcosystem(Ecosystem):
    name = "npm"

    def __init__(
        self, cache: DiskCache | None = None, registry_url: str | None = None
    ) -> None:
        self._fetcher = NpmFetcher(cache, registry_url)
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
