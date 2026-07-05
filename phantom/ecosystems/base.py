"""Ecosystem plugin contracts. ``phantom.core.scan()`` only speaks these
interfaces; adding an ecosystem never touches the core or the differ."""

from __future__ import annotations

from abc import ABC, abstractmethod

from phantom.models import Artifact, NoSource, SourceTree
from phantom.normalizers.base import Normalizer


class Fetcher(ABC):
    """Obtains the published artifact for a package version."""

    @abstractmethod
    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        """Download and unpack the artifact.

        Raises ``OutOfScopeError`` if the release cannot be analyzed,
        ``NotFoundError`` if it does not exist, ``FetchError`` on network
        failure.
        """


class SourceResolver(ABC):
    """Locates the source tree that should match the published version."""

    @abstractmethod
    def resolve_source(
        self, pkg: str, version: str, metadata: dict
    ) -> SourceTree | NoSource:
        """Resolve repo + ref from registry metadata and fetch the tree.

        Returns ``NoSource`` instead of raising: unresolvable source is a
        finding, not an error.
        """


class Ecosystem(ABC):
    """Bundle of everything needed to scan one packaging ecosystem."""

    name: str

    @property
    @abstractmethod
    def fetcher(self) -> Fetcher: ...

    @property
    @abstractmethod
    def source_resolver(self) -> SourceResolver: ...

    @property
    @abstractmethod
    def normalizers(self) -> list[Normalizer]: ...
