"""Test doubles implementing the Ecosystem contracts over local fixtures;
unit tests never touch the network."""

from __future__ import annotations

from pathlib import Path

import pytest

from phantom.ecosystems.base import Ecosystem, Fetcher, SourceResolver
from phantom.models import Artifact, FileEntry, FindingType, NoSource, SourceTree
from phantom.normalizers.base import Normalizer
from phantom.normalizers.python_ast import PythonASTNormalizer

FIXTURES = Path(__file__).parent / "fixtures"

FAKE_METADATA = {
    "project_urls": {"Source": "https://github.com/example/mypkg"},
    "home_page": "https://example.invalid",
}


def load_tree(root: Path) -> list[FileEntry]:
    return [
        FileEntry(path=str(path.relative_to(root)), data=path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


class FakeFetcher(Fetcher):
    def __init__(self, wheel_dir: Path, extra_files: list[FileEntry] | None = None):
        self.wheel_dir = wheel_dir
        self.extra_files = extra_files or []

    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        return Artifact(
            package=pkg,
            version=version,
            filename=f"{pkg}-{version}-py3-none-any.whl",
            files=load_tree(self.wheel_dir) + self.extra_files,
            metadata=FAKE_METADATA,
        )


class FakeSourceResolver(SourceResolver):
    def __init__(self, source_dir: Path):
        self.source_dir = source_dir

    def resolve_source(
        self, pkg: str, version: str, metadata: dict
    ) -> SourceTree | NoSource:
        return SourceTree(
            repo_url="https://github.com/example/mypkg",
            ref=f"v{version}",
            files=load_tree(self.source_dir),
        )


class NoSourceResolver(SourceResolver):
    def __init__(self, finding_type: FindingType):
        self.finding_type = finding_type

    def resolve_source(
        self, pkg: str, version: str, metadata: dict
    ) -> SourceTree | NoSource:
        repo = (
            "https://github.com/example/mypkg"
            if self.finding_type == FindingType.SOURCE_REF_NOT_FOUND
            else None
        )
        return NoSource(
            finding_type=self.finding_type, detail="fixture", repo_url=repo
        )


class FakeEcosystem(Ecosystem):
    name = "pypi"

    def __init__(
        self,
        fetcher: Fetcher,
        source_resolver: SourceResolver,
        normalizers: list[Normalizer] | None = None,
        name: str = "pypi",
    ):
        self.name = name
        self._fetcher = fetcher
        self._source_resolver = source_resolver
        self._normalizers = normalizers or [PythonASTNormalizer()]

    @property
    def fetcher(self) -> Fetcher:
        return self._fetcher

    @property
    def source_resolver(self) -> SourceResolver:
        return self._source_resolver

    @property
    def normalizers(self) -> list[Normalizer]:
        return self._normalizers


@pytest.fixture
def benign_ecosystem() -> FakeEcosystem:
    root = FIXTURES / "benign"
    return FakeEcosystem(
        FakeFetcher(root / "wheel"), FakeSourceResolver(root / "source")
    )


@pytest.fixture
def injected_ecosystem() -> FakeEcosystem:
    root = FIXTURES / "injected"
    return FakeEcosystem(
        FakeFetcher(root / "wheel"), FakeSourceResolver(root / "source")
    )


@pytest.fixture
def span_injected_ecosystem() -> FakeEcosystem:
    root = FIXTURES / "span_injected"
    return FakeEcosystem(
        FakeFetcher(root / "wheel"), FakeSourceResolver(root / "source")
    )
