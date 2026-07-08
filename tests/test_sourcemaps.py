"""Source-map extraction and source-map-assisted JS verdicts."""

from __future__ import annotations

import base64
import json

from conftest import FakeEcosystem

from phantom import core, sourcemaps
from phantom.ecosystems.base import Fetcher, SourceResolver
from phantom.ecosystems.npm import JS_EXTENSIONS
from phantom.models import (
    Artifact,
    Confidence,
    FileEntry,
    FindingType,
    NoSource,
    SourceTree,
)
from phantom.normalizers.raw import RawNormalizer

ORIGINAL = "export function add(a, b) {\n  return a + b;\n}\n"


def _inline_map(sources_content):
    payload = json.dumps(
        {"version": 3, "sources": ["../src/add.ts"], "sourcesContent": sources_content}
    ).encode()
    b64 = base64.b64encode(payload).decode()
    return (
        b"!function(n,d){return n+d}();\n"
        b"//# sourceMappingURL=data:application/json;base64," + b64.encode() + b"\n"
    )


def test_find_inline_source_map():
    js = FileEntry("dist/add.min.js", _inline_map([ORIGINAL]))
    smap = sourcemaps.find_source_map(js, {js.path: js})
    assert smap["version"] == 3
    assert sourcemaps.embedded_originals(smap) == [ORIGINAL]


def test_find_external_source_map():
    js = FileEntry("dist/add.min.js", b"var x=1;\n//# sourceMappingURL=add.min.js.map\n")
    mapping = FileEntry(
        "dist/add.min.js.map",
        json.dumps({"version": 3, "sourcesContent": [ORIGINAL]}).encode(),
    )
    smap = sourcemaps.find_source_map(js, {js.path: js, mapping.path: mapping})
    assert sourcemaps.embedded_originals(smap) == [ORIGINAL]


def test_no_source_map_returns_none():
    js = FileEntry("dist/add.min.js", b"var x=1;\n")
    assert sourcemaps.find_source_map(js, {js.path: js}) is None


class _JsFetcher(Fetcher):
    def __init__(self, files):
        self.files = files

    def fetch_artifact(self, pkg, version):
        return Artifact(pkg, version, f"{pkg}-{version}.tgz", self.files, {})


class _JsResolver(SourceResolver):
    def __init__(self, files):
        self.files = files

    def resolve_source(self, pkg, version, metadata):
        return SourceTree("https://github.com/o/r", f"v{version}", self.files)


def _npm(artifact_files, source_files):
    return FakeEcosystem(
        _JsFetcher(artifact_files),
        _JsResolver(source_files),
        normalizers=[RawNormalizer(JS_EXTENSIONS)],
        name="npm",
    )


def test_built_js_verified_via_source_map_is_low_confidence():
    source = [FileEntry("src/add.ts", ORIGINAL.encode())]
    artifact = [FileEntry("dist/add.min.js", _inline_map([ORIGINAL]))]
    result = core.scan("pkg", "1.0.0", _npm(artifact, source))
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.type == FindingType.PHANTOM_FILE
    assert finding.confidence == Confidence.LOW
    assert "present in the declared source" in finding.reason


def test_built_js_with_unknown_origins_is_medium_confidence():
    source = [FileEntry("src/add.ts", ORIGINAL.encode())]
    # Source map claims an original that is not in the repo.
    artifact = [FileEntry("dist/add.min.js", _inline_map(["export const secret = 1;\n"]))]
    result = core.scan("pkg", "1.0.0", _npm(artifact, source))
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.confidence == Confidence.MEDIUM
    assert "not present in the declared source" in finding.reason
