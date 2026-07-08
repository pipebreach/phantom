"""Detection for compiled Python bytecode shipped inside a wheel.

Wheels normally ship source ``.py`` and let the installer byte-compile on
install. A wheel that ships ``.pyc`` (especially without the corresponding
``.py``) is a blind spot: the executed bytecode cannot be read as source and
audited. This module maps a ``.pyc`` back to its source module path so the
differ can flag bytecode that has no declared source counterpart.

The ``.pyc`` payload is deliberately NOT unmarshalled. ``marshal`` is
documented as unsafe on hostile data, so deep bytecode-vs-source verification
is deferred; this detects the unauditable-bytecode gap without parsing
attacker-controlled bytecode.
"""

from __future__ import annotations

import re

from phantom.models import FileEntry

# Strips the interpreter tag and optional optimization level from a cached
# module name: ``mod.cpython-312.opt-2.pyc`` or ``mod.cpython-312.pyc``.
_TAGGED_PYC_RE = re.compile(r"\.(?:cpython-\d+|pypy\d+-pp\d+)(?:\.opt-\d)?\.pyc$")


def is_pyc(path: str) -> bool:
    return path.endswith(".pyc")


def source_module_path(pyc_path: str) -> str:
    """Map a ``.pyc`` path to the ``.py`` it was compiled from.

    ``pkg/__pycache__/mod.cpython-312.pyc`` -> ``pkg/mod.py``
    ``mod.pyc`` -> ``mod.py``
    """
    directory, _, filename = pyc_path.rpartition("/")
    directory = directory.removesuffix("__pycache__").rstrip("/")
    stem = _TAGGED_PYC_RE.sub("", filename)
    if stem == filename:  # untagged: plain mod.pyc
        stem = filename.removesuffix(".pyc")
    module = f"{stem}.py"
    return f"{directory}/{module}" if directory else module


def has_source_counterpart(module_path: str, source_files: list[FileEntry]) -> bool:
    """Whether any source file plausibly is the module this ``.pyc`` compiled.

    Loose on purpose (exact/suffix path or basename match) so a bytecode file
    with legitimate declared source is never flagged.
    """
    basename = module_path.rsplit("/", 1)[-1]
    for source in source_files:
        if (
            source.path == module_path
            or source.path.endswith("/" + module_path)
            or source.path.rsplit("/", 1)[-1] == basename
        ):
            return True
    return False
