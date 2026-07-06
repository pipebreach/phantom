"""Raw content hashing for file types without a semantic normalizer yet.

Only line endings are normalized, so it matches packages that publish files
verbatim. Built/minified output diverges by construction; those findings are
downgraded to low confidence by the differ until M3 adds build normalizers.
"""

from __future__ import annotations

import hashlib

from phantom.models import FileEntry
from phantom.normalizers.base import Normalizer


class RawNormalizer(Normalizer):
    def __init__(self, extensions: tuple[str, ...]) -> None:
        self.extensions = extensions

    def applies_to(self, file: FileEntry) -> bool:
        return file.path.endswith(self.extensions)

    def normalized_hash(self, file: FileEntry) -> str:
        return hashlib.sha256(file.data.replace(b"\r\n", b"\n")).hexdigest()
