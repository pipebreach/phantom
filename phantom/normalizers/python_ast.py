"""AST-normalized hashing for Python sources: ``ast.dump`` erases comments,
whitespace and formatting. Docstrings are AST constants and are kept."""

from __future__ import annotations

import ast
import hashlib

from phantom.models import FileEntry
from phantom.normalizers.base import Normalizer


class PythonASTNormalizer(Normalizer):
    def applies_to(self, file: FileEntry) -> bool:
        return file.path.endswith(".py")

    def normalized_hash(self, file: FileEntry) -> str:
        text = file.data.decode("utf-8", errors="replace")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            # Symmetric fallback: unparseable files hash raw on both sides.
            return hashlib.sha256(file.data).hexdigest()
        return hashlib.sha256(ast.dump(tree).encode("utf-8")).hexdigest()
