"""Intra-file AST diff: localizes code injected into a file that does exist
in the source (phantom spans).

Comparison is at top-level statement granularity: each statement of the
artifact file is hashed (``ast.dump``) and looked up in the set of source
statements. A miss is a span: "modified" when a same-named function/class
exists in the source, "injected" otherwise. Deletions and reordering produce
no spans; the differ reports that case separately.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from phantom.models import FileEntry


@dataclass
class Span:
    start_line: int
    end_line: int
    kind: str  # "injected" | "modified"
    name: str | None
    segment: str


def find_spans(artifact_file: FileEntry, source_file: FileEntry) -> list[Span] | None:
    """Return artifact statements absent from the source file.

    Returns ``None`` when either side is unparseable (span analysis does not
    apply); an empty list means the divergence is only deletions/reordering.
    """
    artifact_text = artifact_file.data.decode("utf-8", errors="replace")
    source_text = source_file.data.decode("utf-8", errors="replace")
    try:
        artifact_tree = ast.parse(artifact_text)
        source_tree = ast.parse(source_text)
    except SyntaxError:
        return None

    source_hashes = {ast.dump(node) for node in source_tree.body}
    source_names = {
        node.name
        for node in source_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }

    spans: list[Span] = []
    for node in artifact_tree.body:
        if ast.dump(node) in source_hashes:
            continue
        name = getattr(node, "name", None)
        spans.append(
            Span(
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                kind="modified" if name and name in source_names else "injected",
                name=name,
                segment=ast.get_source_segment(artifact_text, node) or "",
            )
        )
    return spans


def find_source_counterpart(
    file: FileEntry, source_files: list[FileEntry]
) -> tuple[FileEntry, str] | None:
    """Locate the source file a diverging artifact file corresponds to.

    Prefers an exact relative-path suffix match (robust to src-layout);
    falls back to a unique basename match. Returns the file plus how it was
    matched (``"path"`` | ``"basename"``) for confidence grading.
    """
    by_path = [
        s
        for s in source_files
        if s.path == file.path or s.path.endswith("/" + file.path)
    ]
    if by_path:
        return min(by_path, key=lambda s: len(s.path)), "path"
    basename = file.path.rsplit("/", 1)[-1]
    by_basename = [s for s in source_files if s.path.rsplit("/", 1)[-1] == basename]
    if len(by_basename) == 1:
        return by_basename[0], "basename"
    return None
