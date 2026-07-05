from __future__ import annotations

from phantom.models import FileEntry
from phantom.normalizers.python_ast import PythonASTNormalizer


def test_comments_and_whitespace_do_not_change_hash():
    normalizer = PythonASTNormalizer()
    a = FileEntry("a.py", b"# a comment\ndef f(x):\n    return x + 1\n")
    b = FileEntry("b.py", b"def f(x):\n\n\n    return x  +  1  # inline\n")
    assert normalizer.normalized_hash(a) == normalizer.normalized_hash(b)


def test_semantic_change_changes_hash():
    normalizer = PythonASTNormalizer()
    a = FileEntry("a.py", b"def f(x):\n    return x + 1\n")
    b = FileEntry("b.py", b"def f(x):\n    return x + 2\n")
    assert normalizer.normalized_hash(a) != normalizer.normalized_hash(b)


def test_unparseable_falls_back_to_raw_hash():
    normalizer = PythonASTNormalizer()
    broken = FileEntry("x.py", b"def broken(:\n")
    assert normalizer.normalized_hash(broken) == normalizer.normalized_hash(broken)
    other = FileEntry("y.py", b"def broken(::\n")
    assert normalizer.normalized_hash(broken) != normalizer.normalized_hash(other)


def test_applies_only_to_python_files():
    normalizer = PythonASTNormalizer()
    assert normalizer.applies_to(FileEntry("pkg/mod.py", b""))
    assert not normalizer.applies_to(FileEntry("data.json", b""))
    assert not normalizer.applies_to(FileEntry("hook.pth", b""))
