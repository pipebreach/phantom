"""Execution-vector analysis for phantom files. Detects capabilities
(env-read, network, process, dynamic-code), not known-bad patterns.

Python is analyzed via AST walk; JavaScript via capability regexes (an AST
parser would require a heavy dependency). Severity: env-read + network ->
critical (exfiltration shape); any single vector -> high; no vector -> medium.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from phantom.models import FileEntry, Severity

_NETWORK_MODULES = {
    "socket",
    "requests",
    "httpx",
    "urllib",
    "http",
    "aiohttp",
    "ftplib",
    "smtplib",
}
_PROCESS_MODULES = {"subprocess"}
_DYNAMIC_BUILTINS = {"exec", "eval", "compile"}
_OS_PROCESS_ATTRS = {"system", "popen", "spawnl", "spawnv", "execv", "execl"}
_OS_ENV_ATTRS = {"environ", "getenv", "environb"}


@dataclass
class RiskAssessment:
    severity: Severity
    vectors: list[str]
    detail: str


_JS_VECTOR_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"""(?:require\(\s*|from\s+|import\s+.*?)['"](?:node:)?child_process['"]"""),
        "process:child_process",
    ),
    (
        re.compile(r"""(?:require\(\s*|from\s+|import\s+.*?)['"](?:node:)?(?:https?|net|dgram|tls|dns)['"]"""),
        "network:node-net-module",
    ),
    (re.compile(r"\bfetch\s*\("), "network:fetch"),
    (re.compile(r"\bnew\s+XMLHttpRequest\b"), "network:XMLHttpRequest"),
    (re.compile(r"\bnew\s+WebSocket\b"), "network:WebSocket"),
    (re.compile(r"\bprocess\.env\b"), "env-read:process.env"),
    (re.compile(r"\beval\s*\("), "dynamic-code:eval"),
    (re.compile(r"\bnew\s+Function\s*\("), "dynamic-code:new-Function"),
)


def assess(file: FileEntry) -> RiskAssessment:
    """Grade a phantom file by its execution vectors."""
    if file.path.endswith((".js", ".mjs", ".cjs")):
        return _assess_js(file)
    return _assess_python(file)


def _assess_js(file: FileEntry) -> RiskAssessment:
    text = file.data.decode("utf-8", errors="replace")
    vectors: list[str] = []
    for pattern, vector in _JS_VECTOR_PATTERNS:
        if vector not in vectors and pattern.search(text):
            vectors.append(vector)
    severity = _classify(vectors)
    detail = (
        "execution vectors detected: " + ", ".join(vectors)
        if vectors
        else "no obvious execution or exfiltration vector detected"
    )
    if severity == Severity.CRITICAL:
        detail = "reads local data AND has network egress (exfiltration shape); " + detail
    return RiskAssessment(severity=severity, vectors=vectors, detail=detail)


def _assess_python(file: FileEntry) -> RiskAssessment:
    text = file.data.decode("utf-8", errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return RiskAssessment(
            severity=Severity.MEDIUM,
            vectors=[],
            detail="file could not be parsed as Python; vectors unknown",
        )

    vectors: list[str] = []

    def add(vector: str) -> None:
        if vector not in vectors:
            vectors.append(vector)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _NETWORK_MODULES:
                    add(f"network:{alias.name}")
                elif root in _PROCESS_MODULES:
                    add(f"process:{alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in _NETWORK_MODULES:
                add(f"network:{node.module}")
            elif root in _PROCESS_MODULES:
                add(f"process:{node.module}")
            elif root == "os":
                for alias in node.names:
                    if alias.name in _OS_ENV_ATTRS:
                        add(f"env-read:os.{alias.name}")
                    elif alias.name in _OS_PROCESS_ATTRS:
                        add(f"process:os.{alias.name}")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os":
                if node.attr in _OS_ENV_ATTRS:
                    add(f"env-read:os.{node.attr}")
                elif node.attr in _OS_PROCESS_ATTRS:
                    add(f"process:os.{node.attr}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _DYNAMIC_BUILTINS:
                add(f"dynamic-code:{node.func.id}")

    severity = _classify(vectors)
    if not vectors:
        detail = "no obvious execution or exfiltration vector detected"
    else:
        detail = "execution vectors detected: " + ", ".join(vectors)
        if severity == Severity.CRITICAL:
            detail = (
                "reads local data AND has network egress (exfiltration shape); "
                + detail
            )
    return RiskAssessment(severity=severity, vectors=vectors, detail=detail)


def _classify(vectors: list[str]) -> Severity:
    has_read = any(v.startswith("env-read:") for v in vectors)
    has_network = any(v.startswith("network:") for v in vectors)
    if has_read and has_network:
        return Severity.CRITICAL
    if vectors:
        return Severity.HIGH
    return Severity.MEDIUM
