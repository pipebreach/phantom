"""Lockfile audit: scan every pinned package in a lockfile.

Per-package failures never abort the run; they become entries with status
``error`` / ``out_of_scope`` so one unscannable dependency doesn't hide
findings in the rest.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from phantom import core
from phantom.ecosystems.base import Ecosystem
from phantom.errors import OutOfScopeError, PhantomError
from phantom.models import AuditEntry, AuditResult, AuditStatus

_REQUIREMENT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*(?P<version>[^\s;\\#]+)"
)


def audit(lockfile: Path, ecosystem: Ecosystem) -> AuditResult:
    """Scan every pinned package of a lockfile against its declared source."""
    specs, skipped = parse_lockfile(lockfile)
    entries: list[AuditEntry] = []
    for line in skipped:
        entries.append(
            AuditEntry(
                package=line,
                version="?",
                status=AuditStatus.SKIPPED,
                detail="not an exact pin (pkg==version); cannot scan",
            )
        )
    for package, version in specs:
        try:
            result = core.scan(package, version, ecosystem)
        except OutOfScopeError as exc:
            entries.append(
                AuditEntry(package, version, AuditStatus.OUT_OF_SCOPE, detail=str(exc))
            )
        except PhantomError as exc:
            entries.append(
                AuditEntry(package, version, AuditStatus.ERROR, detail=str(exc))
            )
        else:
            entries.append(
                AuditEntry(package, version, AuditStatus.SCANNED, result=result)
            )
    return AuditResult(
        lockfile=str(lockfile), ecosystem=ecosystem.name, entries=entries
    )


def exit_code_for(result: AuditResult) -> int:
    """Findings dominate (1); otherwise per-package errors surface as 2."""
    if any(e.result and e.result.has_blocking_findings for e in result.entries):
        return 1
    if any(e.status == AuditStatus.ERROR for e in result.entries):
        return 2
    return 0


def parse_lockfile(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Extract exact pins from a lockfile.

    Returns (pins, skipped_lines). Format is chosen by filename:
    ``poetry.lock`` is TOML; anything else is requirements.txt syntax.
    """
    if not path.is_file():
        raise PhantomError(f"lockfile not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.name == "poetry.lock":
        return _parse_poetry_lock(text), []
    return _parse_requirements(text)


def _parse_requirements(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    pins: list[tuple[str, str]] = []
    skipped: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _REQUIREMENT_RE.match(line)
        if match:
            pins.append((match.group("name"), match.group("version")))
        else:
            skipped.append(line)
    return pins, skipped


def _parse_poetry_lock(text: str) -> list[tuple[str, str]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PhantomError(f"invalid poetry.lock: {exc}") from exc
    return [
        (pkg["name"], pkg["version"])
        for pkg in data.get("package", [])
        if pkg.get("name") and pkg.get("version")
    ]
