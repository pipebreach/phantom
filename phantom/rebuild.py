"""Assisted rebuild: build a wheel from the published sdist and diff it against
the published wheel, catching a wheel tampered post-build while the sdist stayed
clean (the LiteLLM shape).

This EXECUTES the package's build (setup.py / build backend): untrusted,
attacker-influenced code. It is opt-in and must only be run in a disposable
environment (a fresh Codespace, a throwaway CI runner). When possible the build
subprocess is placed in a network namespace with no interfaces (``unshare
--net``) so a malicious build cannot exfiltrate; if that is unavailable phantom
reports that egress was NOT denied so the caller can judge the risk.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from phantom.models import FileEntry


@dataclass
class RebuildResult:
    files: list[FileEntry] | None
    network_denied: bool
    detail: str


def network_deny_prefix() -> list[str] | None:
    """A command prefix that runs its argument with no network, or None.

    Uses ``unshare`` to enter a fresh network namespace (no interfaces means no
    egress). Requires Linux with user-namespace support; probed once.
    """
    if not shutil.which("unshare"):
        return None
    probe = subprocess.run(
        ["unshare", "--map-root-user", "--net", "true"],
        capture_output=True,
    )
    if probe.returncode == 0:
        return ["unshare", "--map-root-user", "--net", "--"]
    return None


def rebuild_wheel_from_sdist(sdist: bytes, timeout: float = 300.0) -> RebuildResult:
    """Extract an sdist, build a wheel from it, and return the wheel's files."""
    prefix = network_deny_prefix()
    network_denied = prefix is not None
    with tempfile.TemporaryDirectory(prefix="phantom-rebuild-") as tmp:
        root = Path(tmp)
        src, out = root / "src", root / "out"
        src.mkdir()
        out.mkdir()
        try:
            _safe_extract(sdist, src)
        except (tarfile.TarError, ValueError) as exc:
            return RebuildResult(None, network_denied, f"invalid sdist: {exc}")

        package_dir = _single_child_dir(src)
        if package_dir is None:
            return RebuildResult(None, network_denied, "sdist has no source root")

        command = [
            *(prefix or []),
            sys.executable, "-m", "build", "--wheel", "--no-isolation",
            "--outdir", str(out), str(package_dir),
        ]
        try:
            proc = subprocess.run(
                command, capture_output=True, timeout=timeout, cwd=str(package_dir)
            )
        except subprocess.TimeoutExpired:
            return RebuildResult(None, network_denied, f"build timed out ({timeout}s)")
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-5:]
            return RebuildResult(
                None, network_denied, "build failed: " + " / ".join(tail)
            )

        wheels = list(out.glob("*.whl"))
        if not wheels:
            return RebuildResult(None, network_denied, "build produced no wheel")
        return RebuildResult(_unpack_wheel(wheels[0]), network_denied, "ok")


def _safe_extract(sdist: bytes, dest: Path) -> None:
    """Extract a gzipped tar to ``dest``, rejecting path traversal.

    ``tarfile.extractall`` on untrusted input can escape the target directory;
    each member is validated to resolve inside ``dest`` before extraction.
    """
    dest = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(sdist), mode="r:gz") as tar:
        for member in tar.getmembers():
            target = (dest / member.name).resolve()
            if not target.is_relative_to(dest):
                raise ValueError(f"unsafe path in sdist: {member.name}")
            if member.issym() or member.islnk():
                raise ValueError(f"link in sdist not allowed: {member.name}")
        try:
            tar.extractall(dest, filter="data")  # defense in depth (3.12+)
        except TypeError:
            tar.extractall(dest)


def _single_child_dir(path: Path) -> Path | None:
    children = [child for child in path.iterdir() if child.is_dir()]
    if len(children) == 1:
        return children[0]
    return path if any(path.iterdir()) else None


def _unpack_wheel(wheel_path: Path) -> list[FileEntry]:
    entries = []
    with zipfile.ZipFile(wheel_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            entries.append(FileEntry(path=info.filename, data=archive.read(info)))
    return entries
