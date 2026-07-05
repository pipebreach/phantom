"""Disk cache keyed by URL digest and the single HTTP helper. A cached
scan of the same ``pkg==version`` is deterministic and works offline."""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from pathlib import Path

from phantom.errors import FetchError, NotFoundError

USER_AGENT = "phantom/0.1 (+https://github.com/pipebreach/phantom)"


def default_cache_dir() -> Path:
    return Path.home() / ".cache" / "phantom"


class DiskCache:
    """Blob store keyed by the SHA-256 of an arbitrary string key."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.root / digest[:2] / digest

    def get(self, key: str) -> bytes | None:
        path = self._path(key)
        if path.is_file():
            return path.read_bytes()
        return None

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)


def http_get(url: str, cache: DiskCache | None = None, timeout: float = 60.0) -> bytes:
    """GET a URL through the cache. Raises ``NotFoundError`` on 404,
    ``FetchError`` on any other failure."""
    if cache is not None:
        cached = cache.get(url)
        if cached is not None:
            return cached
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotFoundError(f"404 Not Found: {url}") from exc
        raise FetchError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"network error fetching {url}: {exc.reason}") from exc
    if cache is not None:
        cache.put(url, data)
    return data
