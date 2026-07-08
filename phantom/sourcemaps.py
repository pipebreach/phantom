"""Source-map assisted verification of built JavaScript.

A minified or bundled ``.js`` file often ships a source map (inline as a
``//# sourceMappingURL=data:...`` comment, or an external ``.map`` file) that
carries the original sources it was built from in ``sourcesContent``. When a
built file diverges from the repository by raw comparison, phantom checks
those embedded originals against the declared source: if they are all present
in the repo, the built output is accounted for by verified source; if the map
references sources absent from the repo, that is a provenance signal.

Only ``sourcesContent`` is used (plain JSON); the VLQ ``mappings`` are not
decoded, so no position-level localization is done yet.
"""

from __future__ import annotations

import base64
import json
import posixpath
import re
import urllib.parse

from phantom.models import FileEntry

_MAPPING_URL_RE = re.compile(rb"//[#@]\s*sourceMappingURL=(\S+)")


def find_source_map(js_file: FileEntry, artifact_by_path: dict[str, FileEntry]) -> dict | None:
    """Locate and parse the source map for a JS file, inline or external."""
    match = _MAPPING_URL_RE.search(js_file.data)
    if not match:
        return None
    url = match.group(1).decode("ascii", "replace")
    if url.startswith("data:"):
        return _parse(_decode_data_uri(url))
    map_path = posixpath.normpath(
        posixpath.join(posixpath.dirname(js_file.path), url)
    )
    map_file = artifact_by_path.get(map_path)
    return _parse(map_file.data) if map_file is not None else None


def embedded_originals(source_map: dict) -> list[str]:
    """The inlined original source contents, if the map carries them."""
    contents = source_map.get("sourcesContent")
    if not isinstance(contents, list):
        return []
    return [entry for entry in contents if isinstance(entry, str)]


def _decode_data_uri(url: str) -> bytes | None:
    payload = url.split(",", 1)
    if len(payload) != 2:
        return None
    meta, data = payload
    if meta.endswith(";base64"):
        try:
            return base64.b64decode(data)
        except (ValueError, base64.binascii.Error):
            return None
    return urllib.parse.unquote(data).encode("utf-8", "replace")


def _parse(raw: bytes | None) -> dict | None:
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None
