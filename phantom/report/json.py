"""JSON output: the versioned public schema defined by ``ScanResult.to_dict()``."""

from __future__ import annotations

import json

from phantom.models import AuditResult, ScanResult


def render(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_audit(result: AuditResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
