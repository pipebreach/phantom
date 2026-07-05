"""Data models. ``ScanResult.to_dict()`` is the versioned public JSON
contract; breaking changes require bumping ``SCHEMA_VERSION``."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

SCHEMA_VERSION = "1.0"


class Severity(str, Enum):
    """Ordered: critical > high > medium > low."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 3, "high": 2, "medium": 1, "low": 0}[self.value]


class Confidence(str, Enum):
    """Likelihood that a finding is real divergence rather than a legitimate
    build transformation."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingType(str, Enum):
    PHANTOM_FILE = "phantom_file"
    SUSPICIOUS_PTH = "suspicious_pth"
    NO_SOURCE_DECLARED = "no_source_declared"
    SOURCE_REF_NOT_FOUND = "source_ref_not_found"


class SourceStatus(str, Enum):
    """Outcome of source resolution for a scan."""

    RESOLVED = "resolved"
    NO_SOURCE_DECLARED = "no_source_declared"
    REF_NOT_FOUND = "ref_not_found"


@dataclass(frozen=True)
class FileEntry:
    """A file as a path relative to its tree root plus raw bytes."""

    path: str
    data: bytes


@dataclass
class Artifact:
    """Unpacked distributed artifact plus its registry metadata."""

    package: str
    version: str
    filename: str
    files: list[FileEntry]
    metadata: dict


@dataclass
class SourceTree:
    """Source tree at the ref corresponding to the published version."""

    repo_url: str
    ref: str
    files: list[FileEntry]


@dataclass
class NoSource:
    """Source resolution failure: either no repo declared or no matching ref."""

    finding_type: FindingType
    detail: str
    repo_url: str | None = None


@dataclass
class Finding:
    """A detected divergence or risk signal. ``execution_vectors`` holds
    strings such as ``"env-read:os.environ"`` produced by ``phantom.risk``."""

    type: FindingType
    path: str | None
    severity: Severity
    confidence: Confidence
    reason: str
    execution_vectors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "path": self.path,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "reason": self.reason,
            "execution_vectors": list(self.execution_vectors),
        }


@dataclass
class ScanResult:
    """Complete outcome of scanning one package version."""

    package: str
    version: str
    ecosystem: str
    source_status: SourceStatus
    source_repo: str | None
    source_ref: str | None
    findings: list[Finding]
    files_scanned: int
    schema_version: str = SCHEMA_VERSION

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict:
        highest = self.highest_severity
        return {
            "schema_version": self.schema_version,
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "source_status": self.source_status.value,
            "source_repo": self.source_repo,
            "source_ref": self.source_ref,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "files_scanned": self.files_scanned,
                "total_findings": len(self.findings),
                "phantom_files": sum(
                    1 for f in self.findings if f.type == FindingType.PHANTOM_FILE
                ),
                "highest_severity": highest.value if highest else None,
            },
        }
