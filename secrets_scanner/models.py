"""Core data model shared across the scanner.

Kept dependency-free (no regex, git or network imports) so every other module
can import it without creating cycles.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

# Sentinel used as ``commit_hash`` for findings that come from the on-disk
# working tree rather than a specific historical commit.
WORKING_TREE = "WORKING_TREE"


class Severity(Enum):
    """Traffic-light severity of a finding."""

    RED = "red"       # confident and/or verified-live secret in real code
    YELLOW = "yellow"  # suspicious, or a real pattern sitting in test/comment
    GREEN = "green"    # almost certainly harmless (placeholder/example)

    @property
    def rank(self) -> int:
        """Higher rank = more severe (used for sorting)."""
        return {"red": 3, "yellow": 2, "green": 1}[self.value]


class LiveStatus(Enum):
    """Result of an optional live-verification API call."""

    NOT_CHECKED = "not_checked"  # verification disabled or type unsupported
    ACTIVE = "active"            # the API accepted the credential — it works
    REVOKED = "revoked"          # the API rejected it — leaked but now dead
    UNKNOWN = "unknown"          # network error / inconclusive response


def mask_secret(value: str, keep: int = 4) -> str:
    """Return a masked version of ``value`` safe to print in a report.

    Keeps the first and last ``keep`` characters and replaces the middle with
    asterisks (capped so very long values stay readable). Short values are fully
    masked. The report should never contain a usable secret.
    """
    length = len(value)
    if length <= 8:
        return "*" * length
    middle = length - 2 * keep
    stars = "*" * min(middle, 16)
    if middle > 16:
        stars += "~"  # ASCII truncation marker (kept console-safe)
    return f"{value[:keep]}{stars}{value[-keep:]}"


@dataclass
class Finding:
    """A single potential secret discovered by the scanner."""

    secret_type: str
    file_path: str
    line_number: int
    commit_hash: str
    detection_method: str  # "regex" or "entropy"
    masked_secret: str
    entropy: float
    severity: Severity
    score: float
    live_status: LiveStatus = LiveStatus.NOT_CHECKED
    reasons: list[str] = field(default_factory=list)
    occurrences: int = 1  # how many times this exact secret was seen (dedup count)

    def to_dict(self) -> dict:
        """JSON-friendly representation (enums flattened to their values)."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["live_status"] = self.live_status.value
        data["entropy"] = round(self.entropy, 3)
        data["score"] = round(self.score, 3)
        return data


@dataclass
class ScanResult:
    """The full result of scanning a repository."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    commits_scanned: int = 0

    @property
    def counts(self) -> dict[str, int]:
        counts = {"red": 0, "yellow": 0, "green": 0}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered most-severe first, then by score."""
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.score),
            reverse=True,
        )

    def to_dict(self) -> dict:
        return {
            "summary": {
                "files_scanned": self.files_scanned,
                "commits_scanned": self.commits_scanned,
                "total_findings": len(self.findings),
                "by_severity": self.counts,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
