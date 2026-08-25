"""Orchestration: turn raw text into fully-scored :class:`Finding` objects.

Ties together detection (:mod:`detectors`), context analysis
(:mod:`false_positives`), optional live verification and scoring
(:mod:`scoring`). This layer is pure with respect to git/network: the only I/O
is the optional ``verifier`` callback the caller injects.
"""

from __future__ import annotations

from typing import Callable, Optional

from .detectors import detect_line
from .entropy import DEFAULT_BASE64_THRESHOLD, DEFAULT_HEX_THRESHOLD, DEFAULT_MIN_LENGTH
from .false_positives import analyze
from .models import Finding, LiveStatus, WORKING_TREE, mask_secret
from .scoring import score_match

# A verifier takes (secret_type, value) and returns a LiveStatus.
Verifier = Callable[[str, str], LiveStatus]


def scan_lines(
    lines,
    file_path: str,
    commit_hash: str = WORKING_TREE,
    *,
    verifier: Optional[Verifier] = None,
    min_length: int = DEFAULT_MIN_LENGTH,
    base64_threshold: float = DEFAULT_BASE64_THRESHOLD,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
) -> list[Finding]:
    """Scan an iterable of text lines and return scored findings."""
    findings: list[Finding] = []

    for line_number, line in enumerate(lines, start=1):
        for match in detect_line(
            line,
            min_length=min_length,
            base64_threshold=base64_threshold,
            hex_threshold=hex_threshold,
        ):
            context = analyze(line, file_path, match.value)

            live_status = LiveStatus.NOT_CHECKED
            if verifier is not None:
                live_status = verifier(match.secret_type, match.value)

            score, severity, reasons = score_match(match, context, live_status)

            findings.append(
                Finding(
                    secret_type=match.secret_type,
                    file_path=file_path,
                    line_number=line_number,
                    commit_hash=commit_hash,
                    detection_method=match.method,
                    masked_secret=mask_secret(match.value),
                    entropy=match.entropy,
                    severity=severity,
                    score=score,
                    live_status=live_status,
                    reasons=reasons,
                )
            )

    return findings


def scan_text(text: str, file_path: str, commit_hash: str = WORKING_TREE, **kwargs) -> list[Finding]:
    """Convenience wrapper: split ``text`` into lines and scan them."""
    return scan_lines(text.splitlines(), file_path, commit_hash, **kwargs)
