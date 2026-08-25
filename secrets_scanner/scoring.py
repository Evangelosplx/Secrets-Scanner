"""Severity scoring: combine pattern confidence, entropy, context and live status.

The output is a score in ``[0, 1]`` mapped to a :class:`Severity` traffic light.
Everything additive/subtractive is deliberately simple and explainable — each
finding records the human-readable ``reasons`` that produced its score.
"""

from __future__ import annotations

from .detectors import RawMatch
from .false_positives import ContextResult
from .models import LiveStatus, Severity

# Score thresholds.
RED_THRESHOLD = 0.70
YELLOW_THRESHOLD = 0.40

# Baseline suspicion for an unknown high-entropy string (no known signature).
ENTROPY_BASE_CONFIDENCE = 0.45

# Context penalties (subtracted from the score).
KEYWORD_PENALTY = 0.60      # "example", "test", ... — strong signal it's fake
TEST_FILE_PENALTY = 0.30    # located in a test/example/doc file
COMMENT_PENALTY = 0.15      # located inside a comment


def severity_for_score(score: float) -> Severity:
    if score >= RED_THRESHOLD:
        return Severity.RED
    if score >= YELLOW_THRESHOLD:
        return Severity.YELLOW
    return Severity.GREEN


def _entropy_boost(match: RawMatch) -> float:
    """Small extra confidence when a regex-matched value is itself very random."""
    if match.method == "entropy":
        return 0.0  # baseline already reflects its entropy
    return min(0.08, max(0.0, (match.entropy - 4.0) * 0.04))


def score_match(
    match: RawMatch,
    context: ContextResult,
    live_status: LiveStatus = LiveStatus.NOT_CHECKED,
) -> tuple[float, Severity, list[str]]:
    """Return ``(score, severity, reasons)`` for a candidate secret."""
    reasons: list[str] = []

    if match.method == "regex":
        score = match.base_confidence
        reasons.append(f"matched {match.secret_type} signature")
    else:
        score = ENTROPY_BASE_CONFIDENCE
        reasons.append(f"high Shannon entropy ({match.entropy:.2f} bits/char)")

    score += _entropy_boost(match)

    # Context down-ranking (recorded so nothing is hidden, only de-prioritised).
    if context.matched_keywords:
        score -= KEYWORD_PENALTY
        reasons.append("down-ranked: " + context.reasons[0])
    if context.in_test_file:
        score -= TEST_FILE_PENALTY
        reasons.append("down-ranked: in a test/example/doc file")
    if context.in_comment:
        score -= COMMENT_PENALTY
        reasons.append("down-ranked: inside a comment")

    # Live verification is authoritative when it produced a definitive answer.
    if live_status == LiveStatus.ACTIVE:
        score = 1.0
        reasons.append("LIVE: credential is currently ACTIVE")
    elif live_status == LiveStatus.REVOKED:
        score = min(score, 0.50)
        reasons.append("verified revoked/inactive (leaked but no longer usable)")
    elif live_status == LiveStatus.UNKNOWN:
        reasons.append("live check inconclusive (network/other)")

    score = max(0.0, min(1.0, score))
    return score, severity_for_score(score), reasons
