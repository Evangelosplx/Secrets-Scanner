"""Run regex signatures and entropy analysis over a single line of text.

Produces :class:`RawMatch` objects — un-scored candidate secrets. Scoring,
context analysis and masking happen later, in the scanner/scoring layers.
"""

from __future__ import annotations

from dataclasses import dataclass

from .entropy import (
    DEFAULT_BASE64_THRESHOLD,
    DEFAULT_HEX_THRESHOLD,
    DEFAULT_MIN_LENGTH,
    find_high_entropy_strings,
    shannon_entropy,
)
from .patterns import PATTERNS

ENTROPY_SECRET_TYPE = "High-entropy string"


@dataclass
class RawMatch:
    """A candidate secret before scoring."""

    secret_type: str
    method: str  # "regex" or "entropy"
    value: str
    base_confidence: float
    high_confidence: bool
    entropy: float


def detect_line(
    line: str,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    base64_threshold: float = DEFAULT_BASE64_THRESHOLD,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
) -> list[RawMatch]:
    """Detect all candidate secrets in one line.

    Runs every regex signature first, then entropy analysis for anything the
    signatures missed. Two forms of de-duplication keep the output clean:

    * the noisy generic ``password = "..."`` pattern is suppressed when its
      value was already claimed by a high-confidence provider signature;
    * an entropy hit is dropped when it is contained in (or contains) a value
      already reported by a regex signature.
    """
    matches: list[RawMatch] = []
    regex_values: list[str] = []
    high_confidence_values: set[str] = set()

    for pattern in PATTERNS:
        for match in pattern.regex.finditer(line):
            value = pattern.value_of(match)
            if not value:
                continue

            # Skip the generic catch-all if a provider signature already owns it.
            if not pattern.high_confidence and value in high_confidence_values:
                continue

            matches.append(
                RawMatch(
                    secret_type=pattern.secret_type,
                    method="regex",
                    value=value,
                    base_confidence=pattern.base_confidence,
                    high_confidence=pattern.high_confidence,
                    entropy=shannon_entropy(value),
                )
            )
            regex_values.append(value)
            if pattern.high_confidence:
                high_confidence_values.add(value)

    for token, entropy in find_high_entropy_strings(
        line,
        min_length=min_length,
        base64_threshold=base64_threshold,
        hex_threshold=hex_threshold,
    ):
        if any(token in value or value in token for value in regex_values):
            continue
        matches.append(
            RawMatch(
                secret_type=ENTROPY_SECRET_TYPE,
                method="entropy",
                value=token,
                base_confidence=0.0,
                high_confidence=False,
                entropy=entropy,
            )
        )

    return matches
