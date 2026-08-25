"""Shannon-entropy analysis for catching secrets with no known signature.

The idea: real cryptographic keys and tokens are close to random, so they pack
a lot of information into few characters — i.e. they have *high Shannon entropy*.
A hand-written English identifier like ``getUserProfile`` is very predictable and
scores low. By scanning each line for long, high-entropy runs of base64/hex-like
characters, we can flag suspicious strings even when none of our regex signatures
recognise them.
"""

from __future__ import annotations

import math
from collections import Counter

# Character sets used to carve candidate tokens out of a line.
# ``=`` is deliberately excluded: in base64 it is only trailing padding, and
# treating it as part of a token would merge assignments like ``token=abc...``
# into one run and dilute the entropy of the real secret.
BASE64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_"
)
HEX_CHARS = frozenset("abcdefABCDEF0123456789")

# Default detection thresholds (bits per character).
# Base64 has a larger alphabet so genuine random base64 sits near ~5-6 bits;
# hex is limited to 16 symbols so its ceiling is 4 bits. Thresholds are chosen
# below those ceilings but above what ordinary code/words produce.
DEFAULT_BASE64_THRESHOLD = 4.5
DEFAULT_HEX_THRESHOLD = 3.0

# Minimum length for a run to even be considered a candidate secret.
DEFAULT_MIN_LENGTH = 20


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of ``data`` in bits per character.

    Entropy is ``-sum(p * log2(p))`` over the probability ``p`` of each distinct
    character. Returns ``0.0`` for empty input. The value is independent of the
    string's length — it measures unpredictability per character, so ``"aaaa"``
    scores ``0`` while a random base64 blob scores high.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _tokenize(text: str, charset: frozenset[str], min_length: int) -> list[str]:
    """Split ``text`` into maximal runs made only of ``charset`` characters.

    Only runs of at least ``min_length`` characters are returned.
    """
    tokens: list[str] = []
    current: list[str] = []
    for char in text:
        if char in charset:
            current.append(char)
        else:
            if len(current) >= min_length:
                tokens.append("".join(current))
            current = []
    if len(current) >= min_length:
        tokens.append("".join(current))
    return tokens


def find_high_entropy_strings(
    text: str,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    base64_threshold: float = DEFAULT_BASE64_THRESHOLD,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
) -> list[tuple[str, float]]:
    """Find long, high-entropy substrings that look like secrets.

    Scans ``text`` for base64-like and hex-like runs of at least ``min_length``
    characters, computes each run's Shannon entropy, and returns those whose
    entropy exceeds the relevant threshold.

    Returns a list of ``(token, entropy)`` tuples, de-duplicated while preserving
    first-seen order. Hex runs are checked against ``hex_threshold`` and all other
    base64-like runs against ``base64_threshold``.
    """
    results: list[tuple[str, float]] = []
    seen: set[str] = set()

    for token in _tokenize(text, BASE64_CHARS, min_length):
        if token in seen:
            continue

        entropy = shannon_entropy(token)
        is_hex = all(char in HEX_CHARS for char in token)
        threshold = hex_threshold if is_hex else base64_threshold

        if entropy >= threshold:
            seen.add(token)
            results.append((token, entropy))

    return results
