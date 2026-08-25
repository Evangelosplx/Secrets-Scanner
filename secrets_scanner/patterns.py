"""Regex signatures for well-known secret formats.

Each :class:`SecretPattern` carries a ``base_confidence`` in ``[0, 1]`` that
feeds the scoring engine: structured, provider-specific tokens (AWS, GitHub,
Stripe, Google, private keys) are high-confidence, while the generic
``password = "..."`` catch-all is intentionally low-confidence because it is
noisy on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Canonical secret-type names. The live-verification layer keys off these,
# so keep them stable.
AWS_ACCESS_KEY = "AWS Access Key"
GITHUB_TOKEN = "GitHub Token"
STRIPE_SECRET_KEY = "Stripe Secret Key"
GOOGLE_API_KEY = "Google API Key"
PRIVATE_KEY = "Private Key"
GENERIC_SECRET = "Generic Secret"


@dataclass(frozen=True)
class SecretPattern:
    """A named regex signature for one class of secret."""

    name: str
    secret_type: str
    regex: re.Pattern
    base_confidence: float
    high_confidence: bool

    def value_of(self, match: re.Match) -> str:
        """Extract the secret from a match.

        Patterns with a capture group (the generic assignment pattern) expose
        the secret as group 1; all others match the secret directly.
        """
        if self.regex.groups:
            return match.group(1)
        return match.group(0)


# Order matters only for readability; detection tries them all.
PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="aws_access_key",
        secret_type=AWS_ACCESS_KEY,
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        base_confidence=0.90,
        high_confidence=True,
    ),
    SecretPattern(
        name="github_token",
        secret_type=GITHUB_TOKEN,
        # ghp_ (personal), gho_ (oauth), ghu_ (user), ghs_ (server), ghr_ (refresh)
        regex=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        base_confidence=0.92,
        high_confidence=True,
    ),
    SecretPattern(
        name="stripe_secret_key",
        secret_type=STRIPE_SECRET_KEY,
        regex=re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
        base_confidence=0.95,
        high_confidence=True,
    ),
    SecretPattern(
        name="google_api_key",
        secret_type=GOOGLE_API_KEY,
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        base_confidence=0.85,
        high_confidence=True,
    ),
    SecretPattern(
        name="private_key_block",
        secret_type=PRIVATE_KEY,
        regex=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        base_confidence=0.95,
        high_confidence=True,
    ),
    SecretPattern(
        name="generic_secret_assignment",
        secret_type=GENERIC_SECRET,
        # e.g.  password = "s3cr3t"   api_key: 'abcdef123456'
        regex=re.compile(
            r"""(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)"""
            r"""\s*[:=]\s*['"]([^'"\n]{6,})['"]"""
        ),
        base_confidence=0.40,
        high_confidence=False,
    ),
]


def iter_matches(text: str):
    """Yield ``(pattern, match)`` for every pattern hit in ``text``."""
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            yield pattern, match
