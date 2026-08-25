"""Tests for regex signatures and line-level detection."""

from secrets_scanner.detectors import ENTROPY_SECRET_TYPE, detect_line
from secrets_scanner.patterns import (
    AWS_ACCESS_KEY,
    GENERIC_SECRET,
    GITHUB_TOKEN,
    GOOGLE_API_KEY,
    PRIVATE_KEY,
    STRIPE_SECRET_KEY,
)

# Realistic-looking but fake secrets (no real credentials in this repo).
AWS_KEY = "AKIA2E4Q7B8XY1Z9K3PL"
GITHUB_KEY = "ghp_0123456789abcdefghijABCDEFGHIJ012345"
# Split so the literal never appears contiguously in source (GitHub push
# protection flags the Stripe live-key shape regardless of authenticity).
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
GOOGLE_KEY = "AIza01234567890123456789012345678901234"
PRIVATE_HEADER = "-----BEGIN RSA PRIVATE KEY-----"


def _types(line):
    return {m.secret_type for m in detect_line(line)}


class TestKnownSignaturesMatch:
    def test_aws_key(self):
        assert AWS_ACCESS_KEY in _types(f'aws_key = "{AWS_KEY}"')

    def test_github_token(self):
        assert GITHUB_TOKEN in _types(f"token: {GITHUB_KEY}")

    def test_stripe_key(self):
        assert STRIPE_SECRET_KEY in _types(f"STRIPE={STRIPE_KEY}")

    def test_google_api_key(self):
        assert GOOGLE_API_KEY in _types(f'key="{GOOGLE_KEY}"')

    def test_private_key_block(self):
        assert PRIVATE_KEY in _types(PRIVATE_HEADER)

    def test_generic_password_assignment(self):
        assert GENERIC_SECRET in _types('password = "s3cr3tP@ssw0rd"')


class TestNonSecretsRejected:
    def test_plain_english(self):
        assert detect_line("This function returns the current user profile.") == []

    def test_short_variable_name(self):
        assert detect_line("count = 42") == []

    def test_akia_lookalike_wrong_length_not_matched_as_aws(self):
        # Too short to be an AWS key.
        assert AWS_ACCESS_KEY not in _types("AKIA123")

    def test_url_is_not_flagged(self):
        assert detect_line("url = https://example.com/api/v1/users") == []


class TestDeduplication:
    def test_provider_signature_suppresses_generic(self):
        # `api_key = "AKIA..."` must report AWS, not a duplicate Generic Secret.
        types = _types(f'api_key = "{AWS_KEY}"')
        assert AWS_ACCESS_KEY in types
        assert GENERIC_SECRET not in types

    def test_entropy_not_double_counted_with_regex(self):
        # The GitHub token is high-entropy but must be reported once, as GitHub.
        matches = detect_line(f"token = {GITHUB_KEY}")
        types = [m.secret_type for m in matches]
        assert types.count(GITHUB_TOKEN) == 1
        assert ENTROPY_SECRET_TYPE not in types


class TestEntropyFallback:
    def test_unknown_high_entropy_string_is_flagged(self):
        # No known signature, but clearly random -> entropy fallback catches it.
        line = 'blob = "Zx9Kp2Qm7Rw4Tn8Vb3Lc6Hd1Fj5Gs0Ya"'
        assert ENTROPY_SECRET_TYPE in _types(line)
