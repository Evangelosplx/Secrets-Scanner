"""Tests for the Shannon-entropy analysis module."""

import math

from secrets_scanner.entropy import (
    DEFAULT_BASE64_THRESHOLD,
    find_high_entropy_strings,
    shannon_entropy,
)


class TestShannonEntropy:
    def test_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_repeated_character_is_zero(self):
        # No uncertainty: every character is identical.
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_uniform_two_symbols_is_one_bit(self):
        # A perfectly balanced binary string carries exactly 1 bit/char.
        assert shannon_entropy("0101010101") == 1.0

    def test_uniform_four_symbols_is_two_bits(self):
        assert math.isclose(shannon_entropy("ABCDABCDABCD"), 2.0)

    def test_random_key_has_higher_entropy_than_english(self):
        random_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
        english = "getUserProfileByAccountIdentifier"
        assert shannon_entropy(random_key) > shannon_entropy(english)

    def test_real_looking_base64_secret_exceeds_threshold(self):
        secret = "dGhpcyBpcyBhIHZlcnkgc2VjcmV0IHRva2VuIHZhbHVl12345"
        assert shannon_entropy(secret) > DEFAULT_BASE64_THRESHOLD


class TestFindHighEntropyStrings:
    def test_detects_embedded_high_entropy_token(self):
        line = 'api_secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY42"'
        results = find_high_entropy_strings(line)
        assert len(results) == 1
        token, entropy = results[0]
        assert token == "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY42"
        assert entropy > DEFAULT_BASE64_THRESHOLD

    def test_ignores_short_tokens(self):
        # "shortvalue" is below the 20-char minimum length.
        assert find_high_entropy_strings('key = "shortvalue"') == []

    def test_ignores_low_entropy_long_runs(self):
        # Long but extremely repetitive → low entropy, not flagged.
        assert find_high_entropy_strings("x" * 60) == []

    def test_ignores_ordinary_english_prose(self):
        line = "This is a perfectly ordinary sentence describing the function."
        assert find_high_entropy_strings(line) == []

    def test_deduplicates_repeated_tokens(self):
        token = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY42"
        line = f"{token} and again {token}"
        results = find_high_entropy_strings(line)
        assert len(results) == 1

    def test_long_hex_string_is_detected(self):
        # 40-char hex digest (e.g. a leaked SHA-ish token) exceeds hex threshold.
        line = "token=deadbeefcafebabe0123456789abcdef01234567"
        results = find_high_entropy_strings(line)
        assert len(results) == 1
