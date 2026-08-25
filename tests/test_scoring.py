"""Tests for severity scoring and the end-to-end scan_text pipeline."""

from secrets_scanner.detectors import detect_line
from secrets_scanner.false_positives import analyze
from secrets_scanner.models import LiveStatus, Severity
from secrets_scanner.scanner import scan_text
from secrets_scanner.scoring import score_match

AWS_KEY = "AKIA2E4Q7B8XY1Z9K3PL"


def _score_line(line, file_path="src/app.py", live=LiveStatus.NOT_CHECKED):
    """Score the first detection found on a line."""
    matches = detect_line(line)
    assert matches, f"expected a detection in: {line!r}"
    match = matches[0]
    context = analyze(line, file_path, match.value)
    return score_match(match, context, live)


class TestSeverityMapping:
    def test_real_aws_key_in_source_is_red(self):
        score, severity, _ = _score_line(f'key = "{AWS_KEY}"')
        assert severity is Severity.RED

    def test_aws_key_with_example_keyword_is_downranked(self):
        score, severity, _ = _score_line('key = "AKIAEXAMPLEKEY123456"')
        # 0.90 base - 0.60 keyword = 0.30 -> GREEN
        assert severity is Severity.GREEN

    def test_aws_key_in_test_file_is_yellow(self):
        score, severity, _ = _score_line(
            f'key = "{AWS_KEY}"', file_path="tests/test_config.py"
        )
        # 0.90 base - 0.30 test-file = 0.60 -> YELLOW
        assert severity is Severity.YELLOW

    def test_high_entropy_unknown_string_is_yellow(self):
        line = 'blob = "Zx9Kp2Qm7Rw4Tn8Vb3Lc6Hd1Fj5Gs0Ya"'
        score, severity, _ = _score_line(line)
        assert severity is Severity.YELLOW


class TestLiveVerificationOverridesScore:
    def test_active_credential_forces_red(self):
        # Even in a test file, a verified-live credential is RED.
        score, severity, reasons = _score_line(
            f'key = "{AWS_KEY}"',
            file_path="tests/test_config.py",
            live=LiveStatus.ACTIVE,
        )
        assert severity is Severity.RED
        assert score == 1.0

    def test_revoked_credential_capped_to_yellow(self):
        score, severity, _ = _score_line(
            f'key = "{AWS_KEY}"', live=LiveStatus.REVOKED
        )
        assert severity is Severity.YELLOW
        assert score <= 0.5


class TestScanTextPipeline:
    def test_scan_text_produces_masked_finding(self):
        findings = scan_text(f'aws_key = "{AWS_KEY}"', "src/config.py")
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity is Severity.RED
        assert AWS_KEY not in finding.masked_secret  # never leak the raw secret
        assert finding.masked_secret.startswith("AKIA")
        assert finding.reasons

    def test_scan_text_reports_line_numbers(self):
        text = "clean = 1\n" + f'token = "{AWS_KEY}"\n'
        findings = scan_text(text, "src/config.py")
        assert findings[0].line_number == 2
