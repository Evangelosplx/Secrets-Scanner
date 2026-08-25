"""Tests for context-based false-positive analysis."""

from secrets_scanner.false_positives import (
    analyze,
    is_in_comment,
    is_test_or_doc_file,
)


class TestKeywordDetection:
    def test_example_keyword_in_value(self):
        result = analyze('key = "AKIAEXAMPLEKEY1234"', "config.py", "AKIAEXAMPLEKEY1234")
        assert "example" in result.matched_keywords

    def test_placeholder_keyword_in_variable_name(self):
        result = analyze('dummy_token = "abcdef123456"', "app.py", "abcdef123456")
        assert "dummy" in result.matched_keywords

    def test_no_keyword_for_real_looking_secret(self):
        result = analyze('key = "AKIA2E4Q7B8XY1Z9K3PL"', "app.py", "AKIA2E4Q7B8XY1Z9K3PL")
        assert result.matched_keywords == []


class TestCommentDetection:
    def test_hash_comment(self):
        assert is_in_comment("# key = SECRETVALUE", "SECRETVALUE")

    def test_double_slash_comment(self):
        assert is_in_comment("code(); // token SECRETVALUE", "SECRETVALUE")

    def test_url_double_slash_is_not_a_comment(self):
        assert not is_in_comment("x = https://host/SECRETVALUE", "SECRETVALUE")

    def test_value_before_comment_is_not_in_comment(self):
        assert not is_in_comment('key = "SECRETVALUE"  # note', "SECRETVALUE")


class TestTestFileDetection:
    def test_test_prefix(self):
        assert is_test_or_doc_file("tests/test_login.py")

    def test_markdown_doc(self):
        assert is_test_or_doc_file("README.md")

    def test_example_extension(self):
        assert is_test_or_doc_file("config.env.example")

    def test_windows_style_path(self):
        assert is_test_or_doc_file(r"src\tests\helpers.py")

    def test_regular_source_file_is_not_test(self):
        assert not is_test_or_doc_file("src/app/config.py")


class TestAnalyzeReasons:
    def test_reasons_are_recorded(self):
        result = analyze("# example_key = ABC", "tests/test_x.py", "ABC")
        assert result.in_comment
        assert result.in_test_file
        assert result.matched_keywords
        assert result.reasons  # human-readable explanations present
