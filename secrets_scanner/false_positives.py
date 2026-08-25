"""Context analysis to suppress obvious false positives.

Findings are never silently deleted here — instead we record *reasons* and a
severity *penalty* so the scoring layer can down-rank things that are clearly
not real secrets (placeholders, values inside comments, values in test/example
files) while still keeping them visible in the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Words that strongly suggest a value is a stand-in rather than a real secret.
FALSE_POSITIVE_KEYWORDS = frozenset(
    {
        "example", "test", "testing", "dummy", "sample", "placeholder",
        "foo", "bar", "baz", "qux", "xxx", "xxxx", "changeme", "change_me",
        "yourkey", "your_key", "your_key_here", "your_token", "your_secret",
        "redacted", "fake", "mock", "todo", "n/a", "notreal", "donotuse",
    }
)

# Substrings in a path that mark it as a test / example / documentation file,
# where secrets are far more likely to be illustrative than real.
TEST_PATH_INDICATORS = (
    "test_", "_test", "/test/", "/tests/", "\\test\\", "\\tests\\",
    "/spec/", ".spec.", ".test.", "/fixtures/", "/fixture/", "conftest",
    "/examples/", "/example/", "/docs/", "/doc/", "/sample",
)

# File extensions that are documentation/examples rather than shipped code.
DOC_LIKE_EXTENSIONS = (
    ".md", ".rst", ".txt", ".example", ".sample", ".dist", ".template",
)


@dataclass
class ContextResult:
    """What we learned about the context surrounding a match."""

    in_comment: bool = False
    in_test_file: bool = False
    matched_keywords: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def is_test_or_doc_file(file_path: str) -> bool:
    """True if the path looks like a test, example or documentation file."""
    lowered = file_path.lower().replace("\\", "/")
    if lowered.endswith(DOC_LIKE_EXTENSIONS):
        return True
    return any(indicator.replace("\\", "/") in lowered for indicator in TEST_PATH_INDICATORS)


def _comment_index(line: str) -> int:
    """Return the index at which a line comment begins, or ``-1``.

    Handles ``#``, ``//`` (ignoring the ``://`` in URLs), ``/*`` and ``<!--``.
    """
    candidates: list[int] = []

    hash_idx = line.find("#")
    if hash_idx != -1:
        candidates.append(hash_idx)

    search = 0
    while True:
        idx = line.find("//", search)
        if idx == -1:
            break
        if idx == 0 or line[idx - 1] != ":":  # skip http:// etc.
            candidates.append(idx)
            break
        search = idx + 2

    for marker in ("/*", "<!--"):
        idx = line.find(marker)
        if idx != -1:
            candidates.append(idx)

    return min(candidates) if candidates else -1


def is_in_comment(line: str, value: str) -> bool:
    """True if ``value`` appears after a comment marker on ``line``."""
    comment_idx = _comment_index(line)
    if comment_idx == -1:
        return False
    value_idx = line.find(value)
    return value_idx != -1 and value_idx > comment_idx


def _find_keywords(text: str) -> list[str]:
    lowered = text.lower()
    return sorted({kw for kw in FALSE_POSITIVE_KEYWORDS if kw in lowered})


def analyze(line: str, file_path: str, value: str) -> ContextResult:
    """Analyse the context around a matched ``value`` on ``line``."""
    result = ContextResult()

    # Look for placeholder keywords both in the value itself and in the
    # surrounding line (e.g. a variable named ``example_key``).
    keywords = _find_keywords(value) or _find_keywords(line)
    if keywords:
        result.matched_keywords = keywords
        result.reasons.append("placeholder/test keyword: " + ", ".join(keywords))

    if is_in_comment(line, value):
        result.in_comment = True
        result.reasons.append("inside a comment")

    if is_test_or_doc_file(file_path):
        result.in_test_file = True
        result.reasons.append("in a test/example/doc file")

    return result
