"""End-to-end test: a secret deleted from current code is still found in history.

This is the core promise of the tool. We build a throwaway git repo, commit a
fake AWS key, then delete it in a later commit, and assert the scanner still
surfaces it and attributes it to the commit that introduced it.
"""

import subprocess

import pytest

from secrets_scanner.git_history import GitError, is_git_repo, scan_repository
from secrets_scanner.models import WORKING_TREE
from secrets_scanner.patterns import AWS_ACCESS_KEY

AWS_KEY = "AKIA2E4Q7B8XY1Z9K3PL"


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo_with_deleted_secret(tmp_path):
    """A repo where a secret is added then removed in a later commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")

    config = repo / "config.py"

    # Commit 1: introduce the secret.
    config.write_text(f'AWS_KEY = "{AWS_KEY}"\n', encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "add config")

    # Commit 2: "clean up" — remove the secret from current code.
    config.write_text("AWS_KEY = load_from_env()\n", encoding="utf-8")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "load key from env")

    return repo


class TestGitHistoryScan:
    def test_is_git_repo_true_for_repo(self, repo_with_deleted_secret):
        assert is_git_repo(str(repo_with_deleted_secret))

    def test_is_git_repo_false_for_plain_dir(self, tmp_path):
        assert not is_git_repo(str(tmp_path))

    def test_secret_found_in_history_not_working_tree(self, repo_with_deleted_secret):
        result = scan_repository(str(repo_with_deleted_secret), include_history=True)

        aws = [f for f in result.findings if f.secret_type == AWS_ACCESS_KEY]
        assert aws, "AWS key should be found in history"
        finding = aws[0]

        # It lives in a real commit, not the working tree (it was deleted).
        assert finding.commit_hash != WORKING_TREE
        assert len(finding.commit_hash) >= 7
        assert result.commits_scanned == 2

    def test_no_history_scan_misses_deleted_secret(self, repo_with_deleted_secret):
        result = scan_repository(str(repo_with_deleted_secret), include_history=False)
        aws = [f for f in result.findings if f.secret_type == AWS_ACCESS_KEY]
        assert aws == []  # not in current files, and we skipped history

    def test_working_tree_secret_is_found_without_history(self, tmp_path):
        repo = tmp_path / "live"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "t@e.com")
        _git(repo, "config", "user.name", "T")
        (repo / "app.py").write_text(f'KEY = "{AWS_KEY}"\n', encoding="utf-8")
        _git(repo, "add", "app.py")
        _git(repo, "commit", "-q", "-m", "init")

        result = scan_repository(str(repo), include_history=False)
        aws = [f for f in result.findings if f.secret_type == AWS_ACCESS_KEY]
        assert aws and aws[0].commit_hash == WORKING_TREE

    def test_non_repo_raises(self, tmp_path):
        with pytest.raises(GitError):
            scan_repository(str(tmp_path))
