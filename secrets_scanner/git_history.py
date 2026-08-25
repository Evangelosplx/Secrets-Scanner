"""Git access via the system ``git`` binary (subprocess), plus repo scanning.

The key value of this tool over a plain file grep is that it walks the *entire
commit history*: a secret deleted from today's code still lives in old commits
and stays exploitable. We scan the working tree and every historical version of
every changed file, attributing each finding to the commit it appears in.

All git I/O is isolated here so the detection/scoring layers stay pure and
unit-testable without a real repository.
"""

from __future__ import annotations

import os
import subprocess
from typing import Optional

from .models import ScanResult, WORKING_TREE
from .scanner import Verifier, scan_text

# Skip absurdly large blobs so one generated file can't stall a scan.
MAX_BLOB_BYTES = 2_000_000


class GitError(RuntimeError):
    """Raised when git is unavailable or a command fails unexpectedly."""


def _run_git(repo: str, args: list[str]) -> bytes:
    """Run ``git -C <repo> <args>`` and return raw stdout bytes."""
    try:
        result = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True,
            check=True,
        )
    except FileNotFoundError as exc:  # git not installed
        raise GitError("git executable not found on PATH") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {' '.join(args)} failed: {stderr}") from exc
    return result.stdout


def is_git_repo(repo: str) -> bool:
    """True if ``repo`` is inside a git working tree."""
    try:
        out = _run_git(repo, ["rev-parse", "--is-inside-work-tree"])
    except GitError:
        return False
    return out.decode("utf-8", "replace").strip() == "true"


def _decode_blob(raw: bytes) -> Optional[str]:
    """Decode blob bytes to text, skipping binary/oversized content."""
    if len(raw) > MAX_BLOB_BYTES:
        return None
    if b"\x00" in raw:  # NUL byte -> treat as binary
        return None
    return raw.decode("utf-8", "replace")


def list_tracked_files(repo: str) -> list[str]:
    """Paths tracked in the current working tree."""
    out = _run_git(repo, ["ls-files", "-z"])
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def list_commits(repo: str, reverse: bool = True) -> list[str]:
    """All commit hashes across all refs (oldest-first by default)."""
    args = ["rev-list", "--all"]
    if reverse:
        args.append("--reverse")
    out = _run_git(repo, args).decode("utf-8", "replace")
    return [line for line in out.splitlines() if line]


def files_changed_in_commit(repo: str, commit: str) -> list[str]:
    """Paths added/modified by ``commit`` (``--root`` so the first commit works)."""
    out = _run_git(
        repo,
        ["diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit],
    )
    return [p for p in out.decode("utf-8", "replace").splitlines() if p]


def read_blob(repo: str, commit: str, path: str) -> Optional[str]:
    """Read a file's content at a specific commit, or ``None`` if unreadable."""
    try:
        raw = _run_git(repo, ["show", f"{commit}:{path}"])
    except GitError:
        return None  # path may not exist at that commit (rename/delete)
    return _decode_blob(raw)


def read_working_file(repo: str, path: str) -> Optional[str]:
    """Read a working-tree file from disk, skipping binary/oversized content."""
    full = os.path.join(repo, path)
    try:
        with open(full, "rb") as handle:
            raw = handle.read(MAX_BLOB_BYTES + 1)
    except OSError:
        return None
    return _decode_blob(raw)


def _dedupe(findings):
    """Collapse the same secret seen many times into one entry.

    Key = (secret_type, file_path, masked_secret). A working-tree occurrence is
    preferred as the representative (it is the current, most actionable one);
    otherwise the earliest commit wins because history is walked oldest-first.
    The highest severity in the group is kept and occurrences are counted.
    """
    groups: dict[tuple, list] = {}
    order: list[tuple] = []
    for finding in findings:
        key = (finding.secret_type, finding.file_path, finding.masked_secret)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    deduped = []
    for key in order:
        group = groups[key]
        representative = next(
            (f for f in group if f.commit_hash == WORKING_TREE), group[0]
        )
        # Prefer the most severe scoring seen for this secret.
        best = max(group, key=lambda f: (f.severity.rank, f.score))
        representative.severity = best.severity
        representative.score = best.score
        representative.live_status = best.live_status
        representative.reasons = best.reasons
        representative.occurrences = len(group)
        deduped.append(representative)
    return deduped


def scan_repository(
    repo: str,
    *,
    include_history: bool = True,
    verifier: Optional[Verifier] = None,
    **scan_kwargs,
) -> ScanResult:
    """Scan a repository's working tree and (optionally) its full history."""
    if not is_git_repo(repo):
        raise GitError(f"{repo!r} is not a git repository")

    findings = []
    files_scanned = 0
    commits_scanned = 0

    # 1) Working tree (current files on disk).
    for path in list_tracked_files(repo):
        content = read_working_file(repo, path)
        if content is None:
            continue
        files_scanned += 1
        findings.extend(
            scan_text(content, path, WORKING_TREE, verifier=verifier, **scan_kwargs)
        )

    # 2) Full history (every version of every changed file).
    if include_history:
        for commit in list_commits(repo, reverse=True):
            commits_scanned += 1
            for path in files_changed_in_commit(repo, commit):
                content = read_blob(repo, commit, path)
                if content is None:
                    continue
                findings.extend(
                    scan_text(content, path, commit, verifier=verifier, **scan_kwargs)
                )

    return ScanResult(
        findings=_dedupe(findings),
        files_scanned=files_scanned,
        commits_scanned=commits_scanned,
    )
