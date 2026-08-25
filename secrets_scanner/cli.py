"""Command-line interface for secrets-scanner."""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from . import __version__
from .git_history import GitError, scan_repository
from .models import ScanResult, Severity
from .report import render_terminal, to_json
from .verify import verify as live_verify

_MIN_SEVERITY = {
    "green": Severity.GREEN,
    "yellow": Severity.YELLOW,
    "red": Severity.RED,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets-scanner",
        description=(
            "Scan a git repository's working tree and full commit history for "
            "leaked secrets (API keys, tokens, passwords, private keys) using "
            "regex signatures and Shannon-entropy analysis."
        ),
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Path to the git repository to scan (default: current directory).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON instead of the colored table.",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Scan only current files, skip git history (faster).",
    )
    parser.add_argument(
        "--live-verify",
        action="store_true",
        help=(
            "OPT-IN: send recognised tokens (e.g. GitHub) to their provider's "
            "API to check whether they are still active. Makes outbound network "
            "calls with the discovered credential."
        ),
    )
    parser.add_argument(
        "--min-severity",
        choices=list(_MIN_SEVERITY),
        default="green",
        help="Only report findings at or above this severity (default: green).",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=None,
        metavar="BITS",
        help="Override the base64 entropy threshold (bits/char, default 4.5).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _filter_by_severity(result: ScanResult, minimum: Severity) -> ScanResult:
    kept = [f for f in result.findings if f.severity.rank >= minimum.rank]
    return ScanResult(
        findings=kept,
        files_scanned=result.files_scanned,
        commits_scanned=result.commits_scanned,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    err_console = Console(stderr=True)

    scan_kwargs = {}
    if args.entropy_threshold is not None:
        scan_kwargs["base64_threshold"] = args.entropy_threshold

    try:
        result = scan_repository(
            args.repo,
            include_history=not args.no_history,
            verifier=live_verify if args.live_verify else None,
            **scan_kwargs,
        )
    except GitError as error:
        err_console.print(f"[bold red]error:[/bold red] {error}")
        return 2

    result = _filter_by_severity(result, _MIN_SEVERITY[args.min_severity])

    if args.json:
        print(to_json(result))
    else:
        render_terminal(result, console=console)

    # Non-zero exit if any RED finding remains — useful as a CI gate.
    return 1 if result.counts["red"] else 0


if __name__ == "__main__":
    sys.exit(main())
