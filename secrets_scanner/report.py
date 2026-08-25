"""Rendering: pretty terminal output (rich) and machine-readable JSON."""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import LiveStatus, ScanResult, Severity, WORKING_TREE

_SEVERITY_STYLE = {
    Severity.RED: "bold white on red",
    Severity.YELLOW: "bold black on yellow",
    Severity.GREEN: "bold white on green",
}

_LIVE_LABEL = {
    LiveStatus.ACTIVE: Text("ACTIVE", style="bold red"),
    LiveStatus.REVOKED: Text("revoked", style="dim"),
    LiveStatus.UNKNOWN: Text("unknown", style="yellow"),
    LiveStatus.NOT_CHECKED: Text("-", style="dim"),
}


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    """Serialize a scan result to a JSON string."""
    return json.dumps(result.to_dict(), indent=indent)


def _short_commit(commit_hash: str) -> str:
    return "working tree" if commit_hash == WORKING_TREE else commit_hash[:10]


def render_terminal(result: ScanResult, *, console: Console | None = None) -> None:
    """Print a colored table + summary panel to the terminal."""
    console = console or Console()

    if not result.findings:
        console.print(
            Panel(
                Text("No secrets detected.", style="bold green"),
                title="secrets-scanner",
                border_style="green",
            )
        )
        _print_summary(result, console)
        return

    table = Table(
        title="Potential Secrets",
        title_style="bold",
        header_style="bold cyan",
        show_lines=False,
        expand=True,
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("File", overflow="fold")
    table.add_column("Line", justify="right", no_wrap=True)
    table.add_column("Commit", no_wrap=True)
    table.add_column("Secret (masked)", overflow="fold")
    table.add_column("Live", no_wrap=True)
    table.add_column("Seen", justify="right", no_wrap=True)

    for finding in result.sorted_findings():
        severity_cell = Text(
            f" {finding.severity.value.upper()} ",
            style=_SEVERITY_STYLE[finding.severity],
        )
        table.add_row(
            severity_cell,
            finding.secret_type,
            finding.file_path,
            str(finding.line_number),
            _short_commit(finding.commit_hash),
            finding.masked_secret,
            _LIVE_LABEL[finding.live_status],
            str(finding.occurrences),
        )

    console.print(table)
    _print_summary(result, console)


def _print_summary(result: ScanResult, console: Console) -> None:
    counts = result.counts
    summary = Text()
    summary.append(f"Files scanned: {result.files_scanned}   ")
    summary.append(f"Commits scanned: {result.commits_scanned}\n")
    summary.append("RED ", style="bold red")
    summary.append(f"{counts['red']}    ")
    summary.append("YELLOW ", style="bold yellow")
    summary.append(f"{counts['yellow']}    ")
    summary.append("GREEN ", style="bold green")
    summary.append(f"{counts['green']}")

    border = "red" if counts["red"] else ("yellow" if counts["yellow"] else "green")
    console.print(Panel(summary, title="Summary", border_style=border))
