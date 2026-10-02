#!/usr/bin/env python3
"""SecureLogAnalyzer: a small Rich-powered authentication log analyzer."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import unquote

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

BRUTE_FORCE_THRESHOLD = 5
DEFAULT_LOG_FILE = Path("mock_auth.log")
DEFAULT_REPORT_FILE = Path("security_incident_report.md")

# The patterns intentionally cover the common Ubuntu/Debian sshd format and
# Apache combined access-log format used by the included fixture.
SSH_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<event>Accepted|Failed)\s+(?:password|publickey)"
    r"(?:\s+for\s+invalid\s+user|\s+for)\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
WEB_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/(?P<version>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)",
)


@dataclass(frozen=True)
class SSHLogin:
    """One accepted or rejected SSH authentication event."""

    timestamp: str
    user: str
    ip: str


@dataclass(frozen=True)
class ExploitationAttempt:
    """A web request whose target contains an exploitation signature."""

    timestamp: str
    ip: str
    method: str
    target: str
    status: str
    indicator: str


@dataclass
class AnalysisResult:
    """Parsed events and derived security findings."""

    successful_logins: list[SSHLogin] = field(default_factory=list)
    failed_logins: list[SSHLogin] = field(default_factory=list)
    exploitation_attempts: list[ExploitationAttempt] = field(default_factory=list)
    malformed_lines: int = 0

    @property
    def failed_by_ip(self) -> Counter[str]:
        return Counter(login.ip for login in self.failed_logins)

    @property
    def brute_force_sources(self) -> dict[str, int]:
        """Return IPs with strictly more than five failed SSH logins."""

        return dict(
            sorted(
                (
                    (ip, count)
                    for ip, count in self.failed_by_ip.items()
                    if count > BRUTE_FORCE_THRESHOLD
                ),
                key=lambda item: (-item[1], item[0]),
            )
        )

    @property
    def overall_threat_level(self) -> str:
        has_brute_force = bool(self.brute_force_sources)
        has_exploitation = bool(self.exploitation_attempts)
        has_failures = bool(self.failed_logins)

        if has_brute_force and has_exploitation:
            return "CRITICAL"
        if has_brute_force or has_exploitation:
            return "HIGH"
        if has_failures:
            return "MEDIUM"
        return "LOW"


def _exploitation_indicator(target: str) -> str | None:
    """Return a human-readable indicator when *target* looks hostile."""

    # Decode twice to catch both ordinary and double-encoded traversal.
    decoded_target = unquote(unquote(target))
    if re.search(r"(?:^|/)\.\.(?:/|$)", decoded_target):
        if re.search(r"/(?:etc/(?:passwd|shadow|hosts)|proc/self/)", decoded_target, re.I):
            return "Directory traversal targeting a sensitive system file"
        return "Directory traversal"
    if re.search(r"/(?:etc/(?:passwd|shadow|hosts)|proc/self/)", decoded_target, re.I):
        return "Sensitive system-file probe"
    return None


def parse_log_lines(lines: Iterable[str]) -> AnalysisResult:
    """Parse SSH and web access events from an iterable of log lines."""

    result = AnalysisResult()
    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if not line.strip():
            continue

        ssh_match = SSH_LOG_PATTERN.match(line)
        if ssh_match:
            event = ssh_match.group("event").lower()
            login = SSHLogin(
                timestamp=ssh_match.group("timestamp"),
                user=ssh_match.group("user"),
                ip=ssh_match.group("ip"),
            )
            if event == "accepted":
                result.successful_logins.append(login)
            else:
                result.failed_logins.append(login)
            continue

        web_match = WEB_LOG_PATTERN.match(line)
        if web_match:
            indicator = _exploitation_indicator(web_match.group("target"))
            if indicator:
                result.exploitation_attempts.append(
                    ExploitationAttempt(
                        timestamp=web_match.group("timestamp"),
                        ip=web_match.group("ip"),
                        method=web_match.group("method"),
                        target=web_match.group("target"),
                        status=web_match.group("status"),
                        indicator=indicator,
                    )
                )
            continue

        result.malformed_lines += 1

    return result


def analyze_log(log_file: Path | str) -> AnalysisResult:
    """Read and analyze *log_file*."""

    path = Path(log_file)
    with path.open("r", encoding="utf-8") as handle:
        return parse_log_lines(handle)


def _threat_markup(level: str) -> str:
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange1",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }
    color = colors.get(level, "white")
    return f"[{color}]{level}[/{color}]"


def render_dashboard(result: AnalysisResult, console: Console | None = None) -> None:
    """Render a color-coded terminal dashboard for an analysis result."""

    console = console or Console()
    console.print()
    console.print(
        Panel.fit(
            "[bold white]SecureLogAnalyzer[/bold white]\n"
            "[dim]Authentication and web exploitation triage[/dim]",
            border_style="cyan",
        )
    )

    summary = Table(box=box.ROUNDED, expand=True)
    summary.add_column("Successful SSH", justify="center", style="green")
    summary.add_column("Failed SSH", justify="center", style="yellow")
    summary.add_column("Brute-force sources", justify="center", style="red")
    summary.add_column("Exploitation attempts", justify="center", style="red")
    summary.add_column("Overall threat", justify="center")
    summary.add_row(
        str(len(result.successful_logins)),
        str(len(result.failed_logins)),
        str(len(result.brute_force_sources)),
        str(len(result.exploitation_attempts)),
        _threat_markup(result.overall_threat_level),
    )
    console.print(Panel(summary, title="[bold cyan]Security overview[/bold cyan]", border_style="cyan"))

    brute_force_table = Table(box=box.SIMPLE_HEAVY, expand=True)
    brute_force_table.add_column("Source IP", style="red")
    brute_force_table.add_column("Failed attempts", justify="right", style="bold red")
    brute_force_table.add_column("Threat", justify="center")
    if result.brute_force_sources:
        for ip, count in result.brute_force_sources.items():
            brute_force_table.add_row(escape(ip), str(count), _threat_markup("HIGH"))
    else:
        brute_force_table.add_row("—", "0", "[green]None detected[/green]")
    console.print(Panel(brute_force_table, title="[bold red]Brute-force detections[/bold red]", border_style="red"))

    exploit_table = Table(box=box.SIMPLE_HEAVY, expand=True)
    exploit_table.add_column("Timestamp")
    exploit_table.add_column("Source IP", style="red")
    exploit_table.add_column("Request")
    exploit_table.add_column("HTTP", justify="center")
    exploit_table.add_column("Indicator", style="bold red")
    if result.exploitation_attempts:
        for attempt in result.exploitation_attempts:
            request = f"{attempt.method} {attempt.target}"
            exploit_table.add_row(
                escape(attempt.timestamp),
                escape(attempt.ip),
                escape(request),
                escape(attempt.status),
                escape(attempt.indicator),
            )
    else:
        exploit_table.add_row("—", "—", "—", "—", "[green]None detected[/green]")
    console.print(
        Panel(
            exploit_table,
            title="[bold red]Exploitation attempts[/bold red]",
            border_style="red",
        )
    )

    recent_successes = Table(box=box.SIMPLE, expand=True)
    recent_successes.add_column("Timestamp")
    recent_successes.add_column("User", style="green")
    recent_successes.add_column("Source IP", style="green")
    for login in result.successful_logins[-5:]:
        recent_successes.add_row(escape(login.timestamp), escape(login.user), escape(login.ip))
    if not result.successful_logins:
        recent_successes.add_row("—", "No successful SSH logins", "—")
    console.print(
        Panel(
            recent_successes,
            title="[bold green]Recent successful SSH logins[/bold green]",
            border_style="green",
        )
    )

    if result.malformed_lines:
        console.print(
            f"[yellow]Note:[/yellow] {result.malformed_lines} unrecognized non-empty log line(s) skipped."
        )


def generate_markdown_report(result: AnalysisResult, source: Path | str) -> str:
    """Build a markdown incident report from an analysis result."""

    source_name = Path(source).name
    brute_force_rows = "\n".join(
        f"| `{ip}` | {count} | HIGH |" for ip, count in result.brute_force_sources.items()
    ) or "| — | 0 | None detected |"
    exploitation_rows = "\n".join(
        "| `{timestamp}` | `{ip}` | `{method} {target}` | {status} | {indicator} |".format(
            timestamp=attempt.timestamp,
            ip=attempt.ip,
            method=attempt.method,
            target=attempt.target.replace("|", "\\|"),
            status=attempt.status,
            indicator=attempt.indicator,
        )
        for attempt in result.exploitation_attempts
    ) or "| — | — | — | — | None detected |"
    success_rows = "\n".join(
        f"| `{login.timestamp}` | `{login.user}` | `{login.ip}` |"
        for login in result.successful_logins
    ) or "| — | — | — |"

    return f"""# SecureLogAnalyzer Security Incident Report

## Executive summary

- **Source log:** `{source_name}`
- **Overall threat level:** {_threat_emoji(result.overall_threat_level)} **{result.overall_threat_level}**
- **Successful SSH logins:** {len(result.successful_logins)}
- **Failed SSH logins:** {len(result.failed_logins)}
- **Brute-force sources:** {len(result.brute_force_sources)}
- **Exploitation attempts:** {len(result.exploitation_attempts)}

Brute force is flagged when one source IP produces **more than {BRUTE_FORCE_THRESHOLD} failed SSH logins**.

## Brute-force detections

| Source IP | Failed attempts | Threat |
|---|---:|---|
{brute_force_rows}

## Exploitation attempts

| Timestamp | Source IP | Request | HTTP status | Indicator |
|---|---|---|---:|---|
{exploitation_rows}

## Successful SSH logins

| Timestamp | User | Source IP |
|---|---|---|
{success_rows}

## Analyst recommendations

1. Investigate and block confirmed brute-force source IPs at the perimeter or host firewall.
2. Review authentication logs and rotate credentials for targeted accounts, especially `root`.
3. Inspect web-server and application logs around each traversal request for follow-on activity.
4. Prefer key-based SSH authentication, disable direct root login, and apply rate limiting.
"""


def _threat_emoji(level: str) -> str:
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }.get(level, "⚪")


def write_report(result: AnalysisResult, source: Path | str, report_file: Path | str) -> Path:
    """Export a markdown report and return its path."""

    report_path = Path(report_file)
    report_path.write_text(generate_markdown_report(result, source), encoding="utf-8")
    return report_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse SSH and web logs, detect threats, and export a markdown report."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help=f"log file to analyze (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "-o",
        "--report",
        dest="report_file",
        type=Path,
        default=DEFAULT_REPORT_FILE,
        help=f"markdown report destination (default: {DEFAULT_REPORT_FILE})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = analyze_log(args.log_file)
    except OSError as exc:
        print(f"SecureLogAnalyzer: unable to read {args.log_file}: {exc}", file=sys.stderr)
        return 2

    render_dashboard(result)
    try:
        report_path = write_report(result, args.log_file, args.report_file)
    except OSError as exc:
        print(f"SecureLogAnalyzer: unable to write {args.report_file}: {exc}", file=sys.stderr)
        return 2

    print(f"\nReport exported to {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
