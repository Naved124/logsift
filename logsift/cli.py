"""Command-line entry point."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

from . import __version__
from .correlate import build_actors
from .detectors import Config
from .detectors import auth as auth_rules
from .detectors import cloudtrail as cloudtrail_rules
from .detectors import web as web_rules
from .models import SEVERITIES, Event, severity_rank
from .parsers import auth as auth_parser
from .parsers import cloudtrail as cloudtrail_parser
from .parsers import web as web_parser
from .report import Analysis, InputSummary, render_json, render_markdown


def parse_tz(value: str) -> tzinfo:
    """Accept UTC, Z, +05:30 or +0530."""
    if value.upper() in {"UTC", "Z"}:
        return timezone.utc
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", value)
    if not match:
        raise argparse.ArgumentTypeError(f"bad timezone offset '{value}', use e.g. +05:30 or UTC")
    sign = 1 if match[1] == "+" else -1
    return timezone(sign * timedelta(hours=int(match[2]), minutes=int(match[3])))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsift",
        description="Investigate web server, Linux auth and AWS CloudTrail logs and report what an attacker did.",
    )
    parser.add_argument("--version", action="version", version=f"logsift {__version__}")
    parser.add_argument("--web", action="append", default=[], metavar="FILE",
                        help="nginx/Apache access log (common or combined format); repeatable, .gz ok")
    parser.add_argument("--auth", action="append", default=[], metavar="FILE",
                        help="auth.log / secure / journalctl output; repeatable, .gz ok")
    parser.add_argument("--cloudtrail", action="append", default=[], metavar="FILE",
                        help="CloudTrail JSON (Records file, array or JSON Lines); repeatable, .gz ok")
    parser.add_argument("-o", "--output", metavar="FILE", help="write the Markdown report here (default: stdout)")
    parser.add_argument("--json", metavar="FILE", help="also write machine-readable findings as JSON")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year for syslog lines, which do not record one (default: current year)")
    parser.add_argument("--tz", type=parse_tz, default=timezone.utc,
                        help="timezone of syslog lines, also used for every time in the report, e.g. +05:30 (default: UTC)")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="low",
                        help="leave out findings below this severity (default: low)")
    parser.add_argument("--fail-on", choices=SEVERITIES,
                        help="exit with status 2 if any finding is at or above this severity (for CI or cron)")
    parser.add_argument("--bruteforce-threshold", type=int, default=Config.bruteforce_threshold,
                        help="failed SSH logins from one IP in 10 minutes that count as brute force (default: 10)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not (args.web or args.auth or args.cloudtrail):
        print("logsift: give at least one of --web, --auth or --cloudtrail", file=sys.stderr)
        return 1

    config = Config(bruteforce_threshold=args.bruteforce_threshold)
    events: list[Event] = []
    inputs: list[InputSummary] = []

    jobs = (
        [(p, "web", lambda p: web_parser.parse_file(p)) for p in args.web]
        + [(p, "auth", lambda p: auth_parser.parse_file(p, args.year, args.tz)) for p in args.auth]
        + [(p, "cloudtrail", lambda p: cloudtrail_parser.parse_file(p)) for p in args.cloudtrail]
    )
    for path, kind, parse in jobs:
        if not Path(path).is_file():
            print(f"logsift: {path}: no such file", file=sys.stderr)
            return 1
        try:
            parsed, skipped = parse(path)
        except (ValueError, OSError) as exc:
            print(f"logsift: {path}: could not read as {kind} log: {exc}", file=sys.stderr)
            return 1
        events.extend(parsed)
        inputs.append(InputSummary(path=path, kind=kind, events=len(parsed), skipped=skipped))

    findings = (
        web_rules.detect(events, config)
        + auth_rules.detect(events, config)
        + cloudtrail_rules.detect(events, config)
    )
    floor = severity_rank(args.min_severity)
    findings = [f for f in findings if severity_rank(f.severity) >= floor]

    timestamps = [e.ts for e in events]
    analysis = Analysis(
        inputs=inputs,
        findings=findings,
        actors=build_actors(findings),
        first_event=min(timestamps) if timestamps else None,
        last_event=max(timestamps) if timestamps else None,
        display_tz=args.tz,
    )

    markdown = render_markdown(analysis)
    if args.output:
        Path(args.output).write_text(markdown + "\n", encoding="utf-8")
        print(f"logsift: {len(findings)} finding(s), report written to {args.output}", file=sys.stderr)
    else:
        print(markdown)
    if args.json:
        Path(args.json).write_text(render_json(analysis) + "\n", encoding="utf-8")

    if args.fail_on and any(severity_rank(f.severity) >= severity_rank(args.fail_on) for f in findings):
        return 2
    return 0
