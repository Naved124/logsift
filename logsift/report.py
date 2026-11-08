"""Markdown and JSON report writers."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from typing import Any

from . import __version__
from .correlate import Actor
from .models import SEVERITIES, Finding, severity_rank

OUTCOME_LABEL = {
    "succeeded": "**SUCCEEDED**",
    "possible": "**possible** (got a 2xx response)",
    "failed": "failed",
    "unknown": "unknown",
}


@dataclass
class InputSummary:
    path: str
    kind: str
    events: int
    skipped: int


@dataclass
class Analysis:
    inputs: list[InputSummary]
    findings: list[Finding]
    actors: list[Actor]
    first_event: datetime | None = None
    last_event: datetime | None = None
    generated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    display_tz: tzinfo = timezone.utc


# Every timestamp in a report is shown in one timezone, so times from different logs line up.
_DISPLAY_TZ: list[tzinfo] = [timezone.utc]


def _ts(value: datetime | None) -> str:
    return value.astimezone(_DISPLAY_TZ[0]).strftime("%Y-%m-%d %H:%M:%S %z") if value else "-"


def _code(lines: list[str]) -> str:
    # Escape anything that would close the fence early.
    body = "\n".join(line.replace("```", "`\u200b``") for line in lines)
    return f"```\n{body}\n```"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-severity_rank(f.severity), f.first_seen, f.rule_id))


def render_markdown(analysis: Analysis, top: int = 10) -> str:
    _DISPLAY_TZ[0] = analysis.display_tz
    out: list[str] = ["# logsift incident report", ""]
    out.append(f"Generated {_ts(analysis.generated)} by logsift {__version__}. "
               f"All times are shown as UTC{_ts(analysis.generated)[-5:]}.")
    out.append("")

    out += ["## Inputs", "", "| File | Type | Events parsed | Lines skipped |", "|---|---|---|---|"]
    for item in analysis.inputs:
        out.append(f"| `{_cell(item.path)}` | {item.kind} | {item.events} | {item.skipped} |")
    out += ["", f"Time range covered: {_ts(analysis.first_event)} to {_ts(analysis.last_event)}", ""]

    out += ["## Summary", ""]
    if not analysis.findings:
        out += ["No findings. Nothing in these logs matched a detection rule.", ""]
        return "\n".join(out)

    counts = Counter(f.severity for f in analysis.findings)
    out.append(" · ".join(f"{s}: {counts[s]}" for s in reversed(SEVERITIES) if counts[s]))
    out.append("")

    compromised = [a for a in analysis.actors if a.outcome == "succeeded"]
    if compromised:
        out.append("**Attacks that appear to have succeeded:**")
        out.append("")
        for actor in compromised:
            wins = [f for f in actor.findings if f.outcome == "succeeded"]
            out.append(f"- `{actor.ip}`: " + "; ".join(f"{f.title} ({f.rule_id})" for f in wins))
        out.append("")

    if analysis.actors:
        out += ["### Source IPs", "",
                "| IP | Worst severity | Outcome | Logs involved | Accounts | First seen | Last seen |",
                "|---|---|---|---|---|---|---|"]
        for actor in analysis.actors:
            out.append(
                f"| `{actor.ip}` | {actor.severity} | {actor.outcome} | {', '.join(actor.sources)} | "
                f"{_cell(', '.join(actor.users)) or '-'} | {_ts(actor.first_seen)} | {_ts(actor.last_seen)} |"
            )
        out.append("")

    multi = [a for a in analysis.actors if len(a.sources) > 1]
    if multi:
        out += ["### Timelines for IPs seen in more than one log", ""]
        for actor in multi[:top]:
            out += [f"**{actor.ip}** ({', '.join(actor.sources)})", ""]
            for f in actor.timeline():
                out.append(f"1. {_ts(f.first_seen)} · {f.rule_id} {f.title} · outcome: {f.outcome}")
            out.append("")

    out += ["## Findings", ""]
    for number, f in enumerate(ordered(analysis.findings), 1):
        out.append(f"### {number}. [{f.severity.upper()}] {f.title} ({f.rule_id})")
        out.append("")
        out.append(f"- **What:** {f.description}")
        when = _ts(f.first_seen) if f.first_seen == f.last_seen else f"{_ts(f.first_seen)} to {_ts(f.last_seen)}"
        out.append(f"- **When:** {when}")
        where = f"`{f.ip}`" if f.ip else "local"
        out.append(f"- **From:** {where} ({f.source} log)")
        if f.user:
            out.append(f"- **Account:** `{f.user}`")
        out.append(f"- **Outcome:** {OUTCOME_LABEL.get(f.outcome, f.outcome)}")
        out.append(f"- **Events:** {f.count}")
        out.append("")
        if f.evidence:
            out += [_code(f.evidence), ""]
    return "\n".join(out)


def render_json(analysis: Analysis) -> str:
    data: dict[str, Any] = {
        "generator": f"logsift {__version__}",
        "generated": analysis.generated.isoformat(),
        "inputs": [vars(i) for i in analysis.inputs],
        "time_range": {
            "first": analysis.first_event.isoformat() if analysis.first_event else None,
            "last": analysis.last_event.isoformat() if analysis.last_event else None,
        },
        "actors": [a.to_dict() for a in analysis.actors],
        "findings": [f.to_dict() for f in ordered(analysis.findings)],
    }
    return json.dumps(data, indent=2)
