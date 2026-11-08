"""Parser for nginx/Apache access logs in the common or combined log format.

Example line (combined):
203.0.113.7 - - [08/Nov/2026:10:15:32 +0530] "GET /login?id=1 HTTP/1.1" 200 512 "-" "sqlmap/1.8"
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus

from ..models import Event
from . import read_lines

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)
TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def decode(value: str) -> str:
    """URL-decode twice so double-encoded payloads (%252e%252e) are visible too."""
    once = unquote_plus(value)
    return unquote_plus(once)


def parse_line(line: str) -> Event | None:
    match = LINE_RE.match(line)
    if not match:
        return None
    try:
        ts = datetime.strptime(match["ts"], TS_FORMAT)
    except ValueError:
        return None

    request = match["request"]
    parts = request.split(" ")
    if len(parts) == 3:
        method, target, protocol = parts
    else:
        # Malformed requests (binary junk, bare probes) are kept whole: they are often scans.
        method, target, protocol = "", request, ""

    user = match["user"]
    return Event(
        ts=ts,
        source="web",
        action="http_request",
        ip=match["ip"],
        user=None if user == "-" else user,
        status=match["status"],
        raw=line,
        details={
            "method": method,
            "target": target,
            "decoded_target": decode(target),
            "protocol": protocol,
            "size": match["size"],
            "referer": match["referer"] or "",
            "user_agent": match["agent"] or "",
        },
    )


def parse_file(path: str | Path) -> tuple[list[Event], int]:
    """Return (events, number of lines that could not be parsed)."""
    events: list[Event] = []
    skipped = 0
    for line in read_lines(path):
        event = parse_line(line)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped
