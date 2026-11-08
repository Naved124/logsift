"""Parser for Linux authentication logs: /var/log/auth.log, /var/log/secure, or journalctl output.

Two timestamp styles are accepted:
  classic syslog:   Nov  8 10:00:01 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 51022 ssh2
  ISO (journalctl -o short-iso, or rsyslog with high-precision timestamps):
                    2026-11-08T10:00:01+05:30 web01 sshd[1234]: Accepted publickey for naved from 198.51.100.4 port 40112 ssh2

Classic syslog lines carry no year and no timezone, so the caller supplies both.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, tzinfo
from pathlib import Path

from ..models import Event
from . import read_lines

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
    r" (?P<host>\S+) (?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)

FAILED_RE = re.compile(r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+)")
INVALID_RE = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)")
SUDO_RE = re.compile(r"^\s*(?P<user>\S+) : .*?(?:USER=(?P<target>\S+) ; )?COMMAND=(?P<command>.*)$")
SUDO_FAIL_RE = re.compile(r"^\s*(?P<user>\S+) : .*(?:incorrect password attempts?|authentication failure)")


def _parse_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    elif re.search(r"[+-]\d{4}$", value):
        # journalctl prints +0530; datetime.fromisoformat before Python 3.11 needs +05:30.
        value = value[:-2] + ":" + value[-2:]
    return datetime.fromisoformat(value)


def parse_line(line: str, year: int, tz: tzinfo = timezone.utc) -> Event | None:
    match = ISO_RE.match(line)
    if match:
        try:
            ts = _parse_iso(match["ts"])
        except ValueError:
            return None
    else:
        match = SYSLOG_RE.match(line)
        if not match:
            return None
        try:
            ts = datetime.strptime(f"{year} {match['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz)
        except ValueError:
            return None

    proc = match["proc"].rsplit("/", 1)[-1]
    msg = match["msg"]
    base = {"host": match["host"], "process": proc}

    if proc == "sshd":
        failed = FAILED_RE.search(msg)
        if failed:
            return Event(
                ts=ts, source="auth", action="ssh_failed", ip=failed["ip"], user=failed["user"],
                status="failure", raw=line,
                details={**base, "method": failed["method"], "invalid_user": bool(failed["invalid"])},
            )
        accepted = ACCEPTED_RE.search(msg)
        if accepted:
            return Event(
                ts=ts, source="auth", action="ssh_accepted", ip=accepted["ip"], user=accepted["user"],
                status="success", raw=line, details={**base, "method": accepted["method"]},
            )
        invalid = INVALID_RE.search(msg)
        if invalid:
            # sshd logs "Invalid user" before the matching "Failed password" line. Counting both
            # would double the failure count, so this is kept as its own action.
            return Event(
                ts=ts, source="auth", action="ssh_invalid_user", ip=invalid["ip"], user=invalid["user"] or None,
                status="failure", raw=line, details=base,
            )
        return None

    if proc == "sudo":
        failed = SUDO_FAIL_RE.match(msg)
        if failed:
            return Event(ts=ts, source="auth", action="sudo_failed", user=failed["user"], status="failure",
                         raw=line, details=base)
        sudo = SUDO_RE.match(msg)
        if sudo:
            return Event(
                ts=ts, source="auth", action="sudo_command", user=sudo["user"], status="success", raw=line,
                details={**base, "target_user": sudo["target"] or "root", "command": sudo["command"].strip()},
            )
    return None


def parse_file(path: str | Path, year: int, tz: tzinfo = timezone.utc) -> tuple[list[Event], int]:
    """Return (events, number of lines skipped).

    Skipped lines include ordinary syslog noise (cron, session opened, etc.), not only malformed ones.
    """
    events: list[Event] = []
    skipped = 0
    for line in read_lines(path):
        event = parse_line(line, year, tz)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped
