"""Core data types shared by parsers, detectors and the report writer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    """Return a sortable rank for a severity name (higher is worse)."""
    return SEVERITIES.index(severity)


# Outcome values a finding can carry. They answer the question "did it work?".
SUCCEEDED = "succeeded"
POSSIBLE = "possible"
FAILED = "failed"
UNKNOWN = "unknown"


@dataclass
class Event:
    """One normalized log event.

    ts      -- timezone-aware timestamp
    source  -- "web", "auth" or "cloudtrail"
    ip      -- source IP address, if the log records one
    user    -- user name or principal, if known
    action  -- short machine-readable verb, e.g. "ssh_failed", "http_request", "StopLogging"
    status  -- HTTP status, "success"/"failure", or an AWS error code
    raw     -- the original line (or a compact JSON rendering for CloudTrail)
    details -- source-specific fields
    """

    ts: datetime
    source: str
    action: str
    ip: str | None = None
    user: str | None = None
    status: str | None = None
    raw: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Something worth an analyst's attention, built from one or more events."""

    rule_id: str
    title: str
    severity: str
    source: str
    ip: str | None
    first_seen: datetime
    last_seen: datetime
    count: int
    outcome: str = UNKNOWN
    description: str = ""
    user: str | None = None
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "source": self.source,
            "ip": self.ip,
            "user": self.user,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "outcome": self.outcome,
            "description": self.description,
            "evidence": self.evidence,
            "details": self.details,
        }


MAX_EVIDENCE = 5


def sample_evidence(events: list[Event], limit: int = MAX_EVIDENCE) -> list[str]:
    """Pick up to `limit` raw lines: the first few plus the last one, so the range is visible."""
    if len(events) <= limit:
        return [e.raw for e in events]
    return [e.raw for e in events[: limit - 1]] + [events[-1].raw]
