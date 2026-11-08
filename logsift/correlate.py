"""Group findings by source IP so each attacker can be read as one story."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .models import POSSIBLE, SUCCEEDED, Finding, severity_rank


@dataclass
class Actor:
    ip: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return min(f.first_seen for f in self.findings)

    @property
    def last_seen(self) -> datetime:
        return max(f.last_seen for f in self.findings)

    @property
    def severity(self) -> str:
        return max((f.severity for f in self.findings), key=severity_rank)

    @property
    def sources(self) -> list[str]:
        return sorted({f.source for f in self.findings})

    @property
    def outcome(self) -> str:
        outcomes = {f.outcome for f in self.findings}
        if SUCCEEDED in outcomes:
            return SUCCEEDED
        if POSSIBLE in outcomes:
            return POSSIBLE
        return "no sign of success"

    @property
    def users(self) -> list[str]:
        return sorted({f.user for f in self.findings if f.user})

    def timeline(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.first_seen, f.rule_id))

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "severity": self.severity,
            "outcome": self.outcome,
            "sources": self.sources,
            "users": self.users,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "rule_ids": [f.rule_id for f in self.timeline()],
        }


def build_actors(findings: list[Finding]) -> list[Actor]:
    """Return one Actor per IP that has findings, worst first."""
    actors: dict[str, Actor] = {}
    for finding in findings:
        if finding.ip:
            actors.setdefault(finding.ip, Actor(finding.ip)).findings.append(finding)
    return sorted(
        actors.values(),
        key=lambda a: (-severity_rank(a.severity), a.outcome != SUCCEEDED, -len(a.sources), a.first_seen),
    )
