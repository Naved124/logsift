"""Web attack detections for access logs.

Signatures look at the decoded request target and the user agent. They are deliberately simple
regular expressions: the aim is to surface requests a person should look at, not to replace a WAF.
"""

from __future__ import annotations

import re

from ..models import FAILED, POSSIBLE, UNKNOWN, Event, Finding, sample_evidence
from . import Config, densest_window, group_by

# (rule_id, title, severity, pattern applied to the decoded target)
SIGNATURES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("WEB-001", "SQL injection attempt", "high", re.compile(
        r"(\bunion\b.{0,40}\bselect\b|\bselect\b.{0,80}\bfrom\b|'\s*or\s+'?\d+'?\s*=\s*'?\d+"
        r"|\b(?:and|or)\s+(?P<n>\d+)\s*=\s*(?P=n)\b|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|\bwaitfor\s+delay\b"
        r"|information_schema|\bextractvalue\s*\(|\bupdatexml\s*\(|'\s*--|;\s*drop\s+table)",
        re.IGNORECASE)),
    ("WEB-002", "Cross-site scripting attempt", "medium", re.compile(
        r"(<\s*script\b|javascript:|\bon(?:error|load|mouseover|focus)\s*=|<\s*(?:img|svg|iframe)\b[^>]*\bsrc\s*="
        r"|document\.cookie|alert\s*\()",
        re.IGNORECASE)),
    ("WEB-003", "Path traversal / local file read attempt", "high", re.compile(
        r"(\.\./|\.\.\\|/etc/(?:passwd|shadow|hosts)\b|\bwin\.ini\b|/proc/self/|php://filter|file://)",
        re.IGNORECASE)),
    ("WEB-004", "Command injection attempt", "high", re.compile(
        r"([;|`]\s*(?:id|whoami|uname|cat|ls|wget|curl|nc|bash|sh|ping)\b|\$\(\s*\w+|\$\{IFS\}"
        r"|/bin/(?:ba)?sh\b)",
        re.IGNORECASE)),
    ("WEB-005", "Probe for sensitive files", "medium", re.compile(
        r"(/\.env\b|/\.git/|/\.svn/|/\.aws/|/wp-config\.php|/config\.php\.bak|\.sql(?:\.gz)?$|/backup\.zip"
        r"|/phpinfo\.php|/server-status|/actuator/(?:env|heapdump)|/\.DS_Store)",
        re.IGNORECASE)),
]

SCANNER_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|wpscan|gobuster|dirbuster|feroxbuster|ffuf|nuclei|acunetix|nessus"
    r"|openvas|hydra|wfuzz|whatweb|jaeles|httpx)",
    re.IGNORECASE,
)

SEVERITY_ON_SUCCESS = {"medium": "high", "high": "critical"}


def _outcome(hits: list[Event]) -> tuple[str, list[Event]]:
    """Decide whether any request in the group looks like it got through."""
    succeeded = [e for e in hits if e.status and e.status.startswith("2")]
    if succeeded:
        return POSSIBLE, succeeded
    if all(e.status and e.status[0] in "45" for e in hits):
        return FAILED, []
    return UNKNOWN, []


def detect(events: list[Event], config: Config) -> list[Finding]:
    events = sorted((e for e in events if e.source == "web"), key=lambda e: e.ts)
    findings: list[Finding] = []

    for ip, requests in group_by(events, lambda e: e.ip).items():
        for rule_id, title, severity, pattern in SIGNATURES:
            hits = [e for e in requests if pattern.search(e.details["decoded_target"])]
            if not hits:
                continue
            outcome, got_through = _outcome(hits)
            if outcome == POSSIBLE:
                severity = SEVERITY_ON_SUCCESS.get(severity, severity)
            statuses = sorted({e.status for e in hits})
            description = f"{len(hits)} request(s) matched; response codes: {', '.join(statuses)}."
            if got_through:
                description += (f" {len(got_through)} got a 2xx response, so check whether the payload was "
                                "actually executed (response size, application logs).")
            # Show the requests that got through first: they are what the reader needs to check.
            evidence_events = got_through[:3] + [e for e in hits if e not in got_through]
            findings.append(Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                source="web",
                ip=ip,
                first_seen=hits[0].ts,
                last_seen=hits[-1].ts,
                count=len(hits),
                outcome=outcome,
                description=description,
                evidence=sample_evidence(evidence_events),
                details={
                    "paths": sorted({e.details["decoded_target"].split("?", 1)[0] for e in hits})[:10],
                    "status_codes": statuses,
                    "successful_requests": len(got_through),
                },
            ))

        scans = [e for e in requests if SCANNER_RE.search(e.details["user_agent"])]
        if scans:
            tools = sorted({SCANNER_RE.search(e.details["user_agent"]).group(1).lower() for e in scans})
            findings.append(Finding(
                rule_id="WEB-006",
                title="Known scanner user agent",
                severity="medium",
                source="web",
                ip=ip,
                first_seen=scans[0].ts,
                last_seen=scans[-1].ts,
                count=len(scans),
                outcome=UNKNOWN,
                description=f"{len(scans)} request(s) sent by {', '.join(tools)}.",
                evidence=sample_evidence(scans),
                details={"tools": tools},
            ))

        not_found = [e for e in requests if e.status == "404"]
        if len(not_found) >= config.notfound_threshold:
            start, end = densest_window(not_found, config.web_window)
            burst = not_found[start:end]
            if len(burst) >= config.notfound_threshold:
                findings.append(Finding(
                    rule_id="WEB-007",
                    title="Content discovery (directory brute force)",
                    severity="medium",
                    source="web",
                    ip=ip,
                    first_seen=burst[0].ts,
                    last_seen=burst[-1].ts,
                    count=len(burst),
                    outcome=UNKNOWN,
                    description=(f"{len(burst)} requests returned 404 within "
                                 f"{int(config.web_window.total_seconds() // 60)} minutes."),
                    evidence=sample_evidence(burst),
                ))

    return findings
