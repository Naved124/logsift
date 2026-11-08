"""SSH and sudo detections."""

from __future__ import annotations

from ..models import FAILED, SUCCEEDED, UNKNOWN, Event, Finding, sample_evidence
from . import Config, densest_window, group_by


def detect(events: list[Event], config: Config) -> list[Finding]:
    events = sorted((e for e in events if e.source == "auth"), key=lambda e: e.ts)
    failures = [e for e in events if e.action == "ssh_failed"]
    successes = [e for e in events if e.action == "ssh_accepted"]
    findings: list[Finding] = []

    successes_by_ip = group_by(successes, lambda e: e.ip)

    for ip, fails in group_by(failures, lambda e: e.ip).items():
        start, end = densest_window(fails, config.auth_window)
        burst = fails[start:end]
        users = {e.user for e in burst}
        later_success = [s for s in successes_by_ip.get(ip, []) if s.ts >= fails[0].ts]
        outcome = SUCCEEDED if later_success else FAILED

        if len(users) >= config.spray_users:
            findings.append(Finding(
                rule_id="AUTH-002",
                title="SSH password spraying",
                severity="high",
                source="auth",
                ip=ip,
                first_seen=burst[0].ts,
                last_seen=burst[-1].ts,
                count=len(burst),
                outcome=outcome,
                description=(f"{len(burst)} failed SSH logins for {len(users)} different usernames "
                             f"within {int(config.auth_window.total_seconds() // 60)} minutes."),
                evidence=sample_evidence(burst),
                details={"usernames": sorted(u for u in users if u)[:20], "total_failures": len(fails)},
            ))
        elif len(burst) >= config.bruteforce_threshold:
            target = max(users, key=lambda u: sum(1 for e in burst if e.user == u))
            findings.append(Finding(
                rule_id="AUTH-001",
                title="SSH brute force",
                severity="high",
                source="auth",
                ip=ip,
                user=target,
                first_seen=burst[0].ts,
                last_seen=burst[-1].ts,
                count=len(burst),
                outcome=outcome,
                description=(f"{len(burst)} failed SSH logins within "
                             f"{int(config.auth_window.total_seconds() // 60)} minutes, mostly for '{target}'."),
                evidence=sample_evidence(burst),
                details={"usernames": sorted(u for u in users if u)[:20], "total_failures": len(fails)},
            ))

    # A success that follows failures from the same IP is the line that matters most.
    fails_by_ip = group_by(failures, lambda e: e.ip)
    for success in successes:
        prior = [f for f in fails_by_ip.get(success.ip, []) if f.ts <= success.ts]
        if len(prior) >= config.success_after_failures:
            findings.append(Finding(
                rule_id="AUTH-003",
                title="Successful SSH login after repeated failures",
                severity="critical",
                source="auth",
                ip=success.ip,
                user=success.user,
                first_seen=prior[0].ts,
                last_seen=success.ts,
                count=len(prior) + 1,
                outcome=SUCCEEDED,
                description=(f"'{success.user}' logged in via {success.details.get('method')} after "
                             f"{len(prior)} failed attempts from the same IP. Treat the account as compromised "
                             "until proven otherwise."),
                evidence=sample_evidence(prior[-3:] + [success]),
                details={"prior_failures": len(prior), "method": success.details.get("method")},
            ))
        elif success.user == "root":
            findings.append(Finding(
                rule_id="AUTH-004",
                title="Direct root login over SSH",
                severity="medium",
                source="auth",
                ip=success.ip,
                user="root",
                first_seen=success.ts,
                last_seen=success.ts,
                count=1,
                outcome=SUCCEEDED,
                description="root logged in directly over SSH. PermitRootLogin should normally be disabled.",
                evidence=[success.raw],
            ))

    sudo_failures = [e for e in events if e.action == "sudo_failed"]
    for user, fails in group_by(sudo_failures, lambda e: e.user).items():
        findings.append(Finding(
            rule_id="AUTH-005",
            title="Failed sudo authentication",
            severity="low" if len(fails) < 3 else "medium",
            source="auth",
            ip=None,
            user=user,
            first_seen=fails[0].ts,
            last_seen=fails[-1].ts,
            count=len(fails),
            outcome=UNKNOWN,
            description=f"'{user}' failed sudo authentication {len(fails)} time(s).",
            evidence=sample_evidence(fails),
        ))

    return findings
