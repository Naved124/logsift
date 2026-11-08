"""AWS CloudTrail detections."""

from __future__ import annotations

from typing import Any, Iterator

from ..models import FAILED, SUCCEEDED, UNKNOWN, Event, Finding, sample_evidence
from . import Config, densest_window, group_by

LOGGING_TAMPER = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
                  "DeleteFlowLogs", "DeleteDetector", "DisableSecurityHub"}
IAM_CHANGES = {"CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
               "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy",
               "PutGroupPolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion", "AddUserToGroup",
               "UpdateAssumeRolePolicy", "CreateRole", "DeactivateMFADevice", "DeleteVirtualMFADevice"}
DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Client.UnauthorizedOperation"}
WORLD = {"0.0.0.0/0", "::/0"}


def _single(event: Event, rule_id: str, title: str, severity: str, description: str,
            outcome: str = SUCCEEDED, details: dict[str, Any] | None = None) -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=severity, source="cloudtrail", ip=event.ip, user=event.user,
        first_seen=event.ts, last_seen=event.ts, count=1, outcome=outcome, description=description,
        evidence=[event.raw], details=details or {},
    )


def _world_open_ranges(request: dict[str, Any]) -> Iterator[str]:
    """Yield port descriptions for ingress rules open to the whole internet."""
    permissions = (request.get("ipPermissions") or {}).get("items") or []
    for perm in permissions:
        ranges = [r.get("cidrIp") for r in ((perm.get("ipRanges") or {}).get("items") or [])]
        ranges += [r.get("cidrIpv6") for r in ((perm.get("ipv6Ranges") or {}).get("items") or [])]
        for cidr in ranges:
            if cidr in WORLD:
                low, high = perm.get("fromPort"), perm.get("toPort")
                proto = perm.get("ipProtocol")
                if proto == "-1":
                    yield f"all traffic from {cidr}"
                else:
                    ports = str(low) if low == high else f"{low}-{high}"
                    yield f"{proto}/{ports} from {cidr}"
    # The older flat form of the API call.
    if request.get("cidrIp") in WORLD:
        yield f"{request.get('ipProtocol')}/{request.get('fromPort')}-{request.get('toPort')} from {request['cidrIp']}"


def detect(events: list[Event], config: Config) -> list[Finding]:
    events = sorted((e for e in events if e.source == "cloudtrail"), key=lambda e: e.ts)
    findings: list[Finding] = []

    for event in events:
        ok = event.status == "success"
        name = event.action

        if event.details.get("identity_type") == "Root" and event.details.get("event_type") != "AwsServiceEvent":
            findings.append(_single(
                event, "CT-001", "Root account used", "high",
                f"The root user called {name}. Root should only be used for the few tasks that require it.",
                outcome=SUCCEEDED if ok else FAILED,
            ))

        if name == "ConsoleLogin" and ok and event.details["additional"].get("MFAUsed") == "No":
            findings.append(_single(
                event, "CT-002", "Console login without MFA", "high",
                f"'{event.user}' signed in to the AWS console without MFA.",
            ))

        if name in LOGGING_TAMPER:
            findings.append(_single(
                event, "CT-003", "Logging or monitoring disabled", "critical",
                f"{name} was called by '{event.user}'. Attackers do this to hide what they do next.",
                outcome=SUCCEEDED if ok else FAILED,
                details={"request": event.details["request"]},
            ))

        if name in IAM_CHANGES:
            target = (event.details["request"] or {}).get("userName") or (event.details["request"] or {}).get("roleName")
            severity = "high" if event.details.get("identity_type") == "Root" or name in {
                "CreateAccessKey", "DeactivateMFADevice", "UpdateAssumeRolePolicy"} else "medium"
            findings.append(_single(
                event, "CT-004", "IAM change", severity,
                f"'{event.user}' called {name}" + (f" on '{target}'." if target else "."),
                outcome=SUCCEEDED if ok else FAILED,
                details={"event": name, "target": target, "request": event.details["request"]},
            ))

        if name in {"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"}:
            opened = list(_world_open_ranges(event.details["request"] or {}))
            if opened:
                group = (event.details["request"] or {}).get("groupId")
                findings.append(_single(
                    event, "CT-005", "Security group opened to the internet", "high",
                    f"'{event.user}' allowed {', '.join(opened)}" + (f" on {group}." if group else "."),
                    outcome=SUCCEEDED if ok else FAILED,
                    details={"group_id": group, "rules": opened},
                ))

    failed_logins = [e for e in events if e.action == "ConsoleLogin" and e.status == "failure"]
    for ip, fails in group_by(failed_logins, lambda e: e.ip).items():
        start, end = densest_window(fails, config.cloudtrail_window)
        burst = fails[start:end]
        if len(burst) >= config.failed_console_threshold:
            later = [e for e in events if e.action == "ConsoleLogin" and e.status == "success"
                     and e.ip == ip and e.ts >= burst[0].ts]
            findings.append(Finding(
                rule_id="CT-006", title="Repeated failed console logins", severity="critical" if later else "medium",
                source="cloudtrail", ip=ip, user=burst[0].user, first_seen=burst[0].ts,
                last_seen=(later[0].ts if later else burst[-1].ts), count=len(burst),
                outcome=SUCCEEDED if later else FAILED,
                description=f"{len(burst)} failed AWS console logins from {ip}"
                            + (f", followed by a successful login as '{later[0].user}'." if later else "."),
                evidence=sample_evidence(burst + later[:1]),
            ))

    denied = [e for e in events if e.status in DENIED_CODES]
    for principal, hits in group_by(denied, lambda e: e.user).items():
        start, end = densest_window(hits, config.cloudtrail_window)
        burst = hits[start:end]
        if len(burst) >= config.access_denied_threshold:
            calls = sorted({e.action for e in burst})
            findings.append(Finding(
                rule_id="CT-007", title="Burst of access-denied API calls", severity="medium",
                source="cloudtrail", ip=burst[-1].ip, user=principal, first_seen=burst[0].ts,
                last_seen=burst[-1].ts, count=len(burst), outcome=UNKNOWN,
                description=(f"'{principal}' was denied {len(burst)} times across {len(calls)} API call(s). "
                             "This pattern is typical of someone enumerating what stolen credentials can do."),
                evidence=sample_evidence(burst),
                details={"api_calls": calls[:20]},
            ))

    return findings
