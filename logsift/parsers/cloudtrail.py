"""Parser for AWS CloudTrail logs.

Accepts the three shapes CloudTrail data usually arrives in:
  * a delivered log file:            {"Records": [ {...}, {...} ]}
  * a JSON array of events            [ {...}, {...} ]  (e.g. saved from the console or an API call)
  * JSON Lines, one event per line   (e.g. exported from Athena or CloudWatch Logs)
  * `aws cloudtrail lookup-events` output: {"Events": [{"CloudTrailEvent": "<json string>"}]}
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import Event
from . import read_text


def _principal(identity: dict[str, Any]) -> str | None:
    kind = identity.get("type")
    if kind == "Root":
        return "root"
    if identity.get("userName"):
        return identity["userName"]
    arn = identity.get("arn")
    if arn:
        # arn:aws:sts::123456789012:assumed-role/RoleName/session -> RoleName/session
        return arn.split(":", 5)[-1].split("/", 1)[-1] if "/" in arn else arn
    return kind


def record_to_event(record: dict[str, Any]) -> Event | None:
    try:
        ts = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        name = record["eventName"]
    except (KeyError, ValueError, AttributeError):
        return None

    identity = record.get("userIdentity") or {}
    error = record.get("errorCode")
    response = record.get("responseElements") or {}
    if name == "ConsoleLogin":
        status = "success" if response.get("ConsoleLogin") == "Success" else "failure"
    else:
        status = error or "success"

    return Event(
        ts=ts,
        source="cloudtrail",
        action=name,
        ip=record.get("sourceIPAddress"),
        user=_principal(identity),
        status=status,
        raw=json.dumps(
            {k: record.get(k) for k in ("eventTime", "eventSource", "eventName", "sourceIPAddress", "errorCode")
             if record.get(k) is not None}
            | {"principal": _principal(identity)},
            separators=(",", ":"),
        ),
        details={
            "event_source": record.get("eventSource"),
            "region": record.get("awsRegion"),
            "identity_type": identity.get("type"),
            "arn": identity.get("arn"),
            "error_code": error,
            "error_message": record.get("errorMessage"),
            "user_agent": record.get("userAgent"),
            "request": record.get("requestParameters") or {},
            "response": response,
            "additional": record.get("additionalEventData") or {},
            "event_type": record.get("eventType"),
        },
    )


def load_records(text: str) -> list[dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
        return records
    if isinstance(data, dict):
        if "Records" in data:
            return list(data["Records"])
        if "Events" in data:
            # `aws cloudtrail lookup-events` wraps each event as a JSON string.
            return [json.loads(e["CloudTrailEvent"]) if isinstance(e.get("CloudTrailEvent"), str) else e
                    for e in data["Events"]]
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("unrecognised CloudTrail JSON layout")


def parse_file(path: str | Path) -> tuple[list[Event], int]:
    records = load_records(read_text(path))
    events: list[Event] = []
    skipped = 0
    for record in records:
        event = record_to_event(record) if isinstance(record, dict) else None
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped
