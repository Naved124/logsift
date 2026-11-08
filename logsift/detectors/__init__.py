"""Detection rules. Each module exposes detect(events, config) -> list[Finding]."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from ..models import Event


@dataclass
class Config:
    # SSH
    bruteforce_threshold: int = 10          # failed logins from one IP inside the window
    spray_users: int = 5                    # distinct usernames tried from one IP inside the window
    auth_window: timedelta = timedelta(minutes=10)
    success_after_failures: int = 3         # failures that make a later success from the same IP suspicious
    # Web
    notfound_threshold: int = 50            # 404s from one IP inside the window (content discovery)
    web_window: timedelta = timedelta(minutes=5)
    # CloudTrail
    failed_console_threshold: int = 3
    access_denied_threshold: int = 8
    cloudtrail_window: timedelta = timedelta(minutes=10)


def densest_window(events: list[Event], window: timedelta) -> tuple[int, int]:
    """Return (start, end) indexes of the window holding the most events.

    `events` must be sorted by time. `end` is exclusive.
    """
    best = (0, 0)
    start = 0
    for end in range(len(events)):
        while events[end].ts - events[start].ts > window:
            start += 1
        if end + 1 - start > best[1] - best[0]:
            best = (start, end + 1)
    return best


def group_by(events: list[Event], key) -> dict:
    groups: dict = {}
    for event in events:
        groups.setdefault(key(event), []).append(event)
    return groups
