from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .model import Finding
from .registry import Call, load_checks
from .runner import Context
from .snapshot import Snapshot

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def snap_with(
    calls: dict[Call, dict[str, Any]], regions: list[str] | None = None, account_id: str = "111122223333"
) -> Snapshot:
    snap = Snapshot(account_id, regions or ["us-east-1"], "us-east-1", NOW.isoformat())
    for c, by_region in calls.items():
        for region, value in by_region.items():
            if isinstance(value, dict) and value.get("__status__"):
                snap.put(c, region, value["__status__"])
            elif isinstance(value, dict) and "__by_id__" in value:
                snap.put(c, region, "ok", by_id=value["__by_id__"])
            else:
                snap.put(c, region, "ok", value=value)
    return snap


def run_one(check_id: str, snap: Snapshot, now: datetime = NOW) -> list[Finding]:
    spec = load_checks()[check_id]
    return spec.fn(snap, Context(now=now, account_id=snap.account_id)) or []
