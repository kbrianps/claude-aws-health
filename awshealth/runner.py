from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .model import Finding
from .registry import CheckSpec, load_checks
from .snapshot import Snapshot


@dataclass
class Context:
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    account_id: str = ""
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    check_id: str
    status: str
    findings: list[Finding]
    detail: str = ""


def coverage_status(spec: CheckSpec, snap: Snapshot) -> tuple[str, str]:
    missing, denied = [], []
    for c in spec.requires:
        statuses = {snap.status(c, r) for r in snap.regions_for(c)}
        if statuses <= {"missing"}:
            missing.append(c.key)
        elif statuses <= {"denied", "missing", "unsupported"} and "denied" in statuses:
            denied.append(c.key)
    unavailable = len(missing) + len(denied)
    if unavailable == len(spec.requires):
        if denied:
            return "no_access", "denied: " + ", ".join(denied)
        return "not_collected", "missing: " + ", ".join(missing)
    parts = []
    if denied:
        parts.append("denied: " + ", ".join(denied))
    if missing:
        parts.append("missing: " + ", ".join(missing))
    return "ran", ("partial, " + "; ".join(parts)) if parts else ""


def run_checks(snap: Snapshot, ctx: Context | None = None, only: list[str] | None = None) -> list[CheckResult]:
    ctx = ctx or Context(account_id=snap.account_id)
    if not ctx.account_id:
        ctx.account_id = snap.account_id
    results = []
    for cid, spec in sorted(load_checks().items()):
        if only and cid not in only:
            continue
        status, detail = coverage_status(spec, snap)
        if status != "ran":
            results.append(CheckResult(cid, status, [], detail))
            continue
        try:
            found = spec.fn(snap, ctx) or []
        except Exception as exc:
            results.append(CheckResult(cid, "error", [], f"{type(exc).__name__}: {exc}"))
            continue
        for f in found:
            if f.check_id != cid:
                raise ValueError(f"check {cid} emitted a finding with check_id {f.check_id}")
        status = "finding" if found else ("partial" if "denied" in detail else "ok")
        results.append(CheckResult(cid, status, found, detail))
    return results
