from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..adjust import Killed, apply
from ..catalog import catalog_coverage
from ..model import SEVERITIES, Finding

CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
OWNER_KEYS = ("owner", "team", "contact", "maintainer", "squad")
PROBLEM_STATUSES = ("denied", "throttled", "error")


@dataclass
class Run:
    path: Path
    meta: dict[str, Any]
    findings: list[Finding]
    killed: list[Killed]
    questions: list[Finding]
    coverage: dict[str, Any]
    api_problems: list[dict[str, str]]
    calls: int | None
    blocked: int
    now: datetime
    version: str = __version__
    sources: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)


def cap(value: Any, n: int = 2000) -> str:
    s = CONTROL.sub("", "" if value is None else str(value))
    return s if len(s) <= n else s[: n - 3] + "..."


def parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def utc_text(ts: str, with_time: bool = True) -> str:
    d = parse_ts(ts)
    if not d:
        return cap(ts, 64)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC" if with_time else "%Y-%m-%d")


def days_until(ts: str, now: datetime) -> int | None:
    d = parse_ts(ts)
    return None if not d else (d - now).days


def fmt_usd(v: float, lang: str = "en") -> str:
    s = f"{v:,.0f}" if abs(v) >= 100 else f"{v:,.2f}"
    if lang == "pt-BR":
        return "US$ " + s.replace(",", "_").replace(".", ",").replace("_", ".")
    return "US$" + s


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def rank_key(f: Finding) -> tuple:
    d = parse_ts(f.deadline)
    return (sev_rank(f.severity), -(f.monthly_usd or 0), d.timestamp() if d else float("inf"), f.uid)


def owner_text(f: Finding, lang: str) -> str:
    return f.owner_question.get(lang) or f.owner_question.get("en") or ""


def _owner_from(value: Any) -> str:
    if isinstance(value, dict):
        for k, v in value.items():
            if str(k).lower() in OWNER_KEYS and v:
                return str(v)
    if isinstance(value, list):
        for t in value:
            if isinstance(t, dict) and str(t.get("Key", t.get("key", ""))).lower() in OWNER_KEYS:
                v = t.get("Value", t.get("value"))
                if v:
                    return str(v)
    return ""


def owner_hint(f: Finding) -> str:
    for c in f.claims:
        last = re.split(r"[.\[\]]", c.path.lower().strip("]"))[-1]
        if last in OWNER_KEYS and isinstance(c.value, str) and c.value:
            return c.value
        hint = _owner_from(c.value)
        if hint:
            return hint
    return ""


def _load_findings(run: Path) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for path in [run / "findings.json", *sorted((run / "imported").glob("*.json"))]:
        if not path.exists():
            continue
        for d in json.loads(path.read_text(encoding="utf-8")):
            f = Finding.from_dict(d)
            if f.uid not in seen:
                seen.add(f.uid)
                out.append(f)
    return out


def _snapshot(run: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    path = run / "snapshot.json"
    if not path.exists():
        return {}, []
    raw = json.loads(path.read_text(encoding="utf-8"))
    problems = []
    for key, by_region in sorted((raw.get("data") or {}).items()):
        for region, entry in sorted(by_region.items()):
            if isinstance(entry, dict) and entry.get("status") in PROBLEM_STATUSES:
                problems.append({"call": key, "region": region, "status": entry["status"],
                                 "error": cap(entry.get("error", ""), 300)})
    return raw.get("meta") or {}, problems


def _ledger(run: Path) -> tuple[int | None, int]:
    collect = {}
    if (run / "collect.json").exists():
        collect = json.loads((run / "collect.json").read_text(encoding="utf-8"))
    calls = None
    if (run / "ledger.jsonl").exists():
        calls = sum(1 for line in (run / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if line.strip())
    elif isinstance(collect.get("calls"), int):
        calls = collect["calls"]
    elif isinstance(collect.get("calls"), dict):
        calls = sum(v for v in collect["calls"].values() if isinstance(v, int))
    blocked = collect.get("blocked", 0)
    return calls, blocked if isinstance(blocked, int) else 0


def load_run(run_dir: Path, now: datetime | None = None) -> Run:
    run_dir = Path(run_dir)
    findings = _load_findings(run_dir)
    kept, killed, questions = apply(findings, run_dir / "adjustments.jsonl")
    kept.sort(key=rank_key)
    meta, problems = _snapshot(run_dir)
    calls, blocked = _ledger(run_dir)
    return Run(
        path=run_dir,
        meta=meta,
        findings=kept,
        killed=killed,
        questions=sorted(questions, key=rank_key),
        coverage=catalog_coverage(run_dir),
        api_problems=problems,
        calls=calls,
        blocked=blocked,
        now=now or datetime.now(timezone.utc),
        sources=sorted({f.source for f in kept}),
        regions=sorted({f.region for f in kept}),
    )


def nearest_deadline(run: Run) -> Finding | None:
    upcoming = [(parse_ts(f.deadline), f) for f in run.findings if parse_ts(f.deadline)]
    upcoming = [(d, f) for d, f in upcoming if d >= run.now]
    return min(upcoming, key=lambda x: x[0])[1] if upcoming else None


def total_usd(run: Run) -> float:
    return round(sum(f.monthly_usd or 0 for f in run.findings), 2)


def high_count(run: Run) -> int:
    return sum(1 for f in run.findings if f.severity in ("critical", "high"))


def dated(run: Run) -> list[Finding]:
    return sorted((f for f in run.findings if parse_ts(f.deadline)), key=lambda f: parse_ts(f.deadline))


def by_owner(run: Run, unassigned: str) -> list[tuple[str, list[Finding]]]:
    groups: dict[str, list[Finding]] = {}
    for f in run.questions:
        groups.setdefault(cap(owner_hint(f), 120) or unassigned, []).append(f)
    return sorted(groups.items(), key=lambda kv: (kv[0] == unassigned, kv[0].lower()))
