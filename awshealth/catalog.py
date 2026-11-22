from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from .registry import load_checks

STATUS_ORDER = ("finding", "error", "no_access", "partial", "not_collected", "ok")
COVERAGE_STATUSES = ("ok", "finding", "partial", "no_access", "not_collected", "error", "agent")


def load_catalog() -> list[dict]:
    return json.loads(resources.files("awshealth").joinpath("data/catalog.json").read_text(encoding="utf-8"))


def covering_checks() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for cid, spec in sorted(load_checks().items()):
        for catalog_id in spec.catalog_ids:
            out.setdefault(catalog_id, []).append(cid)
    return out


def _check_statuses(run_dir: Path | None) -> dict[str, str]:
    if not run_dir or not (Path(run_dir) / "checks.json").exists():
        return {}
    return {c["check_id"]: c["status"] for c in json.loads((Path(run_dir) / "checks.json").read_text())}


def catalog_coverage(run_dir: Path | None) -> dict:
    catalog = load_catalog()
    covers = covering_checks()
    statuses = _check_statuses(run_dir)
    known = {e["id"] for e in catalog}
    entries = []
    counts = dict.fromkeys(COVERAGE_STATUSES, 0)
    for e in catalog:
        checks = covers.get(e["id"], [])
        if not checks:
            status = "agent"
        else:
            found = {statuses.get(c, "not_collected") for c in checks}
            status = next((s for s in STATUS_ORDER if s in found), "error")
        counts[status] += 1
        entries.append({"id": e["id"], "category": e["category"], "service": e["service"], "title": e["title"],
                        "severity": e["severity"], "status": status, "checks": checks})
    return {
        "total": len(catalog),
        "deterministic": sum(1 for e in entries if e["checks"]),
        "checked": counts["ok"] + counts["finding"],
        "counts": counts,
        "entries": entries,
        "unknown_ids": sorted(set(covers) - known),
    }


def print_catalog(category: str | None = None, fmt: str = "table") -> None:
    covers = covering_checks()
    catalog = load_catalog()
    categories = sorted({e["category"] for e in catalog})
    if category and category not in categories:
        raise ValueError(f"unknown category {category!r}; valid categories: {', '.join(categories)}")
    rows = [dict(e, covered_by=covers.get(e["id"], [])) for e in catalog if not category or e["category"] == category]
    if fmt == "json":
        print(json.dumps(rows, indent=1, ensure_ascii=False))
        return
    id_w = max([len(r["id"]) for r in rows] + [2])
    print(f"{'id':<{id_w}}  {'category':<10}  {'severity':<8}  covered by")
    for r in rows:
        by = ", ".join(r["covered_by"]) or "agent (deep mode)"
        print(f"{r['id']:<{id_w}}  {r['category']:<10}  {r['severity']:<8}  {by}")
        print(f"{'':<{id_w}}  {r['title']}")
    covered = sum(1 for r in rows if r["covered_by"])
    print(f"\n{len(rows)} entries, {covered} covered by deterministic checks, {len(rows) - covered} left to deep mode")
