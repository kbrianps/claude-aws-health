from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

from .render import render_all
from .render.common import parse_ts
from .runner import Context, run_checks
from .snapshot import Snapshot

OPTIONAL = ("adjustments.jsonl", "collect.json", "ledger.jsonl")


def demo_dir() -> Path:
    return Path(str(resources.files("awshealth").joinpath("data/demo")))


def run_demo(out_dir: Path, lang: str = "en") -> list[Path]:
    src = demo_dir()
    if not (src / "snapshot.json").exists():
        raise FileNotFoundError(f"demo snapshot not found at {src / 'snapshot.json'}; the demo fixture is missing")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src / "snapshot.json", out_dir / "snapshot.json")
    for name in OPTIONAL:
        if (src / name).exists():
            shutil.copyfile(src / name, out_dir / name)
    snap = Snapshot.load(out_dir)
    now = parse_ts(snap.collected_at) or datetime.now(timezone.utc)
    ctx = Context(now=now, account_id=snap.account_id)
    results = run_checks(snap, ctx)
    (out_dir / "findings.json").write_text(json.dumps([f.to_dict() for r in results for f in r.findings], indent=1))
    (out_dir / "checks.json").write_text(json.dumps(
        [{"check_id": r.check_id, "status": r.status, "detail": r.detail, "findings": len(r.findings)}
         for r in results], indent=1))
    return render_all(out_dir, lang=lang, now=now)
