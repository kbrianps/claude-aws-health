from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .model import Finding
from .runner import Context, run_checks
from .snapshot import Snapshot


def default_runs_dir() -> Path:
    base = os.environ.get("AWSHEALTH_HOME") or os.environ.get("CLAUDE_PLUGIN_DATA")
    if base:
        return Path(base) / "runs"
    return Path.home() / ".local" / "share" / "awshealth" / "runs"


def new_run_dir(parent: Path | None = None) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d = (parent or default_runs_dir()) / stamp
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def latest_run_dir() -> Path:
    runs = sorted(p for p in default_runs_dir().glob("*") if (p / "snapshot.json").exists())
    if not runs:
        sys.exit("no runs found; run `awshealth collect` first or pass --run")
    return runs[-1]


def load_findings(run: Path) -> list[Finding]:
    out: list[Finding] = []
    for path in [run / "findings.json", *sorted((run / "imported").glob("*.json"))]:
        if path.exists():
            out += [Finding.from_dict(d) for d in json.loads(path.read_text())]
    return out


def cmd_collect(a: argparse.Namespace) -> None:
    from .collect.engine import collect

    run = Path(a.out) if a.out else new_run_dir()
    regions = a.regions.split(",") if a.regions else None
    collect(profile=a.profile, regions=regions, run_dir=run, metrics=a.metrics, cost=a.cost)
    print(run)


def cmd_check(a: argparse.Namespace) -> None:
    run = Path(a.run) if a.run else latest_run_dir()
    snap = Snapshot.load(run)
    results = run_checks(snap, Context(account_id=snap.account_id), only=a.only.split(",") if a.only else None)
    findings = [f.to_dict() for r in results for f in r.findings]
    (run / "findings.json").write_text(json.dumps(findings, indent=1))
    (run / "checks.json").write_text(
        json.dumps(
            [
                {"check_id": r.check_id, "status": r.status, "detail": r.detail, "findings": len(r.findings)}
                for r in results
            ],
            indent=1,
        )
    )
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print(f"{len(findings)} findings from {len(results)} checks {counts} -> {run}")


def cmd_import(a: argparse.Namespace) -> None:
    from .importers import load_any

    run = Path(a.run) if a.run else latest_run_dir()
    found = load_any(Path(a.file), kind=a.kind)
    (run / "imported").mkdir(exist_ok=True)
    out = run / "imported" / f"{a.kind or 'auto'}-{Path(a.file).stem}.json"
    out.write_text(json.dumps([f.to_dict() for f in found], indent=1))
    print(f"{len(found)} findings imported -> {out}")


def cmd_render(a: argparse.Namespace) -> None:
    from .render import render_all

    run = Path(a.run) if a.run else latest_run_dir()
    paths = render_all(run, lang=a.lang)
    for p in paths:
        print(p)


def cmd_verify(a: argparse.Namespace) -> None:
    run = Path(a.run) if a.run else latest_run_dir()
    for f in load_findings(run):
        if not a.uid or f.uid in a.uid or f.check_id in a.uid:
            print(f"# {f.uid} {f.t('title')}")
            for c in f.verify:
                print(c)


def cmd_demo(a: argparse.Namespace) -> None:
    from .demo import run_demo

    for p in run_demo(Path(a.out) if a.out else new_run_dir(), lang=a.lang):
        print(p)


def cmd_catalog(a: argparse.Namespace) -> None:
    from .catalog import print_catalog

    print_catalog(category=a.category, fmt=a.format)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="awshealth", description="Read-only AWS health audit.")
    p.add_argument("--version", action="version", version=f"awshealth {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("collect", help="read the account into a local snapshot (needs AWS credentials)")
    s.add_argument("--profile", default=os.environ.get("AWS_PROFILE"))
    s.add_argument("--regions", help="comma-separated; default: every enabled region")
    s.add_argument("--out", help="run directory; default: a new one under the runs dir")
    s.add_argument("--metrics", action="store_true", help="allow billed CloudWatch metric reads")
    s.add_argument("--cost", action="store_true", help="allow Cost Explorer reads (US$0.01 per request)")
    s.set_defaults(fn=cmd_collect)

    s = sub.add_parser("check", help="run deterministic checks on a snapshot (no AWS access)")
    s.add_argument("--run")
    s.add_argument("--only", help="comma-separated check ids")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("import", help="import findings from Prowler OCSF or Cost Optimization Hub exports")
    s.add_argument("file")
    s.add_argument("--kind", choices=["prowler", "coh"])
    s.add_argument("--run")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("render", help="write report.html, report.md, deadlines.ics and more (no AWS access)")
    s.add_argument("--run")
    s.add_argument("--lang", default="en", choices=["en", "pt-BR"])
    s.set_defaults(fn=cmd_render)

    s = sub.add_parser("verify", help="print read-only aws CLI commands that re-check findings")
    s.add_argument("uid", nargs="*")
    s.add_argument("--run")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("demo", help="run the full pipeline on a fictional account (no AWS access)")
    s.add_argument("--out")
    s.add_argument("--lang", default="en", choices=["en", "pt-BR"])
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("catalog", help="list the 282-check health catalog and what covers each check")
    s.add_argument("--category")
    s.add_argument("--format", default="table", choices=["table", "json"])
    s.set_defaults(fn=cmd_catalog)

    a = p.parse_args(argv)
    try:
        a.fn(a)
    except (FileNotFoundError, ValueError) as exc:
        sys.exit(f"awshealth: {exc}")


if __name__ == "__main__":
    main()
