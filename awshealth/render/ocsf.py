from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding
from .common import Run, parse_ts

OCSF_VERSION = "1.3.0"
SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_NAME = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
STATUS = {"open": (1, "New"), "confirmed": (1, "New"), "question": (1, "New"), "killed": (3, "Suppressed")}


def detection(f: Finding, run: Run, reason: str = "") -> dict:
    sev = SEVERITY_ID.get(f.severity, 0)
    status_id, status = STATUS.get(f.status, (99, "Other"))
    collected = parse_ts(run.meta.get("collected_at", "")) or run.now
    out = {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        "severity_id": sev,
        "severity": SEVERITY_NAME.get(sev, "Unknown"),
        "status_id": status_id,
        "status": status,
        "time": int(collected.timestamp() * 1000),
        "message": f.t("title"),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "awshealth", "vendor_name": "awshealth", "version": run.version},
        },
        "finding_info": {
            "uid": f.uid,
            "title": f.t("title"),
            "desc": f.t("what"),
            "types": [f.category],
            "analytic": {"uid": f.check_id, "name": f.check_id, "type_id": 1, "type": "Rule"},
        },
        "cloud": {"provider": "AWS", "region": f.region,
                  "account": {"uid": run.meta.get("account_id", ""), "type": "AWS Account", "type_id": 10}},
        "resources": [{"uid": r, "region": f.region} for r in f.resources],
        "remediation": {"desc": f.t("fix")},
        "unmapped": {
            "source": f.source,
            "risk": f.t("risk"),
            "monthly_usd": f.monthly_usd,
            "usd_calc": f.usd_calc,
            "deadline": f.deadline,
            "owner_question": f.owner_question.get("en", ""),
            "evidence": [{"source": c.source, "path": c.path, "value": c.value} for c in f.claims],
            "notes": f.notes,
        },
    }
    if reason:
        out["status_detail"] = reason
    return out


def write(run: Run) -> Path:
    items = [detection(f, run) for f in run.findings]
    items += [detection(k.finding, run, k.reason) for k in run.killed]
    path = run.path / "findings.ocsf.json"
    path.write_text(json.dumps(items, indent=1, default=str), encoding="utf-8")
    return path
