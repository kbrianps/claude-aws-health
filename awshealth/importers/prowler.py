from __future__ import annotations

import re
from typing import Any

from ..model import Claim, Finding

SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info",
            "info": "info"}

CATEGORY_BY_TAG = {
    "resilience": "resilience",
    "redundancy": "resilience",
    "backup": "resilience",
    "cost-optimization": "cost",
    "costoptimization": "cost",
}

CATEGORY_BY_SERVICE = {
    "backup": "resilience",
    "drs": "resilience",
    "organizations": "governance",
    "account": "governance",
    "config": "governance",
    "cloudtrail": "governance",
    "servicequotas": "quota",
    "trustedadvisor": "governance",
}


def is_prowler(data: Any) -> bool:
    return isinstance(data, list) and any(isinstance(d, dict) and "finding_info" in d for d in data)


def _category(item: dict, service: str) -> str:
    tags = [str(c).lower() for c in (item.get("unmapped") or {}).get("categories") or []]
    for t in tags:
        if t in CATEGORY_BY_TAG:
            return CATEGORY_BY_TAG[t]
    return CATEGORY_BY_SERVICE.get(service, "security")


def _service(item: dict, resource: dict, event_code: str) -> str:
    group = (resource.get("group") or {}).get("name") or ""
    service = str(group or (item.get("metadata") or {}).get("service") or event_code.split("_")[0])
    return service.lower()


def to_finding(item: dict) -> Finding | None:
    if str(item.get("status_code", "")).upper() != "FAIL":
        return None
    info = item.get("finding_info") or {}
    meta = item.get("metadata") or {}
    event_code = str(meta.get("event_code") or info.get("uid") or "unknown")
    check_id = "prowler-" + re.sub(r"[^A-Za-z0-9_.-]", "-", event_code)
    resources = [r for r in item.get("resources") or [] if isinstance(r, dict)]
    first = resources[0] if resources else {}
    cloud = item.get("cloud") or {}
    region = str(first.get("region") or cloud.get("region") or "global")
    resource = str(first.get("uid") or first.get("name") or (cloud.get("account") or {}).get("uid") or info.get("uid"))
    title = str(info.get("title") or event_code)
    detail = str(item.get("status_detail") or info.get("desc") or "")
    risk = str(item.get("risk_details") or "")
    fix = str((item.get("remediation") or {}).get("desc") or "")
    what_en = "Imported from Prowler." + (f" {detail}" if detail else "")
    severity = SEVERITY.get(str(item.get("severity", "")).lower(), "medium")
    return Finding(
        check_id=check_id,
        resource=resource,
        severity=severity,
        category=_category(item, _service(item, first, event_code)),
        region=region,
        text={
            "en": {"title": title, "what": what_en, "risk": risk, "fix": fix},
            "pt-BR": {"title": title, "what": "Importado do Prowler." + (f"\n{detail}" if detail else ""),
                      "risk": risk, "fix": fix},
        },
        claims=[Claim("prowler", str(info.get("uid") or event_code), detail or item.get("status_code"))],
        resources=[str(r.get("uid") or r.get("name")) for r in resources if r.get("uid") or r.get("name")],
        source="prowler",
    )


def load(data: list) -> list[Finding]:
    return [f for f in (to_finding(d) for d in data if isinstance(d, dict)) if f]
