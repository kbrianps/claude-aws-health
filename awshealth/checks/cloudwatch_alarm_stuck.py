from __future__ import annotations

import re

from ..calls_security import ALARMS, days_since
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "cloudwatch-alarm-stuck"
_HEARTBEAT = re.compile(r"heartbeat|watchdog|deadman|canary", re.I)


def _stuck(a, now) -> int:
    state = a.get("state")
    if state not in ("ALARM", "INSUFFICIENT_DATA") or _HEARTBEAT.search(a.get("name", "")):
        return 0
    if state == "ALARM" and a.get("enabled") is False:
        return 0
    if state == "INSUFFICIENT_DATA" and a.get("treat_missing") in ("notBreaching", "ignore"):
        return 0
    days = days_since(a.get("updated"), now) or 0
    return days if days > 30 else 0


@check(
    id=CHECK_ID,
    category="errors",
    severity="low",
    title={"en": "CloudWatch alarms stuck for over 30 days",
           "pt-BR": "Alarmes do CloudWatch parados há mais de 30 dias"},
    requires=[ALARMS],
    catalog_ids=["cloudwatch-alarm-stuck-in-alarm", "cloudwatch-alarm-insufficient-data-long",
                 "cloudwatch-alarms-orphan"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        stuck = [(a, d) for a in snap.items(ALARMS, region) if a for d in [_stuck(a, ctx.now)] if d]
        if not stuck:
            continue
        stuck.sort(key=lambda x: -x[1])
        alarm = sum(1 for a, _ in stuck if a["state"] == "ALARM")
        nodata = len(stuck) - alarm
        sample = ", ".join(f"{a['name']} ({a['state']}, {d} days)" for a, d in stuck[:5])
        sample_pt = ", ".join(f"{a['name']} ({a['state']}, {d} dias)" for a, d in stuck[:5])
        more_en = f" and {len(stuck) - 5} more" if len(stuck) > 5 else ""
        more_pt = f" e mais {len(stuck) - 5}" if len(stuck) > 5 else ""
        findings.append(Finding(
            check_id=CHECK_ID,
            resource=f"cloudwatch-alarms/{region}",
            resources=[a.get("arn") or a["name"] for a, _ in stuck],
            severity="low",
            category="errors",
            region=region,
            text={
                "en": {
                    "title": f"{len(stuck)} CloudWatch alarm(s) in {region} stuck for over 30 days",
                    "what": f"{alarm} alarm(s) have been in ALARM and {nodata} in INSUFFICIENT_DATA for over 30 "
                            f"days: {sample}{more_en}.",
                    "risk": "Alarms that never change train people to ignore them, and INSUFFICIENT_DATA often "
                            "means the watched resource was deleted, so real failures go unnoticed.",
                    "fix": "Fix the condition, adjust the threshold or TreatMissingData, or delete alarms that "
                           "watch deleted resources.",
                },
                "pt-BR": {
                    "title": f"{len(stuck)} alarme(s) do CloudWatch em {region} parados há mais de 30 dias",
                    "what": f"{alarm} alarme(s) estão em ALARM e {nodata} em INSUFFICIENT_DATA há mais de 30 dias: "
                            f"{sample_pt}{more_pt}.",
                    "risk": "Alarmes que nunca mudam ensinam as pessoas a ignorá-los, e INSUFFICIENT_DATA muitas "
                            "vezes indica que o recurso observado foi apagado, então falhas reais passam batido.",
                    "fix": "Corrigir a causa, ajustar o limite ou o TreatMissingData, ou apagar alarmes que "
                           "observam recursos apagados.",
                },
            },
            claims=[Claim(f"cloudwatch:DescribeAlarms@{region}", f"{a['name']}.StateUpdatedTimestamp", a.get("updated"))
                    for a, _ in stuck[:10]],
            verify=[
                f"aws cloudwatch describe-alarms --region {region} --state-value ALARM --query "
                "'MetricAlarms[].[AlarmName,StateUpdatedTimestamp]' --output table",
                f"aws cloudwatch describe-alarms --region {region} --state-value INSUFFICIENT_DATA --query "
                "'MetricAlarms[].[AlarmName,StateUpdatedTimestamp,TreatMissingData]' --output table",
            ],
        ))
    return findings
