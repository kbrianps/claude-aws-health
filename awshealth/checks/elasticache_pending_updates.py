from __future__ import annotations

from ..calls_compute import CACHE_UPDATE_ACTIONS, parse_time
from ..model import Claim, Finding
from ..registry import check

SEVERITY = {"critical": "high", "important": "medium"}


def _day(action: dict) -> str:
    d = parse_time(action.get("apply_by"))
    return d.strftime("%Y-%m-%d") if d else "n/a"


@check(
    id="elasticache-pending-updates",
    category="security",
    severity="medium",
    title={"en": "ElastiCache service updates not applied",
           "pt-BR": "Atualizações de serviço do ElastiCache pendentes"},
    requires=[CACHE_UPDATE_ACTIONS],
    catalog_ids=["elasticache-service-updates-pending"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        by_target: dict[tuple[str, str], list[dict]] = {}
        for a in snap.items(CACHE_UPDATE_ACTIONS, region):
            if not a or a.get("severity") not in SEVERITY:
                continue
            if a.get("group"):
                target = ("replication-group", a["group"])
            elif a.get("cluster"):
                target = ("cluster", a["cluster"])
            else:
                continue
            by_target.setdefault(target, []).append(a)
        for (kind, rid), actions in sorted(by_target.items()):
            actions.sort(key=lambda a: (a.get("apply_by") or "9999", a.get("update") or ""))
            severity = "high" if any(a["severity"] == "critical" for a in actions) else "medium"
            dates = [d for d in (parse_time(a.get("apply_by")) for a in actions) if d]
            first = min(dates) if dates else None
            overdue = bool(first and first <= ctx.now)
            listing = "; ".join(f"{a.get('update')} ({a['severity']}, {a.get('status')}, apply by {_day(a)})"
                                for a in actions)
            when = first.strftime("%Y-%m-%d") if first else ""
            due_en = (f"The recommended apply-by date {when} has passed." if overdue
                      else f"The first recommended apply-by date is {when}." if first else "")
            due_pt = (f"A data recomendada de aplicação {when} já passou." if overdue
                      else f"A primeira data recomendada de aplicação é {when}." if first else "")
            flag = "--replication-group-ids" if kind == "replication-group" else "--cache-cluster-ids"
            resource = (f"arn:aws:elasticache:{region}:{snap.account_id}:"
                        f"{'replicationgroup' if kind == 'replication-group' else 'cluster'}:{rid}")
            findings.append(Finding(
                check_id="elasticache-pending-updates",
                resource=resource,
                severity=severity,
                category="security",
                region=region,
                text={
                    "en": {
                        "title": f"ElastiCache {kind} {rid} has {len(actions)} pending service update"
                                 f"{'s' if len(actions) > 1 else ''}",
                        "what": f"Pending updates: {listing}. {due_en}".strip(),
                        "risk": "Critical and important service updates carry security and stability fixes. Past "
                                "the recommended date the update is outside the SLA and AWS may apply it on its own.",
                        "fix": "Apply the update in a maintenance window with batch-apply-update-action, starting with "
                               "staging, or let the next maintenance window apply it if that is before the date.",
                    },
                    "pt-BR": {
                        "title": f"O {kind} {rid} do ElastiCache tem {len(actions)} atualização"
                                 f"{'ões' if len(actions) > 1 else ''} de serviço pendente"
                                 f"{'s' if len(actions) > 1 else ''}",
                        "what": f"Atualizações pendentes: {listing}. {due_pt}".strip(),
                        "risk": "Atualizações críticas e importantes trazem correções de segurança e estabilidade. "
                                "Depois da data recomendada a atualização sai do SLA e a AWS pode aplicar sozinha.",
                        "fix": "Aplicar a atualização numa janela de manutenção com batch-apply-update-action, "
                               "começando por staging, ou deixar a próxima janela aplicar se for antes da data.",
                    },
                },
                claims=[Claim(f"elasticache:DescribeUpdateActions@{region}",
                              f"{rid}.{a.get('update')}.ServiceUpdateRecommendedApplyByDate", a.get("apply_by"))
                        for a in actions],
                deadline=first.isoformat() if first else "",
                verify=[
                    f"aws elasticache describe-update-actions {flag} {rid} --region {region} "
                    "--update-action-status not-applied waiting-to-start in-progress "
                    "--query 'UpdateActions[].[ServiceUpdateName,ServiceUpdateSeverity,UpdateActionStatus,"
                    "ServiceUpdateRecommendedApplyByDate]' --output table",
                ],
            ))
    return findings
