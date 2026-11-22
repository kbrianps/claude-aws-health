from __future__ import annotations

from ..calls_security import ANOMALY_MONITORS, BUDGET_HISTORY, BUDGETS, days_since, parse_ts
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "cost-guardrails-missing"


def exceeded_days(history, now) -> int:
    rows = [h for h in history or [] if isinstance(h, dict) and h.get("start")]
    rows.sort(key=lambda h: parse_ts(h["start"]))
    start = None
    for h in reversed(rows):
        if float(h.get("actual") or 0) <= float(h.get("budgeted") or 0):
            break
        start = h["start"]
    return (days_since(start, now) or 0) if start else 0


@check(
    id=CHECK_ID,
    category="governance",
    severity="medium",
    title={"en": "No working cost guardrails", "pt-BR": "Sem proteção de custo funcionando"},
    requires=[BUDGETS, BUDGET_HISTORY, ANOMALY_MONITORS],
    catalog_ids=["budgets-exceeded"],
)
def run(snap, ctx):
    region = snap.home_region
    problems_en, problems_pt, claims, verify = [], [], [], []
    if snap.status(BUDGETS, region) == "ok":
        budgets = [b for b in snap.items(BUDGETS, region) if b]
        verify.append(f"aws budgets describe-budgets --account-id {ctx.account_id} --region us-east-1 --query "
                      "'Budgets[].[BudgetName,BudgetLimit.Amount,CalculatedSpend.ActualSpend.Amount]' --output table")
        if not budgets:
            problems_en.append("the account has no AWS Budgets")
            problems_pt.append("a conta não tem nenhum AWS Budget")
            claims.append(Claim(f"budgets:DescribeBudgets@{region}", "length(Budgets)", 0))
        else:
            history = snap.per_item(BUDGET_HISTORY, region)
            over = {b["name"]: exceeded_days(history.get(b["name"]), ctx.now) for b in budgets}
            if all(d >= 30 for d in over.values()):
                names = ", ".join(f"{n} ({d} days)" for n, d in over.items())
                names_pt = ", ".join(f"{n} ({d} dias)" for n, d in over.items())
                problems_en.append("every budget has been over its limit for 30+ days, so its alerts are ignored or "
                                   f"its limit is stale: {names}")
                problems_pt.append("todos os budgets estão acima do limite há 30+ dias, então os alertas são "
                                   f"ignorados ou o limite está desatualizado: {names_pt}")
                claims += [Claim(f"budgets:DescribeBudgetPerformanceHistory@{region}", f"{n}.days_over_limit", d)
                           for n, d in over.items()]
    if snap.status(ANOMALY_MONITORS, region) == "ok" and not snap.items(ANOMALY_MONITORS, region):
        problems_en.append("Cost Anomaly Detection has no monitor")
        problems_pt.append("o Cost Anomaly Detection não tem nenhum monitor")
        claims.append(Claim(f"ce:GetAnomalyMonitors@{region}", "length(AnomalyMonitors)", 0))
        verify.append("aws ce get-anomaly-monitors --region us-east-1 --query "
                      "'AnomalyMonitors[].[MonitorName,MonitorType]' --output table")
    if not problems_en:
        return []
    return [Finding(
        check_id=CHECK_ID,
        resource=f"arn:aws:budgets::{ctx.account_id}:guardrails",
        severity="medium",
        category="governance",
        region="global",
        text={
            "en": {
                "title": "Nothing warns anyone when AWS spend jumps",
                "what": "In this account " + "; ".join(problems_en) + ".",
                "risk": "A runaway job, a leaked key mining crypto or a forgotten test cluster runs for weeks "
                        "before the invoice shows it.",
                "fix": "Create a monthly cost budget with alerts at 80% and 100% of a realistic limit, and a Cost "
                       "Anomaly Detection monitor for AWS services with an e-mail or Slack subscription.",
            },
            "pt-BR": {
                "title": "Nada avisa ninguém quando o gasto na AWS dispara",
                "what": "Nesta conta, " + "; ".join(problems_pt) + ".",
                "risk": "Um job descontrolado, uma chave vazada minerando cripto ou um cluster de teste esquecido "
                        "roda por semanas até a fatura mostrar.",
                "fix": "Criar um budget mensal de custo com alertas em 80% e 100% de um limite realista, e um "
                       "monitor do Cost Anomaly Detection para os serviços da AWS com assinatura por e-mail ou "
                       "Slack.",
            },
        },
        claims=claims,
        verify=verify,
    )]
