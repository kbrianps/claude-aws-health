from __future__ import annotations

from ..calls_security import FUNCTIONS, RULE_TARGETS, RULES
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "eventbridge-target-missing"


def _function(arn: str) -> tuple[str, str, str] | None:
    parts = arn.split(":")
    if len(parts) < 7 or parts[2] != "lambda" or parts[5] != "function":
        return None
    return parts[3], parts[4], parts[6]


@check(
    id=CHECK_ID,
    category="errors",
    severity="medium",
    title={"en": "EventBridge rule targets a deleted Lambda function",
           "pt-BR": "Regra do EventBridge aponta para uma função Lambda apagada"},
    requires=[RULES, RULE_TARGETS, FUNCTIONS],
    catalog_ids=["messaging-orphan-sns-sqs", "eventbridge-failed-invocations"],
)
def run(snap, ctx):
    names = {r: {f.get("name") for f in snap.items(FUNCTIONS, r) if f} for r in snap.regions
             if snap.status(FUNCTIONS, r) == "ok"}
    findings = []
    for region in snap.regions:
        rules = {r["name"]: r for r in snap.items(RULES, region) if r and r.get("state") == "ENABLED"}
        for rule_name, targets in snap.per_item(RULE_TARGETS, region).items():
            rule = rules.get(rule_name)
            if not rule or not isinstance(targets, list):
                continue
            gone = []
            for t in targets:
                fn = _function(t.get("arn") or "")
                if not fn:
                    continue
                fn_region, account, fn_name = fn
                if account == ctx.account_id and fn_region in names and fn_name not in names[fn_region]:
                    gone.append(t["arn"])
            if not gone:
                continue
            gone_txt = ", ".join(gone)
            findings.append(Finding(
                check_id=CHECK_ID,
                resource=rule.get("arn") or rule_name,
                resources=[rule.get("arn") or rule_name] + gone,
                severity="medium",
                category="errors",
                region=region,
                text={
                    "en": {
                        "title": f"EventBridge rule {rule_name} is enabled but targets {len(gone)} deleted Lambda "
                                 "function(s)",
                        "what": f"The enabled rule {rule_name} in {region} sends events to {gone_txt}, which no "
                                "longer exist.",
                        "risk": "Every matching event fails delivery. The scheduled job or integration behind this "
                                "rule silently stopped.",
                        "fix": "Point the target at the current function or delete the rule. If the rule still "
                               "matters, add a dead-letter queue to the target so failures are visible.",
                    },
                    "pt-BR": {
                        "title": f"A regra {rule_name} do EventBridge está ativa mas aponta para {len(gone)} "
                                 "função(ões) Lambda apagada(s)",
                        "what": f"A regra ativa {rule_name} em {region} envia eventos para {gone_txt}, que não "
                                "existem mais.",
                        "risk": "Todo evento que casa com a regra falha na entrega. A rotina ou integração por trás "
                                "dela parou sem aviso.",
                        "fix": "Apontar o alvo para a função atual ou apagar a regra. Se a regra ainda importa, "
                               "colocar uma fila de dead-letter no alvo para que as falhas apareçam.",
                    },
                },
                claims=[Claim(f"events:ListTargetsByRule@{region}", f"{rule_name}.Targets[].Arn", gone)]
                + [Claim(f"lambda:ListFunctions@{_function(a)[0]}",
                         f"Functions[?FunctionName=='{_function(a)[2]}']", [])
                   for a in gone],
                verify=[
                    f"aws events list-targets-by-rule --rule {rule_name} --region {region} --query "
                    "'Targets[].[Id,Arn]' --output table",
                ] + [f"aws lambda list-functions --region {_function(a)[0]} --query "
                     f"\"Functions[?FunctionName=='{_function(a)[2]}'].FunctionArn\" --output text"
                     for a in gone[:2]],
            ))
    return findings
