from __future__ import annotations

from shlex import quote

from ..calls_compute import LISTENERS, LOAD_BALANCERS, TARGET_GROUPS, TARGET_HEALTH, parse_time
from ..model import Claim, Finding
from ..prices import HOURS_PER_MONTH, price, source
from ..registry import check
from . import counted

HOURLY_KEYS = {"application": "alb_hour", "network": "nlb_hour"}
NON_FORWARD = {"redirect", "fixed-response"}
MIN_AGE_DAYS = 7


@check(
    id="elb-no-targets",
    category="zombie",
    severity="medium",
    title={"en": "Load balancer with no registered targets", "pt-BR": "Load balancer sem targets registrados"},
    requires=[LOAD_BALANCERS, TARGET_GROUPS, TARGET_HEALTH, LISTENERS],
    catalog_ids=["elb-idle-load-balancer", "elb-empty-target-group"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        health = snap.per_item(TARGET_HEALTH, region)
        listeners = snap.per_item(LISTENERS, region)
        groups: dict[str, list[dict]] = {}
        for tg in snap.items(TARGET_GROUPS, region):
            for lb_arn in (tg or {}).get("lbs") or []:
                groups.setdefault(lb_arn, []).append(tg)
        for lb in snap.items(LOAD_BALANCERS, region):
            if not lb or lb.get("state") not in ("active", "active_impaired"):
                continue
            created = parse_time(lb.get("created"))
            if created and (ctx.now - created).days < MIN_AGE_DAYS:
                continue
            arn, name, lb_type = lb["arn"], lb.get("name"), lb.get("type")
            tgs = groups.get(arn, [])
            if any(tg["arn"] not in health for tg in tgs):
                continue
            if any(health[tg["arn"]] for tg in tgs):
                continue
            lb_listeners = listeners.get(arn)
            actions = {a for li in lb_listeners or [] for a in li.get("actions") or []}
            redirect_only = not tgs and bool(actions) and actions <= NON_FORWARD
            key = HOURLY_KEYS.get(lb_type)
            monthly = round(price(key) * HOURS_PER_MONTH, 2) if key else None
            if tgs:
                tg_names = ", ".join(tg.get("name") or tg["arn"] for tg in tgs)
                what_en = (f"Load balancer {name} ({lb_type}, {lb.get('scheme')}) has "
                           f"{counted(len(tgs), 'target group', 'target groups')} "
                           f"({tg_names}) and none has a registered target.")
                what_pt = (f"O load balancer {name} ({lb_type}, {lb.get('scheme')}) tem "
                           f"{counted(len(tgs), 'target group', 'target groups')} "
                           f"({tg_names}) e nenhum tem target registrado.")
            else:
                what_en = f"Load balancer {name} ({lb_type}, {lb.get('scheme')}) has no target group."
                what_pt = f"O load balancer {name} ({lb_type}, {lb.get('scheme')}) não tem target group."
                if lb_listeners is not None and not lb_listeners:
                    what_en += " It has no listeners either."
                    what_pt += " Ele também não tem listeners."
                elif redirect_only:
                    what_en += " Its listeners only redirect or return a fixed response."
                    what_pt += " Os listeners dele só redirecionam ou devolvem resposta fixa."
            cost_en = f" The fixed charge alone is about US${monthly:,.2f}/month." if monthly is not None else ""
            cost_pt = f" Só a cobrança fixa dá cerca de US$ {monthly:,.2f}/mês." if monthly is not None else ""
            question = {}
            if redirect_only:
                question = {
                    "en": f"Load balancer {name} only redirects or returns fixed responses. Is that redirect still "
                          "needed, for example http to https or an old domain?",
                    "pt-BR": f"O load balancer {name} só redireciona ou devolve resposta fixa. Esse redirecionamento "
                             "ainda é necessário, por exemplo http para https ou um domínio antigo?",
                }
            first_tg = tgs[0]["arn"] if tgs else ""
            verify = [
                f"aws elbv2 describe-target-groups --load-balancer-arn {quote(arn)} --region {quote(region)} "
                "--query 'TargetGroups[].[TargetGroupName,TargetType,TargetGroupArn]' --output table",
                f"aws elbv2 describe-listeners --load-balancer-arn {quote(arn)} --region {quote(region)} "
                "--query 'Listeners[].[Port,Protocol,DefaultActions[0].Type]' --output table",
            ]
            if first_tg:
                verify.append(
                    f"aws elbv2 describe-target-health --target-group-arn {quote(first_tg)} --region {quote(region)} "
                    "--query 'TargetHealthDescriptions[].[Target.Id,TargetHealth.State]' --output table")
            findings.append(Finding(
                check_id="elb-no-targets",
                resource=arn,
                severity="low" if redirect_only else "medium",
                category="zombie",
                region=region,
                text={
                    "en": {
                        "title": f"Load balancer {name} has no registered targets",
                        "what": what_en,
                        "risk": f"It serves no backend but bills every hour.{cost_en}",
                        "fix": "Confirm it is not a DR standby or pre-created for a cutover. If a Kubernetes ingress "
                               "controller owns it, delete the Ingress or Service instead of the load balancer. "
                               "Otherwise delete it.",
                    },
                    "pt-BR": {
                        "title": f"O load balancer {name} não tem targets registrados",
                        "what": what_pt,
                        "risk": f"Ele não atende nenhum backend, mas cobra toda hora.{cost_pt}",
                        "fix": "Confirmar que não é standby de DR nem foi criado antes de uma migração. Se um ingress "
                               "controller do Kubernetes é o dono, apagar o Ingress ou o Service em vez do load "
                               "balancer. Senão, apagar.",
                    },
                },
                claims=[Claim(f"elbv2:DescribeTargetGroups@{region}", f"{arn}.TargetGroups", [tg["arn"] for tg in tgs])]
                + [Claim(f"elbv2:DescribeTargetHealth@{region}", tg["arn"], health[tg["arn"]]) for tg in tgs],
                monthly_usd=monthly,
                usd_calc=(f"US${price(key)}/h x {HOURS_PER_MONTH} h = US${monthly:,.2f}/month, fixed charge only, "
                          f"LCU usage not included ({source(key)})") if monthly is not None else "",
                owner_question=question,
                confidence="medium" if redirect_only else "high",
                verify=verify,
            ))
    return findings
