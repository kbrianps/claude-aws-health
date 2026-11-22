from __future__ import annotations

from ..calls_compute import LOG_GROUPS
from ..model import Claim, Finding
from ..prices import price, source
from ..registry import check

GIB = 1024 ** 3


@check(
    id="logs-no-retention",
    category="cost",
    severity="medium",
    title={"en": "Large log groups that never expire", "pt-BR": "Log groups grandes que nunca expiram"},
    requires=[LOG_GROUPS],
    catalog_ids=["cloudwatch-logs-no-retention"],
)
def run(snap, ctx):
    findings = []
    gb_price = price("cloudwatch_logs_gb_month")
    for region in snap.regions:
        groups = sorted(
            (g for g in snap.items(LOG_GROUPS, region) if g and not g.get("retention") and (g.get("bytes") or 0) > GIB),
            key=lambda g: (-(g.get("bytes") or 0), g["name"]),
        )
        if not groups:
            continue
        total_gb = round(sum(g["bytes"] for g in groups) / GIB, 1)
        monthly = round(total_gb * gb_price, 2)
        top = groups[:10]
        top_list = ", ".join(f"{g['name']} ({g['bytes'] / GIB:,.1f} GB)" for g in top)
        plural = "s" if len(groups) > 1 else ""
        findings.append(Finding(
            check_id="logs-no-retention",
            resource=f"arn:aws:logs:{region}:{snap.account_id}:log-group:no-retention",
            resources=[g.get("arn") or g["name"] for g in groups],
            severity="medium",
            category="cost",
            region=region,
            text={
                "en": {
                    "title": f"{len(groups)} log group{plural} in {region} keep {total_gb:,.1f} GB forever",
                    "what": f"{len(groups)} log groups over 1 GB have no retention set (Never expire). "
                            f"Largest: {top_list}.",
                    "risk": f"Stored logs cost about US${monthly:,.2f}/month today and grow every month.",
                    "fix": "Set a retention (for example 30 or 90 days) with put-retention-policy, in IaC. Keep "
                           "longer only for audit logs that a law or contract requires, and check subscription "
                           "filters first if the data is exported elsewhere.",
                },
                "pt-BR": {
                    "title": f"{len(groups)} log group{plural} em {region} guardam {total_gb:,.1f} GB para sempre",
                    "what": f"{len(groups)} log groups com mais de 1 GB não têm retenção (Never expire). "
                            f"Maiores: {top_list}.",
                    "risk": f"Os logs guardados custam cerca de US$ {monthly:,.2f}/mês hoje e crescem todo mês.",
                    "fix": "Definir uma retenção (por exemplo 30 ou 90 dias) com put-retention-policy, no IaC. Guardar "
                           "por mais tempo só logs de auditoria exigidos por lei ou contrato, e ver os subscription "
                           "filters antes se os dados são exportados para outro lugar.",
                },
            },
            claims=[Claim(f"logs:DescribeLogGroups@{region}", f"{g['name']}.storedBytes", g["bytes"]) for g in top],
            monthly_usd=monthly,
            usd_calc=f"{total_gb:,.1f} GB stored x US${gb_price}/GB-month = US${monthly:,.2f}/month "
                     f"({source('cloudwatch_logs_gb_month')})",
            verify=[
                f"aws logs describe-log-groups --region {region} "
                "--query 'logGroups[?!retentionInDays].[logGroupName,storedBytes]' --output table",
                f"aws logs describe-subscription-filters --log-group-name {top[0]['name']} --region {region} "
                "--query 'subscriptionFilters[].[filterName,destinationArn]' --output table",
            ],
        ))
    return findings
