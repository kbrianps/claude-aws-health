from __future__ import annotations

from datetime import datetime, timezone

from ..model import Claim, Finding
from ..prices import HOURS_PER_MONTH, price, source
from ..registry import call, check

LIST_CLUSTERS = call("eks", "ListClusters", keep="clusters", result_key="clusters")
DESCRIBE_CLUSTER = call(
    "eks", "DescribeCluster",
    keep="cluster.{name: name, arn: arn, version: version, status: status, upgradePolicy: upgradePolicy, tags: tags}",
    per_item=("eks", "ListClusters", "[]", "name"),
)
CLUSTER_VERSIONS = call(
    "eks", "DescribeClusterVersions",
    keep="clusterVersions[].{version: clusterVersion, status: versionStatus, "
         "endOfStandardSupportDate: endOfStandardSupportDate, endOfExtendedSupportDate: endOfExtendedSupportDate, "
         "defaultVersion: defaultVersion}",
    result_key="clusterVersions",
)


def _parse(ts: str) -> datetime | None:
    if not ts:
        return None
    d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@check(
    id="eks-extended-support",
    category="outdated",
    severity="high",
    title={"en": "EKS cluster leaving standard support", "pt-BR": "Cluster EKS saindo do suporte padrão"},
    requires=[LIST_CLUSTERS, DESCRIBE_CLUSTER, CLUSTER_VERSIONS],
    catalog_ids=["eks-extended-support-billing", "eks-cluster-extended-support-billing"],
)
def run(snap, ctx):
    findings = []
    extra_hour = price("eks_cluster_extended_hour") - price("eks_cluster_standard_hour")
    for region in snap.regions:
        versions = {v["version"]: v for v in snap.items(CLUSTER_VERSIONS, region) if v}
        for name, c in snap.per_item(DESCRIBE_CLUSTER, region).items():
            if not c:
                continue
            v = versions.get(c.get("version"), {})
            end_std = _parse(v.get("endOfStandardSupportDate", ""))
            if not end_std:
                continue
            days = (end_std - ctx.now).days
            policy = (c.get("upgradePolicy") or {}).get("supportType", "EXTENDED")
            in_extended = days < 0
            if days > 120:
                continue
            monthly = round(extra_hour * HOURS_PER_MONTH, 2) if policy == "EXTENDED" else None
            severity = "high" if (in_extended or days <= 45) else "medium"
            when = end_std.strftime("%Y-%m-%d %H:%M UTC")
            if policy == "EXTENDED":
                consequence_en = f"After {when} the control plane bills US${price('eks_cluster_extended_hour'):.2f}/h instead of US${price('eks_cluster_standard_hour'):.2f}/h, about +US${monthly:,.0f}/month, with no warning."
                consequence_pt = f"Depois de {when}, o control plane passa a custar US$ {price('eks_cluster_extended_hour'):.2f}/h em vez de US$ {price('eks_cluster_standard_hour'):.2f}/h, cerca de +US$ {monthly:,.0f}/mês, sem aviso."
            else:
                consequence_en = f"The upgrade policy is STANDARD, so AWS upgrades the cluster automatically after {when}, on its own schedule."
                consequence_pt = f"A política de upgrade é STANDARD, então a AWS atualiza o cluster sozinha depois de {when}, no horário dela."
            findings.append(Finding(
                check_id="eks-extended-support",
                resource=c.get("arn") or name,
                severity=severity,
                category="outdated",
                region=region,
                text={
                    "en": {
                        "title": f"EKS cluster {name} runs Kubernetes {c.get('version')}, which "
                                 + ("is already in extended support" if in_extended else f"leaves standard support in {days} days"),
                        "what": f"Kubernetes {c.get('version')} ends standard support on {when}. The cluster upgrade policy is {policy}.",
                        "risk": consequence_en,
                        "fix": "Upgrade to the next minor version (test staging first), and set upgradePolicy.supportType=STANDARD in IaC so a missed date forces an upgrade instead of a surcharge.",
                    },
                    "pt-BR": {
                        "title": f"O cluster EKS {name} roda Kubernetes {c.get('version')}, que "
                                 + ("já está no suporte estendido" if in_extended else f"sai do suporte padrão em {days} dias"),
                        "what": f"O Kubernetes {c.get('version')} sai do suporte padrão em {when}. A política de upgrade do cluster é {policy}.",
                        "risk": consequence_pt,
                        "fix": "Subir para a próxima versão menor (staging primeiro) e definir upgradePolicy.supportType=STANDARD no IaC, para que um prazo perdido force o upgrade em vez de virar cobrança.",
                    },
                },
                claims=[
                    Claim(f"eks:DescribeCluster@{region}", f"{name}.version", c.get("version")),
                    Claim(f"eks:DescribeCluster@{region}", f"{name}.upgradePolicy.supportType", policy),
                    Claim(f"eks:DescribeClusterVersions@{region}", f"{c.get('version')}.endOfStandardSupportDate", v.get("endOfStandardSupportDate")),
                ],
                monthly_usd=monthly,
                usd_calc=(f"(US${price('eks_cluster_extended_hour'):.2f} - US${price('eks_cluster_standard_hour'):.2f}) x {HOURS_PER_MONTH} h = US${monthly:,.2f}/month ({source('eks_cluster_extended_hour')})" if monthly else ""),
                deadline=end_std.isoformat(),
                verify=[
                    f"aws eks describe-cluster --name {name} --region {region} --query 'cluster.[version,upgradePolicy.supportType]' --output text",
                    f"aws eks describe-cluster-versions --region {region} --cluster-versions {c.get('version')} --query 'clusterVersions[].[clusterVersion,endOfStandardSupportDate,endOfExtendedSupportDate]' --output table",
                    f"aws eks list-insights --cluster-name {name} --region {region} --filter categories=UPGRADE_READINESS --query 'insights[].[name,insightStatus.status]' --output table",
                ],
            ))
    return findings
