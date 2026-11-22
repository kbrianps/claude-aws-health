from __future__ import annotations

from datetime import datetime, timezone

from ..model import Claim, Finding
from ..prices import HOURS_PER_MONTH, price, source
from ..registry import call, check

LIST_CLUSTERS = call("eks", "ListClusters", keep="clusters", result_key="clusters")
DESCRIBE_CLUSTER = call(
    "eks",
    "DescribeCluster",
    keep="cluster.{name: name, arn: arn, version: version, status: status, upgradePolicy: upgradePolicy, tags: tags}",
    per_item=("eks", "ListClusters", "[]", "name"),
)
CLUSTER_VERSIONS = call(
    "eks",
    "DescribeClusterVersions",
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


def _text(name, version, days, when, policy, monthly):
    ext, std = price("eks_cluster_extended_hour"), price("eks_cluster_standard_hour")
    in_extended = days < 0
    if policy == "EXTENDED":
        risk_en = (
            f"After {when} the control plane bills US${ext:.2f}/h instead of US${std:.2f}/h, "
            f"about +US${monthly:,.0f}/month, with no warning."
        )
        risk_pt = (
            f"Depois de {when}, o control plane passa a custar US$ {ext:.2f}/h em vez de US$ {std:.2f}/h, "
            f"cerca de +US$ {monthly:,.0f}/mês, sem aviso."
        )
    else:
        risk_en = f"The upgrade policy is STANDARD, so AWS upgrades the cluster automatically after {when}."
        risk_pt = f"A política de upgrade é STANDARD, então a AWS atualiza o cluster sozinha depois de {when}."
    state_en = "is already in extended support" if in_extended else f"leaves standard support in {days} days"
    state_pt = "já está no suporte estendido" if in_extended else f"sai do suporte padrão em {days} dias"
    return {
        "en": {
            "title": f"EKS cluster {name} runs Kubernetes {version}, which {state_en}",
            "what": f"Kubernetes {version} ends standard support on {when}. The cluster upgrade policy is {policy}.",
            "risk": risk_en,
            "fix": (
                "Upgrade to the next minor version (staging first), and set upgradePolicy.supportType=STANDARD "
                "in IaC so a missed date forces an upgrade instead of a surcharge."
            ),
        },
        "pt-BR": {
            "title": f"O cluster EKS {name} roda Kubernetes {version}, que {state_pt}",
            "what": f"O Kubernetes {version} sai do suporte padrão em {when}. A política de upgrade é {policy}.",
            "risk": risk_pt,
            "fix": (
                "Subir para a próxima versão menor (staging primeiro) e definir upgradePolicy.supportType=STANDARD "
                "no IaC, para que um prazo perdido force o upgrade em vez de virar cobrança."
            ),
        },
    }


def _verify(name, region, version):
    return [
        f"aws eks describe-cluster --name {name} --region {region} "
        "--query 'cluster.[version,upgradePolicy.supportType]' --output text",
        f"aws eks describe-cluster-versions --region {region} --cluster-versions {version} "
        "--query 'clusterVersions[].[clusterVersion,endOfStandardSupportDate,endOfExtendedSupportDate]' --output table",
        f"aws eks list-insights --cluster-name {name} --region {region} --filter categories=UPGRADE_READINESS "
        "--query 'insights[].[name,insightStatus.status]' --output table",
    ]


@check(
    id="eks-extended-support",
    category="outdated",
    severity="high",
    title={"en": "EKS cluster leaving standard support", "pt-BR": "Cluster EKS saindo do suporte padrão"},
    requires=[LIST_CLUSTERS, DESCRIBE_CLUSTER, CLUSTER_VERSIONS],
    catalog_ids=["eks-cluster-extended-support-billing", "eks-cluster-end-of-extended-support-forced-upgrade"],
)
def run(snap, ctx):
    findings = []
    ext, std = price("eks_cluster_extended_hour"), price("eks_cluster_standard_hour")
    for region in snap.regions:
        versions = {v["version"]: v for v in snap.items(CLUSTER_VERSIONS, region) if v}
        for name, c in snap.per_item(DESCRIBE_CLUSTER, region).items():
            if not c or "__error__" in c:
                continue
            version = c.get("version")
            v = versions.get(version, {})
            end_std = _parse(v.get("endOfStandardSupportDate", ""))
            if not end_std:
                continue
            days = (end_std - ctx.now).days
            if days > 120:
                continue
            policy = (c.get("upgradePolicy") or {}).get("supportType", "EXTENDED")
            monthly = round((ext - std) * HOURS_PER_MONTH, 2) if policy == "EXTENDED" else None
            when = end_std.strftime("%Y-%m-%d %H:%M UTC")
            usd_calc = ""
            if monthly:
                usd_calc = (
                    f"(US${ext:.2f} - US${std:.2f}) x {HOURS_PER_MONTH} h = US${monthly:,.2f}/month "
                    f"({source('eks_cluster_extended_hour')})"
                )
            findings.append(
                Finding(
                    check_id="eks-extended-support",
                    resource=c.get("arn") or name,
                    severity="high" if days <= 45 else "medium",
                    category="outdated",
                    region=region,
                    text=_text(name, version, days, when, policy, monthly),
                    claims=[
                        Claim(f"eks:DescribeCluster@{region}", f"{name}.version", version),
                        Claim(f"eks:DescribeCluster@{region}", f"{name}.upgradePolicy.supportType", policy),
                        Claim(
                            f"eks:DescribeClusterVersions@{region}",
                            f"{version}.endOfStandardSupportDate",
                            v.get("endOfStandardSupportDate"),
                        ),
                    ],
                    monthly_usd=monthly,
                    usd_calc=usd_calc,
                    deadline=end_std.isoformat(),
                    verify=_verify(name, region, version),
                )
            )
    return findings
