from __future__ import annotations

from ..calls_compute import (
    ECS_CLUSTERS,
    FUNCTIONS,
    GUARDDUTY_DETECTORS,
    INSTANCES,
    LOAD_BALANCERS,
    RDS_INSTANCES,
    VOLUMES,
)
from ..model import Claim, Finding
from ..registry import check
from .eks_extended_support import LIST_CLUSTERS

INVENTORY = {
    "ec2:DescribeInstances": INSTANCES,
    "ec2:DescribeVolumes": VOLUMES,
    "lambda:ListFunctions": FUNCTIONS,
    "rds:DescribeDBInstances": RDS_INSTANCES,
    "ecs:ListClusters": ECS_CLUSTERS,
    "eks:ListClusters": LIST_CLUSTERS,
    "elbv2:DescribeLoadBalancers": LOAD_BALANCERS,
}


@check(
    id="unused-regions-open",
    category="security",
    severity="high",
    title={"en": "Unused regions with no threat detection", "pt-BR": "Regiões sem uso e sem detecção de ameaças"},
    requires=[*INVENTORY.values(), GUARDDUTY_DETECTORS],
    catalog_ids=["resourceexplorer-inventory-unexpected-regions", "guardduty-disabled-or-unaddressed"],
)
def run(snap, ctx):
    empty = []
    for region in snap.regions:
        calls = [*INVENTORY.values(), GUARDDUTY_DETECTORS]
        if any(snap.status(c, region) != "ok" for c in calls):
            continue
        if any(snap.items(c, region) for c in calls):
            continue
        empty.append(region)
    if not empty:
        return []
    listed = ", ".join(empty)
    first = empty[0]
    verb_en, verb_pt = (("s have", "regiões ativas não têm") if len(empty) > 1
                        else (" has", "região ativa não tem"))
    return [Finding(
        check_id="unused-regions-open",
        resource=f"arn:aws:iam::{snap.account_id}:root/unused-regions",
        resources=[f"arn:aws:guardduty:{r}:{snap.account_id}:detector" for r in empty],
        severity="high",
        category="security",
        region="global",
        text={
            "en": {
                "title": f"{len(empty)} enabled region{verb_en} no resources and no GuardDuty: {listed}",
                "what": f"In {listed} there are no EC2 instances, EBS volumes, Lambda functions, RDS instances, ECS "
                        "clusters, EKS clusters or load balancers, and GuardDuty has no detector.",
                "risk": "A leaked access key can launch instances (often crypto miners) in a region nobody looks at, "
                        "and nothing raises an alert there. SCP region denies do not apply to an Organization "
                        "management account, so that account needs its own guard.",
                "fix": "Disable opt-in regions you do not use, add an IAM deny on aws:RequestedRegion for every "
                       "region outside your list (in the management account too), and enable GuardDuty in all "
                       "enabled regions, ideally org-wide with a delegated administrator.",
            },
            "pt-BR": {
                "title": f"{len(empty)} {verb_pt} recursos nem GuardDuty: {listed}",
                "what": f"Em {listed} não há instâncias EC2, volumes EBS, funções Lambda, instâncias RDS, clusters "
                        "ECS, clusters EKS nem load balancers, e o GuardDuty não tem detector.",
                "risk": "Uma chave de acesso vazada pode subir instâncias (muitas vezes mineradores de cripto) numa "
                        "região que ninguém olha, e nada gera alerta lá. Bloqueio de região por SCP não vale para a "
                        "conta de gerenciamento da Organization, então essa conta precisa de proteção própria.",
                "fix": "Desativar as regiões opt-in que não são usadas, colocar um deny de IAM em aws:RequestedRegion "
                       "para toda região fora da lista (na conta de gerenciamento também) e ligar o GuardDuty em "
                       "todas as regiões ativas, de preferência para a organização inteira com administrador "
                       "delegado.",
            },
        },
        claims=[Claim(f"guardduty:ListDetectors@{r}", "DetectorIds", []) for r in empty]
        + [Claim(f"{name}@{r}", "count", 0) for r in empty[:3] for name in INVENTORY],
        verify=[
            f"aws guardduty list-detectors --region {first} --query 'DetectorIds' --output text",
            f"aws ec2 describe-instances --region {first} --query 'length(Reservations[].Instances[])' --output text",
            "aws account list-regions --region us-east-1 --region-opt-status-contains ENABLED ENABLED_BY_DEFAULT "
            "--query 'Regions[].RegionName' --output text",
        ],
    )]
