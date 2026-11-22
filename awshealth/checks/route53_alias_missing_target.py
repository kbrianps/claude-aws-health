from __future__ import annotations

import json
import re
from shlex import quote

from ..calls_security import ELB_CLASSIC, ELBV2, HOSTED_ZONES, RECORD_SETS
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "route53-alias-missing-target"
_ALB = re.compile(r"\.([a-z]{2}(?:-[a-z]+)+-\d)\.elb\.amazonaws\.com$")
_NLB = re.compile(r"\.elb\.([a-z]{2}(?:-[a-z]+)+-\d)\.amazonaws\.com$")


def _normalize(dns: str) -> str:
    d = (dns or "").lower().rstrip(".")
    return d[len("dualstack."):] if d.startswith("dualstack.") else d


def _elb_region(dns: str) -> str:
    m = _ALB.search(dns) or _NLB.search(dns)
    return m.group(1) if m else ""


@check(
    id=CHECK_ID,
    category="errors",
    severity="medium",
    title={"en": "DNS alias points at a load balancer that no longer exists",
           "pt-BR": "Alias DNS aponta para um load balancer que não existe mais"},
    requires=[HOSTED_ZONES, RECORD_SETS, ELBV2, ELB_CLASSIC],
    catalog_ids=["route53-dangling-dns-takeover"],
)
def run(snap, ctx):
    known, existing = set(), set()
    for region in snap.regions:
        if snap.status(ELBV2, region) == "ok" and snap.status(ELB_CLASSIC, region) == "ok":
            known.add(region)
        existing.update(_normalize(lb.get("dns")) for lb in snap.items(ELBV2, region) if lb)
        existing.update(_normalize(lb.get("dns")) for lb in snap.items(ELB_CLASSIC, region) if lb)
    zones = {z["id"]: z for z in snap.items(HOSTED_ZONES, "global") if z}
    findings = []
    for zone_id, records in snap.per_item(RECORD_SETS, "global").items():
        if zone_id not in zones or not isinstance(records, list):
            continue
        short_zone = zone_id.split("/")[-1]
        for rec in records:
            target = _normalize((rec.get("alias") or {}).get("DNSName", ""))
            region = _elb_region(target)
            if not region or region not in known or target in existing:
                continue
            name = rec["name"].rstrip(".")
            findings.append(Finding(
                check_id=CHECK_ID,
                resource=f"{short_zone}/{name}/{rec.get('type')}",
                severity="medium",
                category="errors",
                region=region,
                text={
                    "en": {
                        "title": f"{name} is an alias to load balancer {target}, which does not exist in {region}",
                        "what": f"The {rec.get('type')} alias {name} in zone "
                                f"{zones[zone_id].get('name', '').rstrip('.')} targets {target}. No ALB, NLB or "
                                f"Classic Load Balancer in {region} has that DNS name.",
                        "risk": "The name stops resolving, so whatever used it fails quietly. ELB names carry a "
                                "random part, so takeover is unlikely, but the record is broken.",
                        "fix": "Point the alias at the current load balancer or delete the record. If the load "
                               "balancer lives in another account, confirm it there.",
                    },
                    "pt-BR": {
                        "title": f"{name} é um alias para o load balancer {target}, que não existe em {region}",
                        "what": f"O alias {rec.get('type')} {name} na zona "
                                f"{zones[zone_id].get('name', '').rstrip('.')} aponta para {target}. Nenhum ALB, NLB "
                                f"ou Classic Load Balancer em {region} tem esse nome DNS.",
                        "risk": "O nome para de resolver e quem depende dele falha sem aviso. Nomes de ELB têm uma "
                                "parte aleatória, então tomada do nome é improvável, mas o registro está quebrado.",
                        "fix": "Apontar o alias para o load balancer atual ou apagar o registro. Se o load balancer "
                               "estiver em outra conta, confirmar lá.",
                    },
                },
                claims=[
                    Claim("route53:ListResourceRecordSets@global", f"{zone_id}.{rec['name']}.AliasTarget.DNSName",
                          target),
                    Claim(f"elbv2:DescribeLoadBalancers@{region}", f"LoadBalancers[?DNSName=='{target}']", []),
                    Claim(f"elb:DescribeLoadBalancers@{region}", f"LoadBalancerDescriptions[?DNSName=='{target}']", []),
                ],
                owner_question={
                    "en": f"Is {target} a load balancer in another AWS account?",
                    "pt-BR": f"{target} é um load balancer em outra conta AWS?",
                },
                verify=[
                    f"aws route53 list-resource-record-sets --hosted-zone-id {quote(short_zone)} "
                    "--region us-east-1 --query "
                    + quote(f"ResourceRecordSets[?Name==`{json.dumps(rec['name'])}`].AliasTarget.DNSName")
                    + " --output text",
                    f"aws elbv2 describe-load-balancers --region {quote(region)} --query "
                    + quote(f"LoadBalancers[?DNSName==`{json.dumps(target)}`].LoadBalancerArn") + " --output text",
                    f"aws elb describe-load-balancers --region {quote(region)} --query "
                    + quote(f"LoadBalancerDescriptions[?DNSName==`{json.dumps(target)}`].LoadBalancerName")
                    + " --output text",
                ],
            ))
    return findings
