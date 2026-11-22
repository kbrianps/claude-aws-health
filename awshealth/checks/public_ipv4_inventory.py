from __future__ import annotations

from ..calls_compute import ADDRESSES, INSTANCES, NETWORK_INTERFACES
from ..model import Claim, Finding
from ..prices import HOURS_PER_MONTH, price, source
from ..registry import check


def _kind(eni: dict) -> str:
    desc = eni.get("description") or ""
    if eni.get("type") == "nat_gateway":
        return "nat_gateway"
    if eni.get("type") == "network_load_balancer" or desc.startswith("ELB "):
        return "load_balancer"
    if eni.get("instance"):
        return "instance"
    return eni.get("type") or "interface"


@check(
    id="public-ipv4-inventory",
    category="cost",
    severity="info",
    title={"en": "Billed public IPv4 addresses", "pt-BR": "Endereços IPv4 públicos cobrados"},
    requires=[ADDRESSES, INSTANCES, NETWORK_INTERFACES],
    catalog_ids=["vpc-public-ipv4-inventory"],
)
def run(snap, ctx):
    findings = []
    hourly = price("public_ipv4_hour")
    for region in snap.regions:
        eips = [a for a in snap.items(ADDRESSES, region) if a and a.get("ip")]
        byoip = {a["ip"] for a in eips if (a.get("pool") or "amazon") != "amazon"}
        kinds: dict[str, str] = {}
        for e in snap.items(NETWORK_INTERFACES, region):
            if e and e.get("public_ip") and e["public_ip"] not in byoip:
                kinds.setdefault(e["public_ip"], _kind(e))
        for i in snap.items(INSTANCES, region):
            if i and i.get("public_ip") and i["public_ip"] not in byoip:
                kinds.setdefault(i["public_ip"], "instance")
        for a in eips:
            if a["ip"] not in byoip:
                kinds.setdefault(a["ip"], "elastic_ip_unassociated" if not a.get("association") else "elastic_ip")
        if not kinds:
            continue
        count = len(kinds)
        monthly = round(count * hourly * HOURS_PER_MONTH, 2)
        breakdown: dict[str, int] = {}
        for k in kinds.values():
            breakdown[k] = breakdown.get(k, 0) + 1
        parts = ", ".join(f"{k} {n}" for k, n in sorted(breakdown.items(), key=lambda kv: (-kv[1], kv[0])))
        byoip_en = f" {len(byoip)} BYOIP addresses are not counted." if byoip else ""
        byoip_pt = f" {len(byoip)} endereços BYOIP não entram na conta." if byoip else ""
        plural, noun_pt = (("es", "endereços IPv4 públicos cobrados") if count > 1
                           else ("", "endereço IPv4 público cobrado"))
        findings.append(Finding(
            check_id="public-ipv4-inventory",
            resource=f"arn:aws:ec2:{region}:{snap.account_id}:public-ipv4",
            severity="info",
            category="cost",
            region=region,
            text={
                "en": {
                    "title": f"{count} public IPv4 address{plural} billed in {region}",
                    "what": f"{count} distinct public IPv4 addresses by owner: {parts}.{byoip_en}",
                    "risk": f"Every public IPv4 address bills US${hourly}/h, in use or idle, about "
                            f"US${monthly:,.2f}/month in total.",
                    "fix": "Turn off auto-assign public IP on subnets that do not need it, put private workloads "
                           "behind a NAT gateway or load balancer, and release idle Elastic IPs.",
                },
                "pt-BR": {
                    "title": f"{count} {noun_pt} em {region}",
                    "what": f"{count} endereços IPv4 públicos distintos por dono: {parts}.{byoip_pt}",
                    "risk": f"Cada IPv4 público custa US$ {hourly}/h, em uso ou parado, cerca de "
                            f"US$ {monthly:,.2f}/mês no total.",
                    "fix": "Desligar o IP público automático nas subnets que não precisam, colocar cargas privadas "
                           "atrás de NAT gateway ou load balancer e liberar Elastic IPs parados.",
                },
            },
            claims=[Claim(f"ec2:DescribeNetworkInterfaces@{region}", f"count(public_ip).{k}", n)
                    for k, n in sorted(breakdown.items())],
            monthly_usd=monthly,
            usd_calc=f"{count} addresses x US${hourly}/h x {HOURS_PER_MONTH} h = US${monthly:,.2f}/month "
                     f"({source('public_ipv4_hour')})",
            notes=["The EC2 Free Tier covers 750 hours a month of in-use public IPv4 for 12 months; idle addresses "
                   "are not covered."],
            verify=[
                f"aws ec2 describe-network-interfaces --region {region} "
                "--query 'NetworkInterfaces[?Association.PublicIp].[NetworkInterfaceId,InterfaceType,"
                "Association.PublicIp,Description]' --output table",
                f"aws ec2 describe-addresses --region {region} "
                "--query 'Addresses[].[PublicIp,AssociationId,PublicIpv4Pool]' --output table",
            ],
        ))
    return findings
