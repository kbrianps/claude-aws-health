from __future__ import annotations

import ipaddress

from ..calls_core import IP_RANGES
from ..calls_security import ADDRESSES, ENI_PUBLIC_IPS, HOSTED_ZONES, RECORD_SETS
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "route53-dangling-ip"


def _ec2_ranges(snap):
    out = []
    for r in snap.items(IP_RANGES, "global"):
        if isinstance(r, dict) and r.get("service") == "EC2" and ":" not in r.get("cidr", ""):
            out.append((ipaddress.ip_network(r["cidr"]), r.get("region", "")))
    return out


def _owned(snap):
    owned, known = set(), set()
    for region in snap.regions:
        if snap.status(ADDRESSES, region) == "ok" and snap.status(ENI_PUBLIC_IPS, region) == "ok":
            known.add(region)
        owned.update(a.get("ip") for a in snap.items(ADDRESSES, region) if a)
        owned.update(e.get("public_ip") for e in snap.items(ENI_PUBLIC_IPS, region) if e)
    return owned, known


@check(
    id=CHECK_ID,
    category="security",
    severity="high",
    title={"en": "DNS A record points at an AWS IP the account does not own",
           "pt-BR": "Registro DNS A aponta para um IP da AWS que a conta não possui"},
    requires=[IP_RANGES, HOSTED_ZONES, RECORD_SETS, ADDRESSES, ENI_PUBLIC_IPS],
    catalog_ids=["route53-dangling-dns-takeover"],
)
def run(snap, ctx):
    ranges = _ec2_ranges(snap)
    if not ranges:
        return []
    owned, known = _owned(snap)
    zones = {z["id"]: z for z in snap.items(HOSTED_ZONES, "global") if z}
    findings = []
    for zone_id, records in snap.per_item(RECORD_SETS, "global").items():
        zone = zones.get(zone_id)
        if not zone or zone.get("private") or not isinstance(records, list):
            continue
        short_zone = zone_id.split("/")[-1]
        for rec in records:
            if rec.get("type") != "A" or rec.get("alias"):
                continue
            for value in rec.get("values") or []:
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    continue
                region = next((reg for net, reg in ranges if ip in net), None)
                if region is None or value in owned:
                    continue
                if region in snap.regions and region not in known:
                    continue
                scanned = region in known
                name = rec["name"].rstrip(".")
                resource = f"{short_zone}/{name}/A/{value}"
                note_en = "" if scanned else (f" Region {region} was not scanned, so an Elastic IP there would not "
                                              "be seen.")
                note_pt = "" if scanned else (f" A região {region} não foi analisada, então um Elastic IP lá não "
                                              "apareceria.")
                findings.append(Finding(
                    check_id=CHECK_ID,
                    resource=resource,
                    severity="high",
                    category="security",
                    region=region or "global",
                    confidence="high" if scanned else "medium",
                    text={
                        "en": {
                            "title": f"{name} points at {value}, an AWS {region} IP that this account does not hold",
                            "what": (f"The A record {name} in public zone {zone.get('name', '').rstrip('.')} "
                                     f"resolves to {value}, inside the AWS EC2 range for {region}. No Elastic IP or "
                                     f"network interface in the scanned regions has this address.{note_en}"),
                            "risk": ("If the IP was a released Elastic IP, anyone can allocate it and serve content "
                                     "or receive traffic as your subdomain (subdomain takeover)."),
                            "fix": ("Delete or update the record. If the IP belongs to another account you control "
                                    "or to a partner, document it and point the record at a name you own instead."),
                        },
                        "pt-BR": {
                            "title": f"{name} aponta para {value}, um IP da AWS em {region} que esta conta não possui",
                            "what": (f"O registro A {name} na zona pública {zone.get('name', '').rstrip('.')} "
                                     f"resolve para {value}, dentro da faixa EC2 da AWS em {region}. Nenhum Elastic "
                                     f"IP ou interface de rede nas regiões analisadas tem esse endereço.{note_pt}"),
                            "risk": ("Se o IP era um Elastic IP liberado, qualquer pessoa pode alocá-lo e servir "
                                     "conteúdo ou receber tráfego como o seu subdomínio (tomada de subdomínio)."),
                            "fix": ("Apagar ou corrigir o registro. Se o IP for de outra conta sua ou de um "
                                    "parceiro, documentar isso e apontar o registro para um nome que você controla."),
                        },
                    },
                    claims=[
                        Claim("route53:ListResourceRecordSets@global", f"{zone_id}.{rec['name']}.A", value),
                        Claim("aws:IpRanges@global", "EC2", region),
                        Claim(f"ec2:DescribeAddresses@{region}", f"Addresses[?PublicIp=='{value}']", []),
                        Claim(f"ec2:DescribeNetworkInterfaces@{region}",
                              f"NetworkInterfaces[?Association.PublicIp=='{value}']", []),
                    ],
                    owner_question={
                        "en": f"Does {value} belong to another AWS account of yours or to a partner?",
                        "pt-BR": f"O IP {value} pertence a outra conta AWS sua ou a um parceiro?",
                    },
                    verify=[
                        (f"aws route53 list-resource-record-sets --hosted-zone-id {short_zone} --region us-east-1 "
                         f"--query \"ResourceRecordSets[?Name=='{rec['name']}' && "
                         "Type=='A'].ResourceRecords[].Value\" --output text"),
                        (f"aws ec2 describe-addresses --region {region} --filters Name=public-ip,Values={value} "
                         "--query 'Addresses[].AllocationId' --output text"),
                        (f"aws ec2 describe-network-interfaces --region {region} --filters "
                         f"Name=association.public-ip,Values={value} --query "
                         "'NetworkInterfaces[].NetworkInterfaceId' --output text"),
                    ],
                ))
    return findings
