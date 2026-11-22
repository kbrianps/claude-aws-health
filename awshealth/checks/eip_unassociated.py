from __future__ import annotations

from shlex import quote

from ..calls_compute import ADDRESSES, tag_map
from ..model import Claim, Finding
from ..prices import HOURS_PER_MONTH, price, source
from ..registry import check


@check(
    id="eip-unassociated",
    category="zombie",
    severity="low",
    title={"en": "Elastic IP not associated", "pt-BR": "Elastic IP sem associação"},
    requires=[ADDRESSES],
    catalog_ids=["ec2-eip-unassociated"],
)
def run(snap, ctx):
    findings = []
    hourly = price("public_ipv4_hour")
    for region in snap.regions:
        for a in snap.items(ADDRESSES, region):
            if not a or a.get("association") or a.get("instance") or a.get("eni"):
                continue
            ip, alloc = a.get("ip"), a.get("allocation")
            pool = a.get("pool") or "amazon"
            byoip = pool != "amazon"
            monthly = None if byoip else round(hourly * HOURS_PER_MONTH, 2)
            name = tag_map(a.get("tags")).get("Name")
            label = f"{ip} ({name})" if name else ip
            ref = f"--allocation-ids {quote(alloc)}" if alloc else f"--public-ips {quote(ip)}"
            cost_en = (f"It bills US${hourly}/h, about US${monthly:,.2f}/month." if monthly is not None
                       else f"It comes from the BYOIP pool {pool}, so AWS does not bill the address itself.")
            cost_pt = (f"Ele custa US$ {hourly}/h, cerca de US$ {monthly:,.2f}/mês." if monthly is not None
                       else f"Ele vem do pool BYOIP {pool}, então a AWS não cobra pelo endereço.")
            findings.append(Finding(
                check_id="eip-unassociated",
                resource=f"arn:aws:ec2:{region}:{snap.account_id}:elastic-ip/{alloc or ip}",
                severity="low",
                category="zombie",
                region=region,
                text={
                    "en": {
                        "title": f"Elastic IP {label} is not associated with anything",
                        "what": f"Elastic IP {ip} ({alloc or 'no allocation id'}) has no association, instance or "
                                "network interface.",
                        "risk": cost_en,
                        "fix": "Ask the owner first. Releasing the address loses it for good, and partners or "
                               "customer firewalls may allowlist it. If nobody depends on it, release it.",
                    },
                    "pt-BR": {
                        "title": f"O Elastic IP {label} não está associado a nada",
                        "what": f"O Elastic IP {ip} ({alloc or 'sem allocation id'}) não tem associação, instância "
                                "nem interface de rede.",
                        "risk": cost_pt,
                        "fix": "Perguntar ao dono antes. Liberar o endereço perde ele para sempre, e parceiros ou "
                               "firewalls de clientes podem ter ele na lista de liberação. Se ninguém depende dele, "
                               "liberar.",
                    },
                },
                claims=[
                    Claim(f"ec2:DescribeAddresses@{region}", f"{alloc or ip}.AssociationId", a.get("association")),
                    Claim(f"ec2:DescribeAddresses@{region}", f"{alloc or ip}.PublicIpv4Pool", pool),
                ],
                monthly_usd=monthly,
                usd_calc=(f"US${hourly}/h x {HOURS_PER_MONTH} h = US${monthly:,.2f}/month "
                          f"({source('public_ipv4_hour')})") if monthly is not None else "",
                owner_question={
                    "en": f"Does any partner, customer or firewall allowlist {ip}, or is it kept for a planned "
                          "re-creation? Releasing it loses the address forever.",
                    "pt-BR": f"Algum parceiro, cliente ou firewall libera o IP {ip}, ou ele está guardado para uma "
                             "recriação planejada? Liberar perde o endereço para sempre.",
                },
                verify=[
                    f"aws ec2 describe-addresses {ref} --region {quote(region)} "
                    "--query 'Addresses[].[PublicIp,AllocationId,AssociationId,PublicIpv4Pool]' --output table",
                    f"aws cloudtrail lookup-events --region {quote(region)} "
                    f"--lookup-attributes AttributeKey=ResourceName,AttributeValue={quote(alloc or ip)} "
                    "--max-results 5 "
                    "--query 'Events[].[EventTime,EventName,Username]' --output table",
                ],
            ))
    return findings
