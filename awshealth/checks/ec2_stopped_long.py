from __future__ import annotations

import re
from datetime import datetime, timezone
from shlex import quote

from ..calls_compute import ADDRESSES, INSTANCES, VOLUMES, ebs_gb_month, tag_map
from ..model import Claim, Finding
from ..prices import HOURS_PER_MONTH, price, source
from ..registry import check
from . import counted

STOP_RE = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)")
MIN_DAYS = 30
ASG_TAG = "aws:autoscaling:groupName"


def stopped_at(reason: str | None) -> datetime | None:
    m = STOP_RE.search(reason or "")
    return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) if m else None


@check(
    id="ec2-stopped-long",
    category="zombie",
    severity="medium",
    title={"en": "EC2 instance stopped for a long time", "pt-BR": "Instância EC2 parada há muito tempo"},
    requires=[INSTANCES, VOLUMES, ADDRESSES],
    catalog_ids=["ec2-stopped-instance-with-ebs"],
)
def run(snap, ctx):
    findings = []
    hourly_ip = price("public_ipv4_hour")
    for region in snap.regions:
        volumes = {v["id"]: v for v in snap.items(VOLUMES, region) if v}
        eips = [a for a in snap.items(ADDRESSES, region) if a and a.get("instance")]
        for i in snap.items(INSTANCES, region):
            if not i or i.get("state") != "stopped":
                continue
            tags = tag_map(i.get("tags"))
            if ASG_TAG in tags:
                continue
            when = stopped_at(i.get("reason"))
            if not when or (ctx.now - when).days <= MIN_DAYS:
                continue
            iid, days = i["id"], (ctx.now - when).days
            vols = [volumes[v] for v in i.get("volumes") or [] if v in volumes]
            parts, unknown = [], []
            for v in vols:
                p = ebs_gb_month(v.get("type"))
                if p is None:
                    unknown.append(v["id"])
                else:
                    parts.append((v, p))
            ips = [a for a in eips if a["instance"] == iid and (a.get("pool") or "amazon") == "amazon"]
            ebs_usd = sum((v.get("size") or 0) * p for v, p in parts)
            ip_usd = len(ips) * hourly_ip * HOURS_PER_MONTH
            monthly = round(ebs_usd + ip_usd, 2) if parts or ips else None
            calc = [f"{v['id']} {v.get('size')} GiB x US${p} ({v.get('type')})" for v, p in parts]
            calc += [f"EIP {a.get('ip')} US${hourly_ip}/h x {HOURS_PER_MONTH} h" for a in ips]
            total_gb = sum(v.get("size") or 0 for v in vols)
            name = tags.get("Name")
            label = f"{iid} ({name})" if name else iid
            one = len(vols) + len(ips) == 1
            ips_en = f" and {counted(len(ips), 'Elastic IP', 'Elastic IPs')}" if ips else ""
            ips_pt = f" e {counted(len(ips), 'Elastic IP', 'Elastic IPs')}" if ips else ""
            cost_en = (" Its volume" if len(vols) == 1 else f" Its {len(vols)} volumes") \
                + f" ({total_gb} GiB){ips_en}" \
                + (f" still {'costs' if one else 'cost'} about US${monthly:,.2f}/month." if monthly is not None
                   else f" still {'bills' if one else 'bill'} storage.")
            cost_pt = (" O volume dela" if len(vols) == 1 else f" Os {len(vols)} volumes dela") \
                + f" ({total_gb} GiB){ips_pt}" \
                + (f" ainda {'custa' if one else 'custam'} cerca de US$ {monthly:,.2f}/mês." if monthly is not None
                   else f" ainda {'cobra' if one else 'cobram'} armazenamento.")
            findings.append(Finding(
                check_id="ec2-stopped-long",
                resource=f"arn:aws:ec2:{region}:{snap.account_id}:instance/{iid}",
                severity="medium" if (monthly or 0) >= 10 else "low",
                category="zombie",
                region=region,
                text={
                    "en": {
                        "title": f"EC2 instance {label} has been stopped for {days} days",
                        "what": f"Instance {iid} ({i.get('type')}) was stopped on {when.strftime('%Y-%m-%d')}: "
                                f"{i.get('reason')}.",
                        "risk": f"A stopped instance bills no compute, but its storage keeps billing.{cost_en}",
                        "fix": "Ask the owner. If it is not a DR standby or a license-bound host, create an AMI as "
                               "a final backup and terminate it, then release its Elastic IPs.",
                    },
                    "pt-BR": {
                        "title": f"A instância EC2 {label} está parada há {days} dias",
                        "what": f"A instância {iid} ({i.get('type')}) foi parada em {when.strftime('%Y-%m-%d')}: "
                                f"{i.get('reason')}.",
                        "risk": f"Instância parada não cobra computação, mas o armazenamento continua cobrando."
                                f"{cost_pt}",
                        "fix": "Perguntar ao dono. Se não for standby de DR nem máquina presa a licença, criar uma AMI "
                               "como backup final e terminar a instância, depois liberar os Elastic IPs.",
                    },
                },
                claims=[Claim(f"ec2:DescribeInstances@{region}", f"{iid}.StateTransitionReason", i.get("reason"))]
                + [Claim(f"ec2:DescribeVolumes@{region}", f"{v['id']}.Size", v.get("size")) for v in vols],
                monthly_usd=monthly,
                usd_calc=(" + ".join(calc) + f" = US${monthly:,.2f}/month, storage only, provisioned IOPS not "
                          f"included ({source('ebs_gp3_gb_month')})") if monthly is not None else "",
                owner_question={
                    "en": f"Instance {label} has been stopped for {days} days. Is it a DR standby, a seasonal box or "
                          "a host tied to a license, or can it be archived as an AMI and terminated?",
                    "pt-BR": f"A instância {label} está parada há {days} dias. Ela é standby de DR, máquina sazonal ou "
                             "presa a uma licença, ou pode virar AMI e ser terminada?",
                },
                notes=[{"en": f"Volume types without a price: {', '.join(unknown)}.",
                        "pt-BR": f"Tipos de volume sem preço: {', '.join(unknown)}."}] if unknown else [],
                verify=[
                    f"aws ec2 describe-instances --instance-ids {quote(iid)} --region {quote(region)} "
                    "--query 'Reservations[].Instances[].[InstanceId,State.Name,StateTransitionReason,InstanceType]' "
                    "--output table",
                    f"aws ec2 describe-volumes --filters Name=attachment.instance-id,Values={quote(iid)} "
                    f"--region {quote(region)} "
                    "--query 'Volumes[].[VolumeId,Size,VolumeType]' --output table",
                    f"aws cloudtrail lookup-events --region {quote(region)} "
                    f"--lookup-attributes AttributeKey=ResourceName,AttributeValue={quote(iid)} --max-results 5 "
                    "--query 'Events[].[EventTime,EventName,Username]' --output table",
                ],
            ))
    return findings
