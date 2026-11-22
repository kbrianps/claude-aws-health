from __future__ import annotations

from shlex import quote

from ..calls_compute import EBS_PRICE_KEYS, VOLUMES, ebs_gb_month, parse_time, tag_map
from ..model import Claim, Finding
from ..prices import source
from ..registry import check

PVC_TAG = "kubernetes.io/created-for/pvc/name"


@check(
    id="ebs-unattached",
    category="zombie",
    severity="medium",
    title={"en": "Unattached EBS volume", "pt-BR": "Volume EBS sem anexo"},
    requires=[VOLUMES],
    catalog_ids=["ebs-unattached-volume"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        for v in snap.items(VOLUMES, region):
            if not v or v.get("state") != "available":
                continue
            vid, size, vtype = v["id"], v.get("size") or 0, v.get("type")
            tags = tag_map(v.get("tags"))
            pvc = tags.get(PVC_TAG)
            created = parse_time(v.get("created"))
            age = f"{(ctx.now - created).days}" if created else "?"
            gb_price = ebs_gb_month(vtype)
            monthly = round(size * gb_price, 2) if gb_price is not None else None
            usd_calc = (f"{size} GiB x US${gb_price}/GB-month ({vtype}) = US${monthly:,.2f}/month, storage only "
                        f"({source(EBS_PRICE_KEYS[vtype])})") if monthly is not None else ""
            cost_en = f" It costs about US${monthly:,.2f}/month." if monthly is not None else ""
            cost_pt = f" Custa cerca de US$ {monthly:,.2f}/mês." if monthly is not None else ""
            name = tags.get("Name")
            label = f"{vid} ({name})" if name else vid
            claims = [
                Claim(f"ec2:DescribeVolumes@{region}", f"{vid}.State", v.get("state")),
                Claim(f"ec2:DescribeVolumes@{region}", f"{vid}.Size", size),
                Claim(f"ec2:DescribeVolumes@{region}", f"{vid}.VolumeType", vtype),
            ]
            question = {}
            notes = []
            if pvc:
                claims.append(Claim(f"ec2:DescribeVolumes@{region}", f"{vid}.Tags.{PVC_TAG}", pvc))
                question = {
                    "en": f"Volume {vid} was created for the Kubernetes PVC {pvc}. Is that PersistentVolume kept on "
                          "purpose with reclaimPolicy Retain, or was the claim deleted for good?",
                    "pt-BR": f"O volume {vid} foi criado para o PVC {pvc} do Kubernetes. Esse PersistentVolume é "
                             "mantido de propósito com reclaimPolicy Retain, ou o claim foi apagado de vez?",
                }
                notes.append({"en": "Kubernetes PVC volume: a reclaimPolicy Retain keeps the data on purpose.",
                              "pt-BR": "Volume de PVC do Kubernetes: reclaimPolicy Retain guarda os dados de "
                                       "propósito."})
            findings.append(Finding(
                check_id="ebs-unattached",
                resource=f"arn:aws:ec2:{region}:{snap.account_id}:volume/{vid}",
                severity="low" if pvc else "medium",
                category="zombie",
                region=region,
                text={
                    "en": {
                        "title": f"EBS volume {label} is not attached to any instance",
                        "what": f"Volume {vid} ({size} GiB {vtype}) is in state available, created {age} days ago."
                                + (f" It was created for the Kubernetes PVC {pvc}." if pvc else ""),
                        "risk": f"Unattached volumes keep billing for storage.{cost_en}",
                        "fix": "Check the last DetachVolume in CloudTrail and the owner. If nobody needs the data, "
                               "take a final snapshot and delete the volume.",
                    },
                    "pt-BR": {
                        "title": f"O volume EBS {label} não está anexado a nenhuma instância",
                        "what": f"O volume {vid} ({size} GiB {vtype}) está no estado available, criado há {age} dias."
                                + (f" Ele foi criado para o PVC {pvc} do Kubernetes." if pvc else ""),
                        "risk": f"Volume sem anexo continua cobrando armazenamento.{cost_pt}",
                        "fix": "Ver o último DetachVolume no CloudTrail e falar com o dono. Se ninguém precisa dos "
                               "dados, tirar um snapshot final e apagar o volume.",
                    },
                },
                claims=claims,
                monthly_usd=monthly,
                usd_calc=usd_calc,
                owner_question=question,
                confidence="low" if pvc else "high",
                notes=notes,
                verify=[
                    f"aws ec2 describe-volumes --volume-ids {quote(vid)} --region {quote(region)} "
                    "--query 'Volumes[].[VolumeId,State,Size,VolumeType,CreateTime]' --output table",
                    f"aws cloudtrail lookup-events --region {quote(region)} "
                    f"--lookup-attributes AttributeKey=ResourceName,AttributeValue={quote(vid)} --max-results 5 "
                    "--query 'Events[].[EventTime,EventName,Username]' --output table",
                ],
            ))
    return findings
