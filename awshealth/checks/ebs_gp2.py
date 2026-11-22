from __future__ import annotations

from shlex import quote

from ..calls_compute import VOLUMES
from ..model import Claim, Finding
from ..prices import price, source
from ..registry import check
from . import counted

GP3_BASE_IOPS = 3000
GP2_IOPS_PER_GIB = 3
GP2_THROUGHPUT_GIB = 170


@check(
    id="ebs-gp2",
    category="cost",
    severity="low",
    title={"en": "EBS gp2 volumes that could move to gp3", "pt-BR": "Volumes EBS gp2 que podem ir para gp3"},
    requires=[VOLUMES],
    catalog_ids=["ebs-gp2-to-gp3"],
)
def run(snap, ctx):
    findings = []
    saving = round(price("ebs_gp2_gb_month") - price("ebs_gp3_gb_month"), 4)
    for region in snap.regions:
        vols = sorted((v for v in snap.items(VOLUMES, region) if v and v.get("type") == "gp2"),
                      key=lambda v: (-(v.get("size") or 0), v["id"]))
        if not vols:
            continue
        total = sum(v.get("size") or 0 for v in vols)
        monthly = round(total * saving, 2)
        big = [v for v in vols if (v.get("size") or 0) * GP2_IOPS_PER_GIB > GP3_BASE_IOPS]
        mid = [v for v in vols if (v.get("size") or 0) > GP2_THROUGHPUT_GIB]
        top = ", ".join(f"{v['id']} ({v.get('size')} GiB)" for v in vols[:10])
        notes = []
        caveat_en, caveat_pt = "", ""
        if big:
            notes.append({"en": f"{len(big)} volumes have more than {GP3_BASE_IOPS} gp2 baseline IOPS.",
                          "pt-BR": f"{len(big)} volumes têm mais de {GP3_BASE_IOPS} IOPS de base no gp2."})
            caveat_en = (f" {counted(len(big), 'volume is', 'volumes are')} over 1000 GiB and "
                         f"{'gets' if len(big) == 1 else 'get'} more than {GP3_BASE_IOPS} IOPS on gp2, so "
                         "gp3 needs provisioned IOPS to match, which lowers the saving.")
            caveat_pt = (f" {counted(len(big), 'volume tem', 'volumes têm')} mais de 1000 GiB e "
                         f"{'recebe' if len(big) == 1 else 'recebem'} mais de {GP3_BASE_IOPS} IOPS no gp2, "
                         "então o gp3 precisa de IOPS provisionado para igualar, o que reduz a economia.")
        if mid:
            caveat_en += (f" {counted(len(mid), 'volume is', 'volumes are')} over {GP2_THROUGHPUT_GIB} GiB and "
                          "may need more than the gp3 "
                          "baseline of 125 MiB/s.")
            caveat_pt += (f" {counted(len(mid), 'volume tem', 'volumes têm')} mais de {GP2_THROUGHPUT_GIB} GiB e "
                          f"{'pode' if len(mid) == 1 else 'podem'} precisar de mais que "
                          "os 125 MiB/s base do gp3.")
        findings.append(Finding(
            check_id="ebs-gp2",
            resource=f"arn:aws:ec2:{region}:{snap.account_id}:volume/gp2",
            resources=[f"arn:aws:ec2:{region}:{snap.account_id}:volume/{v['id']}" for v in vols],
            severity="low",
            category="cost",
            region=region,
            text={
                "en": {
                    "title": f"{len(vols)} EBS volume{'s' if len(vols) > 1 else ''} in {region} still on gp2",
                    "what": f"{counted(len(vols), 'gp2 volume adds', 'gp2 volumes add')} up to {total} GiB. "
                            f"Largest: {top}.",
                    "risk": f"gp3 costs US${price('ebs_gp3_gb_month')}/GB-month instead of "
                            f"US${price('ebs_gp2_gb_month')}, about US${monthly:,.2f}/month less.{caveat_en}",
                    "fix": "Run modify-volume --volume-type gp3 (online, no detach), matching IOPS and throughput "
                           "for large volumes. Change AMIs, launch templates and StorageClasses that still create "
                           "gp2.",
                },
                "pt-BR": {
                    "title": f"{len(vols)} volume{'s' if len(vols) > 1 else ''} EBS em {region} ainda em gp2",
                    "what": f"{counted(len(vols), 'volume gp2 soma', 'volumes gp2 somam')} {total} GiB. "
                            f"Maiores: {top}.",
                    "risk": f"O gp3 custa US$ {price('ebs_gp3_gb_month')}/GB-mês em vez de "
                            f"US$ {price('ebs_gp2_gb_month')}, cerca de US$ {monthly:,.2f}/mês a menos.{caveat_pt}",
                    "fix": "Rodar modify-volume --volume-type gp3 (online, sem desanexar), igualando IOPS e "
                           "throughput nos volumes grandes. Trocar AMIs, launch templates e StorageClasses que ainda "
                           "criam gp2.",
                },
            },
            claims=[Claim(f"ec2:DescribeVolumes@{region}", f"{v['id']}.Size", v.get("size")) for v in vols[:10]],
            monthly_usd=monthly,
            usd_calc=(("upper bound: " if big or mid else "")
                      + f"{total} GiB x (US${price('ebs_gp2_gb_month')} - US${price('ebs_gp3_gb_month')}) = "
                        f"US${monthly:,.2f}/month ({source('ebs_gp3_gb_month')})"),
            confidence="medium" if big else "high",
            notes=notes,
            verify=[
                f"aws ec2 describe-volumes --filters Name=volume-type,Values=gp2 --region {quote(region)} "
                "--query 'Volumes[].[VolumeId,Size,Iops,State]' --output table",
                f"aws compute-optimizer get-ebs-volume-recommendations --region {quote(region)} "
                "--query 'volumeRecommendations[].[volumeArn,finding,currentConfiguration.volumeType]' --output table",
            ],
        ))
    return findings
