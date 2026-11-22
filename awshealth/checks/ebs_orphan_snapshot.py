from __future__ import annotations

from shlex import quote

from ..calls_compute import IMAGES, SNAPSHOTS, VOLUMES, tag_map
from ..model import Claim, Finding
from ..prices import price, source
from ..registry import check
from . import counted

DLM_TAG = "aws:dlm:lifecycle-policy-id"
BACKUP_TAG = "aws:backup:source-resource"


def _managed(s: dict) -> bool:
    tags = tag_map(s.get("tags"))
    return bool(s.get("aws_backup")) or DLM_TAG in tags or BACKUP_TAG in tags


@check(
    id="ebs-orphan-snapshot",
    category="zombie",
    severity="medium",
    title={"en": "EBS snapshots whose source volume is gone", "pt-BR": "Snapshots EBS cujo volume de origem sumiu"},
    requires=[SNAPSHOTS, VOLUMES, IMAGES],
    catalog_ids=["ebs-orphan-snapshot"],
)
def run(snap, ctx):
    findings = []
    gb_price = price("ebs_snapshot_gb_month")
    for region in snap.regions:
        if snap.status(VOLUMES, region) != "ok" or snap.status(IMAGES, region) != "ok":
            continue
        volumes = {v["id"] for v in snap.items(VOLUMES, region) if v}
        ami_snaps = {sid for img in snap.items(IMAGES, region) if img for sid in img.get("snapshots") or [] if sid}
        orphans = [
            s for s in snap.items(SNAPSHOTS, region)
            if s and s.get("volume") not in volumes and s["id"] not in ami_snaps and not _managed(s)
        ]
        if not orphans:
            continue
        orphans.sort(key=lambda s: (-(s.get("size") or 0), s["id"]))
        total_gb = sum(s.get("size") or 0 for s in orphans)
        monthly = round(total_gb * gb_price, 2)
        top = orphans[:10]
        top_list = ", ".join(f"{s['id']} ({s.get('size') or 0} GiB)" for s in top)
        archive = sum(1 for s in orphans if s.get("tier") == "archive")
        archive_en = f" {archive} of them are in the archive tier, which has a 90-day minimum." if archive else ""
        archive_pt = f" {archive} deles estão na camada archive, que tem mínimo de 90 dias." if archive else ""
        ids = " ".join(quote(s["id"]) for s in top[:5])
        vol_ids = ",".join(sorted({s.get("volume") or "vol-ffffffff" for s in top[:5]}))
        snap_csv = ",".join(s["id"] for s in top[:5])
        plural = "s" if len(orphans) > 1 else ""
        findings.append(Finding(
            check_id="ebs-orphan-snapshot",
            resource=f"arn:aws:ec2:{region}:{snap.account_id}:snapshot/orphans",
            resources=[f"arn:aws:ec2:{region}::snapshot/{s['id']}" for s in orphans],
            severity="medium" if monthly >= 10 else "low",
            category="zombie",
            region=region,
            text={
                "en": {
                    "title": f"{len(orphans)} EBS snapshot{plural} in {region} with no source volume, AMI or "
                             "backup policy",
                    "what": f"{counted(len(orphans), 'self-owned snapshot', 'self-owned snapshots')} ({total_gb} GiB "
                            "of volume size) "
                            + ("points at a volume that no longer exists and is" if len(orphans) == 1
                               else "point at volumes that no longer exist and are")
                            + f" not used by any self-owned AMI, DLM or AWS Backup. Largest: {top_list}.{archive_en}",
                    "risk": f"{'It bills' if len(orphans) == 1 else 'They bill'} up to about US${monthly:,.2f}/month. "
                            "Snapshots are incremental, so the real "
                            "figure can be lower.",
                    "fix": "Confirm with the owner that none is a final backup kept for compliance or a DR copy, "
                           "then delete them or move the keepers to the archive tier.",
                },
                "pt-BR": {
                    "title": f"{len(orphans)} snapshot{plural} EBS em {region} sem volume de origem, AMI nem política "
                             "de backup",
                    "what": f"{counted(len(orphans), 'snapshot da conta', 'snapshots da conta')} ({total_gb} GiB de "
                            "tamanho de volume) "
                            + ("aponta para um volume que não existe mais e não é usado" if len(orphans) == 1
                               else "apontam para volumes que não existem mais e não são usados")
                            + f" por nenhuma AMI da conta, DLM ou AWS Backup. Maiores: {top_list}.{archive_pt}",
                    "risk": f"{'Ele custa' if len(orphans) == 1 else 'Eles custam'} até cerca de "
                            f"US$ {monthly:,.2f}/mês. Snapshots são incrementais, então o "
                            "valor real pode ser menor.",
                    "fix": "Confirmar com o dono que nenhum é backup final guardado por compliance ou cópia de DR, "
                           "depois apagar ou mover os que ficam para a camada archive.",
                },
            },
            claims=[Claim(f"ec2:DescribeSnapshots@{region}", f"{s['id']}.VolumeSize", s.get("size")) for s in top]
            + [Claim(f"ec2:DescribeSnapshots@{region}", f"{s['id']}.VolumeId", s.get("volume")) for s in top],
            monthly_usd=monthly,
            usd_calc=f"upper bound: {total_gb} GiB x US${gb_price}/GB-month = US${monthly:,.2f}/month; snapshots "
                     f"are incremental, so billed size can be lower ({source('ebs_snapshot_gb_month')})",
            owner_question={
                "en": ("Is the orphan snapshot" if len(orphans) == 1
                       else f"Are any of the {len(orphans)} orphan snapshots")
                + f" in {region} a final backup kept for compliance or legal reasons, or a copy for disaster recovery?",
                "pt-BR": ("O snapshot órfão" if len(orphans) == 1
                          else f"Algum dos {len(orphans)} snapshots órfãos")
                + f" em {region} é backup final guardado por compliance ou motivo legal, ou cópia para recuperação "
                  "de desastre?",
            },
            confidence="medium",
            verify=[
                f"aws ec2 describe-snapshots --owner-ids self --snapshot-ids {ids} --region {quote(region)} "
                "--query 'Snapshots[].[SnapshotId,VolumeId,VolumeSize,StartTime,StorageTier]' --output table",
                f"aws ec2 describe-volumes --filters Name=volume-id,Values={quote(vol_ids)} --region {quote(region)} "
                "--query 'Volumes[].VolumeId' --output text",
                f"aws ec2 describe-images --owners self --include-deprecated --include-disabled "
                f"--filters Name=block-device-mapping.snapshot-id,Values={quote(snap_csv)} --region {quote(region)} "
                "--query 'Images[].ImageId' --output text",
            ],
        ))
    return findings
