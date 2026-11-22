from __future__ import annotations

from ..calls_compute import RDS_CLUSTERS, RDS_INSTANCES, env_of
from ..model import SEVERITIES, Claim, Finding
from ..registry import check

MIN_BACKUP_DAYS = 7


def _issues(db: dict, env: str | None, is_replica: bool) -> list[tuple[str, str, str, str, str]]:
    out = []
    prod = env == "prod"
    if db.get("encrypted") is False:
        sev = "medium" if env == "nonprod" else "high"
        out.append(("StorageEncrypted", db.get("encrypted"), sev, "storage is not encrypted",
                    "o armazenamento não é criptografado"))
    if prod and db.get("multi_az") is False:
        out.append(("MultiAZ", False, "medium", "it is production and runs in a single Availability Zone",
                    "é produção e roda em uma única zona de disponibilidade"))
    days = db.get("retention")
    if not is_replica and isinstance(days, int) and days < MIN_BACKUP_DAYS:
        out.append(("BackupRetentionPeriod", days, "medium", f"automated backups are kept {days} days",
                    f"os backups automáticos ficam {days} dias"))
    if prod and db.get("deletion_protection") is False:
        out.append(("DeletionProtection", False, "low", "deletion protection is off on production",
                    "a proteção contra exclusão está desligada em produção"))
    return out


def _public(db: dict) -> tuple[str, str, str, str, str]:
    return (f"{db['id']}.PubliclyAccessible", True, "high", f"instance {db['id']} is publicly accessible",
            f"a instância {db['id']} é acessível publicamente")


@check(
    id="rds-posture",
    category="security",
    severity="high",
    title={"en": "RDS database with weak encryption, backup or availability settings",
           "pt-BR": "Banco RDS com criptografia, backup ou disponibilidade fracos"},
    requires=[RDS_INSTANCES, RDS_CLUSTERS],
    catalog_ids=["datastore-deletion-protection-pitr-off"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        instances = [i for i in snap.items(RDS_INSTANCES, region) if i]
        by_cluster: dict[str, list[dict]] = {}
        for i in instances:
            if i.get("cluster"):
                by_cluster.setdefault(i["cluster"], []).append(i)
        clusters = {c["id"]: c for c in snap.items(RDS_CLUSTERS, region) if c}
        for i in instances:
            if i.get("cluster") and i["cluster"] in clusters:
                continue
            env = env_of(i.get("tags"))
            issues = _issues(i, env, bool(i.get("replica_of")))
            if i.get("public"):
                issues.append(_public(i))
            if issues:
                findings.append(_finding(snap, region, "instance", i, env, issues))
        for cid, c in clusters.items():
            env = env_of(c.get("tags"))
            issues = _issues(c, env, False)
            issues += [_public(m) for m in by_cluster.get(cid, []) if m.get("public")]
            if issues:
                findings.append(_finding(snap, region, "cluster", c, env, issues))
    return findings


def _finding(snap, region, kind, db, env, issues):
    name = db["id"]
    severity = min((i[2] for i in issues), key=SEVERITIES.index)
    security = any(i[0].endswith(("StorageEncrypted", "PubliclyAccessible")) for i in issues)
    root = "DBClusters" if kind == "cluster" else "DBInstances"
    env_en = {"prod": "tagged production", "nonprod": "tagged non-production"}.get(env, "with no environment tag")
    env_pt = {"prod": "marcado como produção", "nonprod": "marcado como não produção"}.get(env, "sem tag de ambiente")
    label_en = "RDS cluster" if kind == "cluster" else "RDS instance"
    label_pt = "O cluster RDS" if kind == "cluster" else "A instância RDS"
    if kind == "cluster":
        cmd = f"aws rds describe-db-clusters --db-cluster-identifier {name} --region {region} "
        fields = "DBClusters[].[StorageEncrypted,MultiAZ,BackupRetentionPeriod,DeletionProtection]"
    else:
        cmd = f"aws rds describe-db-instances --db-instance-identifier {name} --region {region} "
        fields = "DBInstances[].[StorageEncrypted,MultiAZ,BackupRetentionPeriod,PubliclyAccessible,DeletionProtection]"
    return Finding(
        check_id="rds-posture",
        resource=db.get("arn") or name,
        severity=severity,
        category="security" if security else "resilience",
        region=region,
        text={
            "en": {
                "title": f"{label_en} {name} has {len(issues)} posture issue{'s' if len(issues) > 1 else ''}",
                "what": f"{label_en} {name} ({db.get('engine')}, {env_en}): " + "; ".join(i[3] for i in issues) + ".",
                "risk": "Unencrypted or public databases expose data; single-AZ, short backups and no deletion "
                        "protection turn one mistake or outage into data loss.",
                "fix": "Encrypt by restoring an encrypted snapshot copy, turn off public access, keep backups for 7 "
                       "days or more, and on production enable Multi-AZ and deletion protection, all in IaC.",
            },
            "pt-BR": {
                "title": f"{label_pt} {name} tem {len(issues)} problema{'s' if len(issues) > 1 else ''} de "
                         "configuração",
                "what": f"{label_pt} {name} ({db.get('engine')}, {env_pt}): " + "; ".join(i[4] for i in issues)
                        + ".",
                "risk": "Banco sem criptografia ou público expõe dados; zona única, backup curto e sem proteção "
                        "contra exclusão fazem um erro ou queda virar perda de dados.",
                "fix": "Criptografar restaurando uma cópia criptografada do snapshot, desligar o acesso público, "
                       "manter backup por 7 dias ou mais e, em produção, ligar Multi-AZ e proteção contra exclusão, "
                       "tudo no IaC.",
            },
        },
        claims=[Claim(f"rds:DescribeDBInstances@{region}", i[0], i[1]) if "." in i[0]
                else Claim(f"rds:Describe{root}@{region}", f"{name}.{i[0]}", i[1]) for i in issues],
        confidence="high" if env else "medium",
        notes=[] if env else ["No environment tag found, so the database was treated as production for encryption."],
        verify=[
            cmd + f"--query '{fields}' --output table",
            f"aws rds list-tags-for-resource --resource-name {db.get('arn') or name} --region {region} "
            "--query 'TagList[].[Key,Value]' --output table",
        ],
    )
