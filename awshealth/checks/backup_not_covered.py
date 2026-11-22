from __future__ import annotations

from ..calls_security import (
    BACKUP_SELECTION,
    DB_INSTANCES,
    DYNAMO_PITR,
    DYNAMO_TABLES,
    EFS,
    PROTECTED,
    TAGGED_RESOURCES,
    is_prod,
    selection_matches,
    tag_dict,
)
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "backup-not-covered"


def _candidates(snap, region, account):
    for db in snap.items(DB_INSTANCES, region):
        if not db or db.get("replica_of") or (db.get("retention") or 0) > 1:
            continue
        arns = [db["arn"]]
        if db.get("cluster"):
            arns.append(db["arn"].rsplit(":db:", 1)[0] + ":cluster:" + db["cluster"])
        yield ("RDS instance", db["id"], arns, db.get("tags"),
               Claim(f"rds:DescribeDBInstances@{region}", f"{db['id']}.BackupRetentionPeriod", db.get("retention")))
    pitr = snap.per_item(DYNAMO_PITR, region)
    for name in snap.items(DYNAMO_TABLES, region):
        status = pitr.get(name)
        if status == "ENABLED" or not isinstance(status, str):
            continue
        yield ("DynamoDB table", name, [f"arn:aws:dynamodb:{region}:{account}:table/{name}"], None,
               Claim(f"dynamodb:DescribeContinuousBackups@{region}", f"{name}.PointInTimeRecoveryStatus", status))
    for fs in snap.items(EFS, region):
        if fs:
            yield ("EFS file system", fs.get("name") or fs["id"], [fs["arn"]], fs.get("tags"), None)


@check(
    id=CHECK_ID,
    category="resilience",
    severity="medium",
    title={"en": "Stateful resource with no backup", "pt-BR": "Recurso com dados sem backup"},
    requires=[PROTECTED, BACKUP_SELECTION, TAGGED_RESOURCES, DB_INSTANCES, DYNAMO_TABLES, DYNAMO_PITR, EFS],
    catalog_ids=["backup-resources-not-covered", "datastore-deletion-protection-pitr-off"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        if snap.status(PROTECTED, region) != "ok":
            continue
        protected = {p.get("arn") for p in snap.items(PROTECTED, region) if p}
        tags_by_arn = {r["arn"]: tag_dict(r.get("tags")) for r in snap.items(TAGGED_RESOURCES, region) if r}
        selections = [s for s in snap.per_item(BACKUP_SELECTION, region).values()
                      if isinstance(s, dict) and "__error__" not in s]
        for kind, name, arns, own_tags, claim in _candidates(snap, region, ctx.account_id):
            tags = {**tags_by_arn.get(arns[0], {}), **tag_dict(own_tags)}
            if any(a in protected for a in arns):
                continue
            if any(selection_matches(s, a, tags) for s in selections for a in arns):
                continue
            prod = is_prod(tags, name)
            extra_en = extra_pt = ""
            if kind == "RDS instance":
                extra_en = f" Automated backup retention is {claim.value} day(s)."
                extra_pt = f" A retenção do backup automático é de {claim.value} dia(s)."
            elif kind == "DynamoDB table":
                extra_en = " Point-in-time recovery is off."
                extra_pt = " A recuperação point-in-time está desligada."
            kind_pt = {"RDS instance": "Instância RDS", "DynamoDB table": "Tabela DynamoDB",
                       "EFS file system": "Sistema de arquivos EFS"}[kind]
            claims = [Claim(f"backup:ListProtectedResources@{region}", arns[0], "absent")]
            if claim:
                claims.append(claim)
            findings.append(Finding(
                check_id=CHECK_ID,
                resource=arns[0],
                severity="high" if prod else "medium",
                category="resilience",
                region=region,
                text={
                    "en": {
                        "title": f"{kind} {name} has no backup plan and no recovery points",
                        "what": f"{kind} {name} in {region} is not selected by any AWS Backup plan and has no "
                                f"recovery point in AWS Backup.{extra_en}",
                        "risk": "A bad migration, deletion or ransomware event leaves nothing to restore beyond "
                                "what the service keeps by itself.",
                        "fix": "Add the resource to a backup plan (tag it to match an existing selection), and for "
                               "RDS raise the automated backup retention to at least 7 days.",
                    },
                    "pt-BR": {
                        "title": f"{kind_pt} {name} sem plano de backup e sem pontos de recuperação",
                        "what": f"{kind_pt} {name} em {region} não entra em nenhum plano do AWS Backup e não tem "
                                f"ponto de recuperação no AWS Backup.{extra_pt}",
                        "risk": "Uma migração errada, exclusão ou ransomware não deixa nada para restaurar além do "
                                "que o serviço guarda sozinho.",
                        "fix": "Colocar o recurso em um plano de backup (com a tag que a seleção existente espera) "
                               "e, no RDS, subir a retenção do backup automático para pelo menos 7 dias.",
                    },
                },
                claims=claims,
                owner_question={"en": f"Is {name} ephemeral or rebuilt from another source?",
                                "pt-BR": f"{name} é temporário ou é recriado a partir de outra fonte?"},
                verify=[
                    f"aws backup list-protected-resources --region {region} --query "
                    f"\"Results[?ResourceArn=='{arns[0]}'].LastBackupTime\" --output text",
                    f"aws backup list-backup-plans --region {region} --query "
                    "'BackupPlansList[].[BackupPlanName,BackupPlanId]' --output table",
                ],
            ))
    return findings
