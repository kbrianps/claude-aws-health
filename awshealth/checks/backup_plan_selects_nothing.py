from __future__ import annotations

from ..calls_security import (
    BACKUP_PLAN,
    BACKUP_PLANS,
    BACKUP_SELECTION,
    BACKUP_SELECTIONS,
    BACKUP_VAULTS,
    TAGGED_RESOURCES,
    backup_supported,
    is_prod,
    near_miss,
    selection_matches,
    wanted_tags,
)
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "backup-plan-selects-nothing"


def _is_database(arn: str) -> bool:
    return ":rds:" in arn or ":dynamodb:" in arn or ":redshift:" in arn


@check(
    id=CHECK_ID,
    category="resilience",
    severity="medium",
    title={"en": "Backup plan selection matches no resource",
           "pt-BR": "Seleção do plano de backup não pega nenhum recurso"},
    requires=[BACKUP_PLANS, BACKUP_PLAN, BACKUP_SELECTIONS, BACKUP_SELECTION, BACKUP_VAULTS, TAGGED_RESOURCES],
    catalog_ids=["backup-resources-not-covered", "backup-failed-jobs"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        if snap.status(TAGGED_RESOURCES, region) != "ok":
            continue
        inventory = [r for r in snap.items(TAGGED_RESOURCES, region) if r and backup_supported(r.get("arn", ""))]
        plans = {p["id"]: p.get("name", p["id"]) for p in snap.items(BACKUP_PLANS, region) if p}
        plan_vaults = snap.per_item(BACKUP_PLAN, region)
        vault_points = {v["name"]: v.get("recovery_points") for v in snap.items(BACKUP_VAULTS, region) if v}
        for sel in snap.per_item(BACKUP_SELECTION, region).values():
            if not isinstance(sel, dict) or "__error__" in sel:
                continue
            wanted = wanted_tags(sel)
            if not wanted or any(selection_matches(sel, r["arn"], r.get("tags")) for r in inventory):
                continue
            misses = []
            for r in inventory:
                for key, value in wanted:
                    hit = near_miss(key, value, r.get("tags"))
                    if hit:
                        misses.append((r["arn"], hit, is_prod(r.get("tags"), r["arn"].split(":")[-1].split("/")[-1])))
                        break
            prod_db_miss = any(prod and _is_database(arn) for arn, _, prod in misses)
            plan_id = sel.get("plan", "")
            plan_name = plans.get(plan_id, plan_id)
            sel_name = sel.get("name") or sel.get("id", "")
            want_txt = ", ".join(f"{k}={v}" for k, v in wanted)
            vaults = [v for v in plan_vaults.get(plan_id) or [] if isinstance(v, str)]
            empty = [v for v in vaults if vault_points.get(v) == 0]
            vault_en = f" Target vault(s) with 0 recovery points: {', '.join(empty)}." if empty else ""
            vault_pt = f" Cofre(s) de destino com 0 pontos de recuperação: {', '.join(empty)}." if empty else ""
            shown = misses[:5]
            miss_en = " Near misses: " + "; ".join(f"{arn} has {hit}" for arn, hit, _ in shown) + "." if shown else ""
            miss_pt = " Quase iguais: " + "; ".join(f"{arn} tem {hit}" for arn, hit, _ in shown) + "." if shown else ""
            claims = [Claim(f"backup:GetBackupSelection@{region}", f"{plan_id}/{sel.get('id')}.tags", want_txt),
                      Claim(f"tag:GetResources@{region}", "matching_resources", 0)]
            claims += [Claim(f"tag:GetResources@{region}", f"{arn}.Tags", hit) for arn, hit, _ in misses[:5]]
            claims += [Claim(f"backup:ListBackupVaults@{region}", f"{v}.NumberOfRecoveryPoints", 0) for v in empty]
            findings.append(Finding(
                check_id=CHECK_ID,
                resource=f"backup-plan/{plan_id}/selection/{sel.get('id')}",
                resources=[f"backup-plan/{plan_id}/selection/{sel.get('id')}"] + [arn for arn, _, _ in misses],
                severity="high" if prod_db_miss else "medium",
                category="resilience",
                region=region,
                text={
                    "en": {
                        "title": f"Backup plan {plan_name} selection {sel_name} matches no resource in {region}",
                        "what": f"The selection wants tags {want_txt}, and no supported resource in {region} carries "
                                f"them.{miss_en}{vault_en}",
                        "risk": "The plan looks healthy in the console and runs on schedule, but it backs up "
                                "nothing. The first restore attempt will find no recovery point.",
                        "fix": "Fix the tag on the resources (or the selection) so the key and value match exactly, "
                               "including case, then confirm a backup job runs.",
                    },
                    "pt-BR": {
                        "title": f"A seleção {sel_name} do plano de backup {plan_name} não pega nenhum recurso em "
                                 f"{region}",
                        "what": f"A seleção espera as tags {want_txt}, e nenhum recurso compatível em {region} tem "
                                f"essas tags.{miss_pt}{vault_pt}",
                        "risk": "O plano parece saudável no console e roda no horário, mas não faz backup de nada. "
                                "A primeira tentativa de restauração não vai achar ponto de recuperação.",
                        "fix": "Corrigir a tag nos recursos (ou na seleção) para que chave e valor batam "
                               "exatamente, inclusive maiúsculas e minúsculas, e confirmar que um job de backup "
                               "roda.",
                    },
                },
                claims=claims,
                verify=[
                    f"aws backup get-backup-selection --backup-plan-id {plan_id} --selection-id {sel.get('id')} "
                    f"--region {region} --query 'BackupSelection.[ListOfTags,Conditions]' --output json",
                    f"aws backup list-backup-jobs --by-backup-vault-name {vaults[0]} --region {region} --query "
                    "'BackupJobs[].[ResourceArn,State,CreationDate]' --output table" if vaults else
                    f"aws backup list-backup-jobs --region {region} --query "
                    "'BackupJobs[].[ResourceArn,State,CreationDate]' --output table",
                    f"aws resourcegroupstaggingapi get-resources --region {region} --tag-filters Key={wanted[0][0]} "
                    "--query 'ResourceTagMappingList[].ResourceARN' --output text",
                ],
            ))
    return findings
