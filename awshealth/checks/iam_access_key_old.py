from __future__ import annotations

from shlex import quote

from ..calls_security import ACCESS_KEYS, KEY_LAST_USED, USERS, days_since
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "iam-access-key-old"


@check(
    id=CHECK_ID,
    category="security",
    severity="medium",
    title={"en": "Old or unused active IAM access keys",
           "pt-BR": "Chaves de acesso IAM ativas antigas ou sem uso"},
    requires=[USERS, ACCESS_KEYS, KEY_LAST_USED],
    catalog_ids=["iam-access-key-age", "iam-access-key-unused"],
)
def run(snap, ctx):
    arns = {u.get("name"): u.get("arn") for u in snap.items(USERS, "global")}
    last_used = snap.per_item(KEY_LAST_USED, "global")
    findings = []
    for name, keys in sorted(snap.per_item(ACCESS_KEYS, "global").items()):
        old, unused, claims = [], [], []
        for k in keys if isinstance(keys, list) else []:
            if k.get("status") != "Active":
                continue
            age = days_since(k.get("created"), ctx.now) or 0
            entry = last_used.get(k["id"])
            lu = entry.get("last_used") if isinstance(entry, dict) else None
            known = isinstance(entry, dict) and "__error__" not in entry
            idle = (days_since(lu, ctx.now) if lu else age) if known else 0
            if idle > 90:
                unused.append((k["id"], str(lu)[:10] if lu else ""))
            elif age > 90:
                old.append((k["id"], age))
            if age > 90 or idle > 90:
                claims.append(Claim("iam:ListAccessKeys@global", f"{name}.{k['id']}.CreateDate", k.get("created")))
                claims.append(Claim("iam:GetAccessKeyLastUsed@global", f"{k['id']}.LastUsedDate", lu))
        if not old and not unused:
            continue
        parts_en, parts_pt = [], []
        if old:
            parts_en.append("in use but not rotated in over 90 days: "
                            + ", ".join(f"{kid} ({age} days)" for kid, age in old))
            parts_pt.append("em uso mas sem rotação há mais de 90 dias: "
                            + ", ".join(f"{kid} ({age} dias)" for kid, age in old))
        if unused:
            parts_en.append("unused for 90+ days: "
                            + ", ".join(f"{kid} (last used {lu or 'never'})" for kid, lu in unused))
            parts_pt.append("sem uso há 90+ dias: "
                            + ", ".join(f"{kid} (último uso {lu or 'nunca'})" for kid, lu in unused))
        findings.append(Finding(
            check_id=CHECK_ID,
            resource=arns.get(name) or name,
            severity="medium" if old else "low",
            category="security",
            region="global",
            text={
                "en": {
                    "title": f"IAM user {name} has active access keys that are old or unused",
                    "what": f"Active keys of {name} " + "; ".join(parts_en) + ".",
                    "risk": "Long-lived keys pile up in laptops, CI settings and old scripts. The longer they live, "
                            "the more likely one has leaked.",
                    "fix": "Deactivate unused keys and delete them after a quiet week. Rotate keys still in use, or "
                           "move the workload to a role.",
                },
                "pt-BR": {
                    "title": f"O usuário IAM {name} tem chaves de acesso ativas antigas ou sem uso",
                    "what": f"Chaves ativas de {name} " + "; ".join(parts_pt) + ".",
                    "risk": "Chaves de longa duração se espalham por notebooks, configurações de CI e scripts "
                            "antigos. Quanto mais tempo vivem, maior a chance de uma ter vazado.",
                    "fix": "Desativar as chaves sem uso e apagar depois de uma semana sem reclamação. Fazer rotação "
                           "das que estão em uso ou passar o uso para uma role.",
                },
            },
            claims=claims,
            owner_question=({"en": f"Are the unused keys of {name} used by a quarterly or yearly job?",
                             "pt-BR": f"As chaves sem uso de {name} servem a alguma rotina trimestral ou anual?"}
                            if unused else {}),
            verify=[
                f"aws iam list-access-keys --user-name {quote(name)} --region us-east-1 --query "
                "'AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]' --output table",
            ] + [f"aws iam get-access-key-last-used --access-key-id {quote(kid)} --region us-east-1 --query "
                 "'AccessKeyLastUsed.[LastUsedDate,ServiceName]' --output text"
                 for kid, _ in (unused or old)[:2]],
        ))
    return findings
