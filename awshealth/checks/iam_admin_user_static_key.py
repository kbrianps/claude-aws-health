from __future__ import annotations

from ..calls_security import (
    ACCESS_KEYS,
    AUTH_DETAILS,
    KEY_LAST_USED,
    USERS,
    days_since,
    iam_admins,
    is_break_glass,
)
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "iam-admin-user-static-key"


@check(
    id=CHECK_ID,
    category="security",
    severity="high",
    title={"en": "Administrator IAM user with an active access key",
           "pt-BR": "Usuário IAM administrador com chave de acesso ativa"},
    requires=[AUTH_DETAILS, USERS, ACCESS_KEYS, KEY_LAST_USED],
    catalog_ids=["iam-access-key-age", "iam-access-key-unused"],
)
def run(snap, ctx):
    auth = snap.get(AUTH_DETAILS, "global") or {}
    admins = iam_admins(auth)
    users = {u["name"]: u for u in auth.get("users") or []}
    keys_by_user = snap.per_item(ACCESS_KEYS, "global")
    last_used = snap.per_item(KEY_LAST_USED, "global")
    findings = []
    for name, reason in sorted(admins.items()):
        keys = [k for k in keys_by_user.get(name) or [] if isinstance(k, dict) and k.get("status") == "Active"]
        if not keys:
            continue
        rows, claims, oldest = [], [], 0
        for k in keys:
            age = days_since(k.get("created"), ctx.now) or 0
            oldest = max(oldest, age)
            lu_entry = last_used.get(k["id"])
            known = isinstance(lu_entry, dict) and "__error__" not in lu_entry
            lu = lu_entry.get("last_used") if known else None
            rows.append((k["id"], age, str(lu)[:10] if lu else ("never" if known else "unknown")))
            claims.append(Claim("iam:ListAccessKeys@global", f"{name}.{k['id']}.CreateDate", k.get("created")))
            claims.append(Claim("iam:GetAccessKeyLastUsed@global", f"{k['id']}.LastUsedDate", lu))
        claims.insert(0, Claim("iam:GetAccountAuthorizationDetails@global", f"{name}.admin", reason))
        severity = "critical" if oldest > 365 else "high"
        detail_en = "; ".join(f"{kid} is {age} days old, last used {used}" for kid, age, used in rows)
        used_pt = {"never": "nunca", "unknown": "desconhecido"}
        detail_pt = "; ".join(f"{kid} tem {age} dias, último uso {used_pt.get(used, used)}" for kid, age, used in rows)
        user = users.get(name, {})
        bg = is_break_glass(name, user.get("tags"))
        findings.append(Finding(
            check_id=CHECK_ID,
            resource=user.get("arn") or name,
            severity=severity,
            category="security",
            region="global",
            text={
                "en": {
                    "title": f"IAM user {name} has administrator access and {len(keys)} active access key(s)",
                    "what": f"{name} gets administrator access through {reason}. Active keys: {detail_en}.",
                    "risk": "A leaked long-lived key gives full control of the account until someone notices and "
                            "revokes it.",
                    "fix": "Move the workload to a role (IAM Identity Center for people, instance or task roles for "
                           "software), then deactivate and delete the key. If a key must stay, scope its policy "
                           "down and rotate it.",
                },
                "pt-BR": {
                    "title": f"O usuário IAM {name} tem acesso de administrador e {len(keys)} chave(s) de acesso "
                             "ativa(s)",
                    "what": f"{name} tem acesso de administrador por {reason}. Chaves ativas: {detail_pt}.",
                    "risk": "Uma chave de longa duração vazada dá controle total da conta até alguém perceber e "
                            "revogar.",
                    "fix": "Passar o uso para uma role (IAM Identity Center para pessoas, role de instância ou de "
                           "task para sistemas), depois desativar e apagar a chave. Se a chave precisar ficar, "
                           "reduzir a política e fazer rotação.",
                },
            },
            claims=claims,
            owner_question=({"en": f"Is {name} a break-glass user, and who holds its key?",
                             "pt-BR": f"{name} é um usuário de emergência (break-glass), e quem guarda a chave?"}
                            if bg else {}),
            verify=[
                f"aws iam list-access-keys --user-name {name} --region us-east-1 --query "
                "'AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]' --output table",
                f"aws iam list-attached-user-policies --user-name {name} --region us-east-1 --query "
                "'AttachedPolicies[].PolicyArn' --output text",
                f"aws iam list-groups-for-user --user-name {name} --region us-east-1 --query 'Groups[].GroupName' "
                "--output text",
            ],
        ))
    return findings
