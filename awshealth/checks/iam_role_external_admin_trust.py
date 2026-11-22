from __future__ import annotations

import re

from ..calls_security import AUTH_DETAILS, admin_policy_arns, admin_reason, as_list, days_since
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "iam-role-external-admin-trust"
_ACCOUNT = re.compile(r"^(?:arn:aws[a-z-]*:iam::)?(\d{12})(?::|$)")


def trusted_accounts(trust, own: str) -> tuple[set[str], set[str]]:
    external, without_external_id = set(), set()
    for s in as_list(trust):
        if not isinstance(s, dict) or s.get("effect") != "Allow":
            continue
        keys = {k.lower() for k in s.get("condition_keys") or []}
        if "aws:principalorgid" in keys:
            continue
        p = s.get("principal")
        principals = ["*"] if p == "*" else as_list(p.get("AWS")) if isinstance(p, dict) else []
        for value in principals:
            m = _ACCOUNT.match(str(value))
            acct = "*" if value == "*" else (m.group(1) if m else "")
            if not acct or acct == own:
                continue
            external.add(acct)
            if "sts:externalid" not in keys:
                without_external_id.add(acct)
    return external, without_external_id


@check(
    id=CHECK_ID,
    category="security",
    severity="high",
    title={"en": "Role trusted by another account with admin access and no external ID",
           "pt-BR": "Role confiada a outra conta com acesso de administrador e sem external ID"},
    requires=[AUTH_DETAILS],
    catalog_ids=["accessanalyzer-external-access", "iam-role-unused"],
)
def run(snap, ctx):
    auth = snap.get(AUTH_DETAILS, "global") or {}
    admin_arns = admin_policy_arns(auth)
    findings = []
    for role in auth.get("roles") or []:
        if (role.get("path") or "").startswith("/aws-service-role/"):
            continue
        external, no_id = trusted_accounts(role.get("trust"), ctx.account_id)
        if not external:
            continue
        name = role["name"]
        admin = admin_reason(role, admin_arns)
        last = role.get("last_used")
        idle = days_since(last, ctx.now) if last else days_since(role.get("created"), ctx.now)
        unused = (idle or 0) > 365
        used_en = f"last used {str(last)[:10]}" if last else "never used"
        used_pt = f"último uso em {str(last)[:10]}" if last else "nunca usada"
        accounts = ", ".join(sorted(no_id or external))
        claims = [
            Claim("iam:GetAccountAuthorizationDetails@global", f"{name}.AssumeRolePolicyDocument.Principal.AWS",
                  sorted(external)),
            Claim("iam:GetAccountAuthorizationDetails@global", f"{name}.RoleLastUsed.LastUsedDate", last),
        ]
        verify = [
            f"aws iam get-role --role-name {name} --region us-east-1 --query "
            "'Role.AssumeRolePolicyDocument.Statement[].[Effect,Principal.AWS]' --output text",
            f"aws iam get-role --role-name {name} --region us-east-1 --query 'Role.RoleLastUsed' --output table",
            f"aws iam list-attached-role-policies --role-name {name} --region us-east-1 --query "
            "'AttachedPolicies[].PolicyArn' --output text",
        ]
        question = {"en": f"Who uses role {name} from account(s) {accounts}, and is it still needed?",
                    "pt-BR": f"Quem usa a role {name} a partir da(s) conta(s) {accounts}, e ela ainda é necessária?"}
        if admin and no_id:
            claims.append(Claim("iam:GetAccountAuthorizationDetails@global", f"{name}.admin", admin))
            anyone_en = " Principal * means any AWS account." if "*" in no_id else ""
            anyone_pt = " Principal * significa qualquer conta AWS." if "*" in no_id else ""
            findings.append(Finding(
                check_id=CHECK_ID,
                resource=role.get("arn") or name,
                severity="high",
                category="security",
                region="global",
                text={
                    "en": {
                        "title": f"Role {name} gives administrator access to account(s) {accounts} without an "
                                 "external ID",
                        "what": f"The trust policy of {name} lets {accounts} assume it with no sts:ExternalId "
                                f"condition, and the role has administrator access through {admin}. It was "
                                f"{used_en}.{anyone_en}",
                        "risk": "Anyone in the trusted account who can call sts:AssumeRole on this role gets full "
                                "control here. Without an external ID a vendor can be tricked into using it for "
                                "someone else (confused deputy).",
                        "fix": "Replace administrator access with the permissions the trusted party needs, and "
                               "require sts:ExternalId (for vendors) or aws:PrincipalOrgID (for your own accounts) "
                               "in the trust policy.",
                    },
                    "pt-BR": {
                        "title": f"A role {name} dá acesso de administrador à(s) conta(s) {accounts} sem external ID",
                        "what": f"A trust policy de {name} permite que {accounts} assuma a role sem condição "
                                f"sts:ExternalId, e a role tem acesso de administrador por {admin}. Situação de uso: "
                                f"{used_pt}.{anyone_pt}",
                        "risk": "Qualquer um na conta confiada que possa chamar sts:AssumeRole nessa role ganha "
                                "controle total aqui. Sem external ID, um fornecedor pode ser induzido a usá-la em "
                                "nome de outra pessoa (confused deputy).",
                        "fix": "Trocar o acesso de administrador pelas permissões que a outra parte precisa e "
                               "exigir sts:ExternalId (fornecedores) ou aws:PrincipalOrgID (suas próprias contas) "
                               "na trust policy.",
                    },
                },
                claims=claims,
                owner_question=question,
                verify=verify,
            ))
        elif unused:
            findings.append(Finding(
                check_id=CHECK_ID,
                resource=role.get("arn") or name,
                severity="low",
                category="security",
                region="global",
                text={
                    "en": {
                        "title": f"Role {name} trusts account(s) {accounts} and has not been used in over a year",
                        "what": f"The trust policy of {name} lets {', '.join(sorted(external))} assume it. It was "
                                f"{used_en}.",
                        "risk": "An unused door into the account. If the other account is compromised or changes "
                                "hands, this role is still open.",
                        "fix": "Confirm with the owner, then delete the role or remove the external principal from "
                               "the trust policy.",
                    },
                    "pt-BR": {
                        "title": f"A role {name} confia na(s) conta(s) {accounts} e está sem uso há mais de um ano",
                        "what": f"A trust policy de {name} permite que {', '.join(sorted(external))} assuma a role. "
                                f"Situação de uso: {used_pt}.",
                        "risk": "Uma porta de entrada sem uso. Se a outra conta for comprometida ou mudar de dono, "
                                "esta role continua aberta.",
                        "fix": "Confirmar com o responsável e então apagar a role ou tirar o principal externo da "
                               "trust policy.",
                    },
                },
                claims=claims,
                owner_question=question,
                verify=verify,
            ))
    return findings
