from __future__ import annotations

from shlex import quote

from ..calls_security import AUTH_DETAILS, LOGIN_PROFILE, MFA_DEVICES, USERS, days_since, iam_admins
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "iam-console-no-mfa"


@check(
    id=CHECK_ID,
    category="security",
    severity="high",
    title={"en": "IAM user with a console password and no MFA",
           "pt-BR": "Usuário IAM com senha de console e sem MFA"},
    requires=[USERS, LOGIN_PROFILE, MFA_DEVICES, AUTH_DETAILS],
    catalog_ids=["iam-console-users-without-mfa", "iam-user-unused"],
)
def run(snap, ctx):
    admins = iam_admins(snap.get(AUTH_DETAILS, "global") or {})
    profiles = snap.per_item(LOGIN_PROFILE, "global")
    mfa = snap.per_item(MFA_DEVICES, "global")
    findings = []
    for u in snap.items(USERS, "global"):
        name = u.get("name")
        profile = profiles.get(name)
        if not isinstance(profile, dict) or "__error__" in profile:
            continue
        if not isinstance(mfa.get(name), int) or mfa[name] > 0:
            continue
        admin = admins.get(name, "")
        last = u.get("password_last_used")
        profile_age = days_since(profile.get("created"), ctx.now) or 0
        never_used = not last and profile_age > 90
        if never_used:
            severity = "low"
        else:
            severity = "high" if admin else "medium"
        used_en = f"last used {str(last)[:10]}" if last else "never used"
        used_pt = f"usada pela última vez em {str(last)[:10]}" if last else "nunca usada"
        admin_en = f" The user has administrator access through {admin}." if admin else ""
        admin_pt = f" O usuário tem acesso de administrador por {admin}." if admin else ""
        findings.append(Finding(
            check_id=CHECK_ID,
            resource=u.get("arn") or name,
            severity=severity,
            category="security",
            region="global",
            text={
                "en": {
                    "title": f"IAM user {name} can sign in to the console without MFA",
                    "what": f"{name} has a console password ({used_en}, created {profile_age} days ago) and no MFA "
                            f"device.{admin_en}",
                    "risk": "A guessed, reused or phished password is enough to sign in.",
                    "fix": "Register an MFA device for the user, or delete the login profile if the user does not "
                           "need the console. Prefer IAM Identity Center for people.",
                },
                "pt-BR": {
                    "title": f"O usuário IAM {name} entra no console sem MFA",
                    "what": f"{name} tem senha de console ({used_pt}, criada há {profile_age} dias) e nenhum "
                            f"dispositivo MFA.{admin_pt}",
                    "risk": "Uma senha adivinhada, reutilizada ou roubada por phishing basta para entrar.",
                    "fix": "Cadastrar um dispositivo MFA para o usuário, ou apagar o login profile se ele não usa o "
                           "console. Para pessoas, preferir o IAM Identity Center.",
                },
            },
            claims=[
                Claim("iam:GetLoginProfile@global", f"{name}.CreateDate", profile.get("created")),
                Claim("iam:ListMFADevices@global", f"length({name}.MFADevices)", mfa[name]),
                Claim("iam:ListUsers@global", f"{name}.PasswordLastUsed", last),
            ],
            owner_question=({"en": f"The password of {name} was never used. Does anyone still need console access "
                                   "for this user?",
                             "pt-BR": f"A senha de {name} nunca foi usada. Alguém ainda precisa de acesso ao console "
                                      "com esse usuário?"}
                            if never_used else {}),
            verify=[
                f"aws iam get-login-profile --user-name {quote(name)} --region us-east-1 "
                "--query 'LoginProfile.CreateDate' "
                "--output text",
                f"aws iam list-mfa-devices --user-name {quote(name)} --region us-east-1 --query 'length(MFADevices)' "
                "--output text",
            ],
        ))
    return findings
