from __future__ import annotations

from ..calls_security import SECRETS, days_since
from ..model import Claim, Finding
from ..prices import price, source
from ..registry import check

CHECK_ID = "secrets-not-rotated"


@check(
    id=CHECK_ID,
    category="security",
    severity="low",
    title={"en": "Secret not rotated in a year or not used in 90 days",
           "pt-BR": "Segredo sem rotação há um ano ou sem uso há 90 dias"},
    requires=[SECRETS],
    catalog_ids=["secretsmanager-secret-unused", "secretsmanager-rotation-failing"],
)
def run(snap, ctx):
    monthly = price("secretsmanager_secret_month")
    findings = []
    for region in snap.regions:
        for s in snap.items(SECRETS, region):
            if not s or s.get("owner"):
                continue
            name = s.get("name", "")
            changed = days_since(s.get("changed") or s.get("created"), ctx.now) or 0
            accessed = s.get("accessed")
            idle = days_since(accessed or s.get("created"), ctx.now) or 0
            stale = not s.get("rotation") and changed > 365
            unused = idle > 90
            if not stale and not unused:
                continue
            what_en, what_pt, title_en, title_pt = [], [], [], []
            if stale:
                what_en.append(f"rotation is off and the value last changed {changed} days ago")
                what_pt.append(f"a rotação está desligada e o valor mudou pela última vez há {changed} dias")
                title_en.append("not rotated in over a year")
                title_pt.append("sem rotação há mais de um ano")
            if unused:
                last_en = f"last read on {str(accessed)[:10]}" if accessed else "never read"
                last_pt = f"lido pela última vez em {str(accessed)[:10]}" if accessed else "nunca foi lido"
                what_en.append(f"{last_en}, {idle} days without use")
                what_pt.append(f"{last_pt}, {idle} dias sem uso")
                title_en.append("unused for 90+ days")
                title_pt.append("sem uso há 90+ dias")
            findings.append(Finding(
                check_id=CHECK_ID,
                resource=s.get("arn") or name,
                severity="low",
                category="security" if stale else "zombie",
                region=region,
                text={
                    "en": {
                        "title": f"Secret {name} is " + " and ".join(title_en),
                        "what": f"In secret {name} ({region}), " + "; ".join(what_en) + ".",
                        "risk": "A credential that never changes stays valid wherever it leaked. An unused secret "
                                "still costs money and is one more thing to protect.",
                        "fix": "Turn on rotation, or rotate the credential at the source and update the secret. If "
                               "nothing reads it anymore, schedule deletion with a recovery window.",
                    },
                    "pt-BR": {
                        "title": f"O segredo {name} está " + " e ".join(title_pt),
                        "what": f"No segredo {name} ({region}), " + "; ".join(what_pt) + ".",
                        "risk": "Uma credencial que nunca muda continua válida onde quer que tenha vazado. Um "
                                "segredo sem uso ainda custa dinheiro e é mais uma coisa para proteger.",
                        "fix": "Ligar a rotação, ou trocar a credencial na origem e atualizar o segredo. Se nada "
                               "mais lê o segredo, agendar a exclusão com janela de recuperação.",
                    },
                },
                claims=[Claim(f"secretsmanager:ListSecrets@{region}", f"{name}.RotationEnabled",
                              bool(s.get("rotation"))),
                        Claim(f"secretsmanager:ListSecrets@{region}", f"{name}.LastChangedDate", s.get("changed")),
                        Claim(f"secretsmanager:ListSecrets@{region}", f"{name}.LastAccessedDate", accessed)],
                monthly_usd=monthly if unused else None,
                usd_calc=(f"1 secret x US${monthly:.2f}/month ({source('secretsmanager_secret_month')})"
                          if unused else ""),
                owner_question=({"en": f"Is {name} a break-glass, DR or yearly-job credential?",
                                 "pt-BR": f"{name} é uma credencial de emergência, de DR ou de rotina anual?"}
                                if unused else {}),
                verify=[
                    f"aws secretsmanager describe-secret --secret-id {name} --region {region} --query "
                    "'[RotationEnabled,LastChangedDate,LastAccessedDate]' --output text",
                ],
            ))
    return findings
