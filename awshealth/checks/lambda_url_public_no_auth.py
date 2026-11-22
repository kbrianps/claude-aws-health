from __future__ import annotations

from shlex import quote

from ..calls_security import FUNCTION_URLS, FUNCTIONS
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "lambda-url-public-no-auth"


@check(
    id=CHECK_ID,
    category="security",
    severity="medium",
    title={"en": "Lambda function URL with no authentication",
           "pt-BR": "URL de função Lambda sem autenticação"},
    requires=[FUNCTIONS, FUNCTION_URLS],
    catalog_ids=["lambda-public-url-or-policy"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        arns = {f.get("name"): f.get("arn") for f in snap.items(FUNCTIONS, region) if f}
        for name, configs in sorted(snap.per_item(FUNCTION_URLS, region).items()):
            for cfg in configs if isinstance(configs, list) else []:
                if cfg.get("auth") != "NONE":
                    continue
                origins = cfg.get("origins") or []
                any_origin = "*" in origins
                cors_en = (" CORS allows any origin (*), so any website can call it from a visitor's browser."
                           if any_origin else "")
                cors_pt = (" O CORS libera qualquer origem (*), então qualquer site consegue chamar a função pelo "
                           "navegador de quem o visita.") if any_origin else ""
                findings.append(Finding(
                    check_id=CHECK_ID,
                    resource=arns.get(name) or name,
                    severity="high" if any_origin else "medium",
                    category="security",
                    region=region,
                    text={
                        "en": {
                            "title": f"Lambda function {name} has a public URL with no authentication",
                            "what": (f"Function {name} in {region} exposes {cfg.get('url')} with AuthType "
                                     f"NONE.{cors_en}"),
                            "risk": ("Anyone with the URL can invoke the function as often as they like, which "
                                     "costs money and reaches whatever the function can touch."),
                            "fix": ("Use AuthType AWS_IAM or put the function behind API Gateway or CloudFront with "
                                    "authentication. If it is a webhook, verify the sender's signature in code and "
                                    "restrict CORS."),
                        },
                        "pt-BR": {
                            "title": f"A função Lambda {name} tem uma URL pública sem autenticação",
                            "what": f"A função {name} em {region} expõe {cfg.get('url')} com AuthType NONE.{cors_pt}",
                            "risk": ("Quem tiver a URL invoca a função quantas vezes quiser, o que gera custo e "
                                     "alcança tudo que a função consegue acessar."),
                            "fix": ("Usar AuthType AWS_IAM ou colocar a função atrás de API Gateway ou CloudFront "
                                    "com autenticação. Se for um webhook, validar a assinatura do remetente no "
                                    "código e restringir o CORS."),
                        },
                    },
                    claims=[Claim(f"lambda:ListFunctionUrlConfigs@{region}", f"{name}.AuthType", "NONE"),
                            Claim(f"lambda:ListFunctionUrlConfigs@{region}", f"{name}.Cors.AllowOrigins", origins)],
                    owner_question={"en": f"Is {name} a public webhook that checks a signature in its code?",
                                    "pt-BR": f"{name} é um webhook público que valida assinatura no código?"},
                    verify=[
                        (f"aws lambda list-function-url-configs --function-name {quote(name)} "
                         f"--region {quote(region)} --query "
                         "'FunctionUrlConfigs[].[FunctionUrl,AuthType]' --output table"),
                        (f"aws lambda list-function-url-configs --function-name {quote(name)} "
                         f"--region {quote(region)} --query "
                         "'FunctionUrlConfigs[].Cors.AllowOrigins' --output text"),
                    ],
                ))
    return findings
