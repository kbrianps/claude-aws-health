from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..calls_compute import FUNCTIONS
from ..model import Claim, Finding
from ..registry import check

TABLE = json.loads((Path(__file__).resolve().parent.parent / "data" / "lambda_runtimes.json").read_text())
WARN_DAYS = 180


def _date(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc) if value else None


@check(
    id="lambda-deprecated-runtime",
    category="outdated",
    severity="medium",
    title={"en": "Lambda functions on a deprecated runtime", "pt-BR": "Funções Lambda em runtime descontinuado"},
    requires=[FUNCTIONS],
    catalog_ids=["lambda-deprecated-runtime", "lambda-al2-based-runtime"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        by_runtime: dict[str, list[dict]] = {}
        for f in snap.items(FUNCTIONS, region):
            if f and f.get("runtime") in TABLE["runtimes"]:
                by_runtime.setdefault(f["runtime"], []).append(f)
        for runtime, funcs in sorted(by_runtime.items()):
            row = TABLE["runtimes"][runtime]
            dep, create, update = (_date(row.get(k)) for k in ("deprecation", "block_create", "block_update"))
            if update and update <= ctx.now:
                severity, state_en, state_pt = "high", "updates are already blocked", "atualizações já estão bloqueadas"
            elif dep and dep <= ctx.now:
                severity, state_en, state_pt = "medium", "is deprecated", "está descontinuado"
            elif dep and (dep - ctx.now).days <= WARN_DAYS:
                days = (dep - ctx.now).days
                severity, state_en, state_pt = "low", f"is deprecated in {days} days", f"é descontinuado em {days} dias"
            else:
                continue
            upcoming = sorted(d for d in (dep, create, update) if d and d > ctx.now)
            deadline = upcoming[0] if upcoming else None
            funcs.sort(key=lambda f: f["name"])
            names = ", ".join(f["name"] for f in funcs[:10])
            more = f" and {len(funcs) - 10} more" if len(funcs) > 10 else ""
            more_pt = f" e mais {len(funcs) - 10}" if len(funcs) > 10 else ""
            dates = (f"deprecation {row.get('deprecation')}, block create {row.get('block_create')}, "
                     f"block update {row.get('block_update')}")
            dates_pt = (f"descontinuação {row.get('deprecation')}, bloqueio de criação {row.get('block_create')}, "
                        f"bloqueio de atualização {row.get('block_update')}")
            plural, noun_pt = ("s", "funções") if len(funcs) > 1 else ("", "função")
            findings.append(Finding(
                check_id="lambda-deprecated-runtime",
                resource=f"arn:aws:lambda:{region}:{snap.account_id}:runtime/{runtime}",
                resources=[f["arn"] for f in funcs],
                severity=severity,
                category="outdated",
                region=region,
                text={
                    "en": {
                        "title": f"{len(funcs)} Lambda function{plural} in {region} on {runtime}, which {state_en}",
                        "what": f"Functions on {runtime}: {names}{more}. Lambda dates: {dates}.",
                        "risk": "A deprecated runtime gets no security patches or support. After the block update "
                                "date you can no longer change code or configuration, so an urgent fix needs a "
                                "runtime upgrade first.",
                        "fix": "Upgrade each function to a supported runtime on Amazon Linux 2023, test it, and "
                               "change the runtime in IaC. Also check layers built for this runtime.",
                    },
                    "pt-BR": {
                        "title": f"{len(funcs)} {noun_pt} Lambda em {region} no {runtime}, que {state_pt}",
                        "what": f"Funções em {runtime}: {names}{more_pt}. Datas da Lambda: {dates_pt}.",
                        "risk": "Runtime descontinuado não recebe patch de segurança nem suporte. Depois da data de "
                                "bloqueio de atualização não dá mais para mudar código nem configuração, então uma "
                                "correção urgente exige trocar o runtime antes.",
                        "fix": "Subir cada função para um runtime suportado no Amazon Linux 2023, testar e mudar o "
                               "runtime no IaC. Ver também as layers feitas para esse runtime.",
                    },
                },
                claims=[Claim(f"lambda:ListFunctions@{region}", f"{f['name']}.Runtime", runtime)
                        for f in funcs[:10]]
                + [Claim("lambda-runtimes", runtime, row | {"source": TABLE["source"]})],
                deadline=deadline.isoformat() if deadline else "",
                verify=[
                    f"aws lambda list-functions --region {region} "
                    f"--query \"Functions[?Runtime=='{runtime}'].[FunctionName,Runtime,LastModified]\" --output table",
                    f"aws lambda list-layers --compatible-runtime {runtime} --region {region} "
                    "--query 'Layers[].[LayerName,LatestMatchingVersion.Version]' --output table",
                ],
            ))
    return findings
