from __future__ import annotations

import re
from typing import Any

from ..model import Claim, Finding

SAFE_ID = re.compile(r"[A-Za-z0-9_+=/.-]{1,256}")
EFFORT_PT = {"VeryLow": "muito baixo", "Low": "baixo", "Medium": "médio", "High": "alto", "VeryHigh": "muito alto"}


def items(data: Any) -> list[dict] | None:
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        data = data["items"]
    if isinstance(data, list) and any(isinstance(d, dict) and "recommendationId" in d for d in data):
        return [d for d in data if isinstance(d, dict)]
    return None


def _severity(savings: float) -> str:
    if savings >= 1000:
        return "high"
    if savings >= 100:
        return "medium"
    return "low"


def to_finding(item: dict) -> Finding:
    rec_id = str(item.get("recommendationId", ""))
    action = str(item.get("actionType") or "Unknown")
    rtype = str(item.get("currentResourceType") or "resource")
    resource = str(item.get("resourceArn") or item.get("resourceId") or rec_id)
    region = str(item.get("region") or "global")
    savings = round(float(item.get("estimatedMonthlySavings") or 0), 2)
    effort = str(item.get("implementationEffort") or "")
    restart = bool(item.get("restartNeeded"))
    slug = re.sub(r"(?<!^)(?=[A-Z])", "-", action).lower()
    savings_pt = f"{savings:,.2f}".replace(",", "_").replace(".", ",").replace("_", ".")
    restart_en = "Needs a restart." if restart else "No restart needed."
    restart_pt = "Precisa reiniciar." if restart else "Não precisa reiniciar."
    effort_en = f" Implementation effort: {effort}." if effort else ""
    effort_pt = f" Esforço de implementação: {EFFORT_PT.get(effort, effort)}." if effort else ""
    return Finding(
        check_id=f"coh-{slug}",
        resource=resource,
        severity=_severity(savings),
        category="cost",
        region=region,
        text={
            "en": {
                "title": f"Cost Optimization Hub: {action} {rtype} {resource} to save about US${savings:,.2f}/month",
                "what": f"Imported from Cost Optimization Hub. Recommendation {rec_id}: {action} for {rtype} "
                        f"{resource}.{effort_en} {restart_en}",
                "risk": "",
                "fix": f"Review the recommendation in Cost Optimization Hub and apply the {action} action after "
                       "checking the workload.",
            },
            "pt-BR": {
                "title": f"Cost Optimization Hub: {action} em {rtype} {resource} economiza cerca de "
                         f"US$ {savings_pt}/mês",
                "what": f"Importado do Cost Optimization Hub. Recomendação {rec_id}: {action} para {rtype} "
                        f"{resource}.{effort_pt} {restart_pt}",
                "risk": "",
                "fix": f"Revisar a recomendação no Cost Optimization Hub e aplicar a ação {action} depois de "
                       "conferir a carga de trabalho.",
            },
        },
        claims=[
            Claim("cost-optimization-hub:ListRecommendations@us-east-1", f"{rec_id}.estimatedMonthlySavings",
                  item.get("estimatedMonthlySavings")),
            Claim("cost-optimization-hub:ListRecommendations@us-east-1", f"{rec_id}.actionType", action),
        ],
        monthly_usd=savings or None,
        usd_calc=f"estimatedMonthlySavings of recommendation {rec_id} from Cost Optimization Hub" if savings else "",
        verify=[
            f"aws cost-optimization-hub get-recommendation --recommendation-id {rec_id} --region us-east-1 "
            "--query '[actionType,currentResourceType,estimatedMonthlySavings]' --output text",
        ] if SAFE_ID.fullmatch(rec_id) else [],
        source="cost-optimization-hub",
    )


def load(data: list[dict]) -> list[Finding]:
    return [to_finding(d) for d in data]
