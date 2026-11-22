from __future__ import annotations

from shlex import quote

from ..calls_compute import CERTIFICATES, parse_time
from ..model import Claim, Finding
from ..registry import check

WARN_DAYS = 45
URGENT_DAYS = 14


@check(
    id="acm-expiry",
    category="errors",
    severity="high",
    title={"en": "ACM certificate expiring or expired", "pt-BR": "Certificado ACM vencendo ou vencido"},
    requires=[CERTIFICATES],
    catalog_ids=["acm-certificate-expiry-renewal", "cert-expiry-imported-iam", "acm-unused-certs-and-private-ca"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        for c in snap.items(CERTIFICATES, region):
            if not c:
                continue
            not_after = parse_time(c.get("not_after"))
            if not not_after:
                continue
            days = (not_after - ctx.now).days
            expired = not_after <= ctx.now or c.get("status") == "EXPIRED"
            in_use = bool(c.get("in_use"))
            imported = c.get("type") == "IMPORTED"
            ineligible = c.get("renewal") == "INELIGIBLE"
            if not expired and (days > WARN_DAYS or not in_use):
                continue
            domain, arn = c.get("domain"), c["arn"]
            when = not_after.strftime("%Y-%m-%d %H:%M UTC")
            kind_en = {"IMPORTED": "imported", "AMAZON_ISSUED": "Amazon-issued", "PRIVATE": "private"}.get(
                c.get("type"), str(c.get("type")))
            kind_pt = {"IMPORTED": "importado", "AMAZON_ISSUED": "emitido pela Amazon", "PRIVATE": "privado"}.get(
                c.get("type"), str(c.get("type")))
            if expired and not in_use:
                severity, category = "low", "zombie"
                title_en = f"Expired ACM certificate for {domain} is not in use"
                title_pt = f"O certificado ACM vencido de {domain} não está em uso"
                risk_en = "No impact today; it is clutter that hides real expiries in lists and alerts."
                risk_pt = "Sem impacto hoje; é sujeira que esconde vencimentos reais em listas e alertas."
                fix_en = "Delete the certificate after confirming nothing will reuse it."
                fix_pt = "Apagar o certificado depois de confirmar que nada vai reusar ele."
            else:
                severity = "high" if expired or imported or ineligible or days <= URGENT_DAYS else "medium"
                category = "errors"
                if expired:
                    title_en = f"ACM certificate for {domain} expired on {when} and is still in use"
                    title_pt = f"O certificado ACM de {domain} venceu em {when} e ainda está em uso"
                else:
                    title_en = f"ACM certificate for {domain} expires in {days} days and is in use"
                    title_pt = f"O certificado ACM de {domain} vence em {days} dias e está em uso"
                risk_en = "Clients get TLS errors when it expires, and the service behind it goes down for them."
                risk_pt = "Os clientes recebem erro de TLS quando ele vence, e o serviço atrás dele cai para eles."
                if imported:
                    fix_en = "ACM never renews imported certificates. Get a new one from the issuer and reimport it " \
                             "with the same ARN, or switch to an Amazon-issued certificate with DNS validation."
                    fix_pt = "O ACM nunca renova certificado importado. Pegar um novo com o emissor e reimportar no " \
                             "mesmo ARN, ou trocar por um certificado da Amazon com validação por DNS."
                else:
                    fix_en = "ACM renews Amazon-issued certificates about 60 days before expiry, so this one is " \
                             "stuck. Check RenewalSummary and restore the DNS validation CNAME records."
                    fix_pt = "O ACM renova certificados da Amazon cerca de 60 dias antes do vencimento, então este " \
                             "travou. Ver o RenewalSummary e recolocar os registros CNAME de validação no DNS."
            findings.append(Finding(
                check_id="acm-expiry",
                resource=arn,
                severity=severity,
                category=category,
                region=region,
                text={
                    "en": {
                        "title": title_en,
                        "what": f"{kind_en.capitalize()} certificate {arn} for {domain}: status {c.get('status')}, "
                                f"NotAfter {when}, in use {in_use}, renewal eligibility {c.get('renewal')}.",
                        "risk": risk_en,
                        "fix": fix_en,
                    },
                    "pt-BR": {
                        "title": title_pt,
                        "what": f"Certificado {kind_pt} {arn} de {domain}: status {c.get('status')}, NotAfter {when}, "
                                f"em uso {in_use}, elegibilidade de renovação {c.get('renewal')}.",
                        "risk": risk_pt,
                        "fix": fix_pt,
                    },
                },
                claims=[
                    Claim(f"acm:ListCertificates@{region}", f"{arn}.NotAfter", c.get("not_after")),
                    Claim(f"acm:ListCertificates@{region}", f"{arn}.InUse", c.get("in_use")),
                    Claim(f"acm:ListCertificates@{region}", f"{arn}.Type", c.get("type")),
                ],
                deadline="" if expired else not_after.isoformat(),
                verify=[
                    f"aws acm describe-certificate --certificate-arn {quote(arn)} --region {quote(region)} "
                    "--query 'Certificate.[DomainName,Type,Status,NotAfter,RenewalEligibility,"
                    "RenewalSummary.RenewalStatus]' --output text",
                    f"aws acm describe-certificate --certificate-arn {quote(arn)} --region {quote(region)} "
                    "--query 'Certificate.InUseBy' --output text",
                ],
            ))
    return findings
