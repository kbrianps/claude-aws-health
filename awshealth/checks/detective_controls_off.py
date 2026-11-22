from __future__ import annotations

from ..calls_security import (
    ANALYZERS,
    CONFIG_RECORDERS,
    DB_INSTANCES,
    FUNCTIONS,
    GD_DETECTOR,
    GD_DETECTORS,
    INSTANCES,
    SECURITY_HUB,
    TRAIL_STATUS,
    TRAILS,
    entry_error,
)
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "detective-controls-off"
NAMES = {"guardduty": ("GuardDuty", "GuardDuty"), "config": ("AWS Config recording", "gravação do AWS Config"),
         "accessanalyzer": ("IAM Access Analyzer", "IAM Access Analyzer"),
         "securityhub": ("Security Hub", "Security Hub")}
SOURCES = {"guardduty": "guardduty:ListDetectors", "config": "config:DescribeConfigurationRecorderStatus",
           "accessanalyzer": "accessanalyzer:ListAnalyzers", "securityhub": "securityhub:DescribeHub"}


def _workloads(snap, region) -> int:
    instances = [i for i in snap.items(INSTANCES, region) if i and i.get("state") != "terminated"]
    return len(instances) + len(snap.items(FUNCTIONS, region)) + len(snap.items(DB_INSTANCES, region))


def _guardduty(snap, region):
    if snap.status(GD_DETECTORS, region) != "ok":
        return None
    detectors = snap.items(GD_DETECTORS, region)
    if not detectors:
        return False
    details = snap.per_item(GD_DETECTOR, region)
    statuses = [d.get("status") for d in details.values() if isinstance(d, dict)]
    if not statuses:
        return None
    return "ENABLED" in statuses


def _config(snap, region):
    if snap.status(CONFIG_RECORDERS, region) != "ok":
        return None
    return any(r.get("recording") for r in snap.items(CONFIG_RECORDERS, region) if r)


def _analyzer(snap, region):
    if snap.status(ANALYZERS, region) != "ok":
        return None
    return any(a.get("status") == "ACTIVE" and a.get("type") in ("ACCOUNT", "ORGANIZATION")
               for a in snap.items(ANALYZERS, region) if a)


def _security_hub(snap, region):
    if snap.status(SECURITY_HUB, region) == "ok":
        return True
    if "InvalidAccessException" in entry_error(snap, SECURITY_HUB, region):
        return False
    return None


def _region_findings(snap):
    rows = []
    for region in snap.regions:
        count = _workloads(snap, region)
        if not count:
            continue
        state = {"guardduty": _guardduty(snap, region), "config": _config(snap, region),
                 "accessanalyzer": _analyzer(snap, region), "securityhub": _security_hub(snap, region)}
        off = [k for k, v in state.items() if v is False]
        if off:
            rows.append((region, count, off, [k for k, v in state.items() if v is None]))
    top = max((r[1] for r in rows), default=0)
    findings = []
    for region, count, off, unknown in rows:
        off_en = ", ".join(NAMES[k][0] for k in off)
        off_pt = ", ".join(NAMES[k][1] for k in off)
        unk_en = f" Could not read: {', '.join(NAMES[k][0] for k in unknown)}." if unknown else ""
        unk_pt = f" Não foi possível ler: {', '.join(NAMES[k][1] for k in unknown)}." if unknown else ""
        verify = {
            "guardduty": f"aws guardduty list-detectors --region {region} --query 'DetectorIds' --output text",
            "config": (f"aws configservice describe-configuration-recorder-status --region {region} --query "
                       "'ConfigurationRecordersStatus[].[name,recording,lastStatus]' --output table"),
            "accessanalyzer": (f"aws accessanalyzer list-analyzers --region {region} --query "
                               "'analyzers[].[name,type,status]' --output table"),
            "securityhub": f"aws securityhub describe-hub --region {region} --query 'HubArn' --output text",
        }
        findings.append(Finding(
            check_id=CHECK_ID,
            resource=f"detective-controls/{region}",
            severity="high" if count == top else "medium",
            category="security",
            region=region,
            text={
                "en": {
                    "title": f"{region} runs {count} workloads with {off_en} off",
                    "what": (f"{region} has {count} EC2 instances, Lambda functions or RDS instances. These "
                             f"detective controls are off there: {off_en}.{unk_en}"),
                    "risk": ("A compromised key or instance in this region would act without any alert, and there "
                             "would be no configuration history to investigate later."),
                    "fix": ("Enable the missing services in this region, ideally from the organization's delegated "
                            "administrator so new regions and accounts are covered automatically."),
                },
                "pt-BR": {
                    "title": f"{region} roda {count} cargas com {off_pt} desligado",
                    "what": (f"{region} tem {count} instâncias EC2, funções Lambda ou instâncias RDS. Estes "
                             f"controles de detecção estão desligados lá: {off_pt}.{unk_pt}"),
                    "risk": ("Uma chave ou instância comprometida nesta região agiria sem nenhum alerta, e não "
                             "haveria histórico de configuração para investigar depois."),
                    "fix": ("Ligar os serviços que faltam nesta região, de preferência pelo administrador delegado "
                            "da organização, para que novas regiões e contas fiquem cobertas sozinhas."),
                },
            },
            claims=[Claim(f"{SOURCES[k]}@{region}", "enabled", False) for k in off]
            + [Claim(f"ec2:DescribeInstances+lambda:ListFunctions+rds:DescribeDBInstances@{region}", "count", count)],
            verify=[verify[k] for k in off][:3],
        ))
    return findings


def _trail_finding(snap):
    region = snap.home_region
    if snap.status(TRAILS, region) != "ok":
        return []
    statuses = snap.per_item(TRAIL_STATUS, region)
    multi = [t for t in snap.items(TRAILS, region) if t and t.get("multi")]
    logging = []
    for t in multi:
        st = statuses.get(t.get("arn"))
        known = isinstance(st, dict) and "__error__" not in st
        if (known and st.get("logging")) or (not known and t.get("org")):
            logging.append(t)
    if logging and any(t.get("validation") for t in logging):
        return []
    if not logging:
        severity, title_en, title_pt = ("high", "No multi-region CloudTrail trail is logging",
                                        "Nenhuma trilha multi-região do CloudTrail está registrando")
        what_en = f"Of {len(multi)} multi-region trail(s), none is logging."
        what_pt = f"Das {len(multi)} trilha(s) multi-região, nenhuma está registrando."
        risk_en = "API calls are not recorded in every region, so an incident cannot be reconstructed."
        risk_pt = ("Chamadas de API não ficam registradas em todas as regiões, então um incidente não pode ser "
                   "reconstruído.")
    else:
        names = ", ".join(t.get("name", "") for t in logging)
        severity, title_en, title_pt = ("medium", "CloudTrail log file validation is off",
                                        "Validação de arquivos de log do CloudTrail desligada")
        what_en = f"The logging multi-region trail(s) {names} have log file validation off."
        what_pt = f"A(s) trilha(s) multi-região ativa(s) {names} estão com a validação de arquivos de log desligada."
        risk_en = "Without digest files nobody can prove the logs were not edited or deleted after an incident."
        risk_pt = ("Sem os arquivos de digest ninguém consegue provar que os logs não foram editados ou apagados "
                   "depois de um incidente.")
    return [Finding(
        check_id=CHECK_ID,
        resource="cloudtrail/multi-region",
        severity=severity,
        category="security",
        region=region,
        text={
            "en": {"title": title_en, "what": what_en, "risk": risk_en,
                   "fix": ("Keep one multi-region trail (or an organization trail) logging, with log file "
                           "validation on and the bucket locked down.")},
            "pt-BR": {"title": title_pt, "what": what_pt, "risk": risk_pt,
                      "fix": ("Manter uma trilha multi-região (ou de organização) registrando, com validação de "
                              "arquivos de log ligada e o bucket protegido.")},
        },
        claims=[Claim(f"cloudtrail:DescribeTrails@{region}", f"{t.get('name')}.LogFileValidationEnabled",
                      t.get("validation")) for t in multi]
        + [Claim(f"cloudtrail:GetTrailStatus@{region}", "logging_multi_region_trails", len(logging))],
        verify=[
            (f"aws cloudtrail describe-trails --region {region} --query "
             "'trailList[].[Name,IsMultiRegionTrail,LogFileValidationEnabled,HomeRegion]' --output table"),
        ] + [(f"aws cloudtrail get-trail-status --name {t.get('arn')} --region {region} --query 'IsLogging' --output "
              "text")
             for t in multi[:2]],
    )]


@check(
    id=CHECK_ID,
    category="security",
    severity="high",
    title={"en": "Detective controls off where workloads run",
           "pt-BR": "Controles de detecção desligados onde há cargas rodando"},
    requires=[INSTANCES, FUNCTIONS, DB_INSTANCES, GD_DETECTORS, GD_DETECTOR, CONFIG_RECORDERS, ANALYZERS, SECURITY_HUB,
              TRAILS, TRAIL_STATUS],
    catalog_ids=["guardduty-disabled-or-unaddressed", "config-recorder-off", "accessanalyzer-external-access",
                 "securityhub-failed-controls", "cloudtrail-not-logging"],
)
def run(snap, ctx):
    return _region_findings(snap) + _trail_finding(snap)
