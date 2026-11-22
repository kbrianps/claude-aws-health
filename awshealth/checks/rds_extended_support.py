from __future__ import annotations

from shlex import quote

from ..calls_compute import RDS_CLUSTERS, RDS_INSTANCES, RDS_MAJOR_VERSIONS, parse_time
from ..model import Claim, Finding
from ..prices import HOURS_PER_MONTH, price, source
from ..registry import check

ENGINES = {"mysql", "postgres", "aurora-mysql", "aurora-postgresql"}
STANDARD = "open-source-rds-standard-support"
EXTENDED = "open-source-rds-extended-support"
DISABLED = "open-source-rds-extended-support-disabled"
WARN_DAYS = 180
FORCED_DAYS = 120

SIZE_VCPU = {"micro": 2, "small": 2, "medium": 2, "large": 2, "xlarge": 4, "2xlarge": 8, "4xlarge": 16,
             "8xlarge": 32, "12xlarge": 48, "16xlarge": 64, "24xlarge": 96, "32xlarge": 128}
BURSTABLE = {"t3", "t4g"}
FAMILIES = {"m5", "m5d", "m6g", "m6gd", "m6i", "m6id", "m7g", "m7i", "r5", "r5b", "r5d", "r6g", "r6gd", "r6i",
            "r6id", "r7g", "r7i"} | BURSTABLE


def vcpus(cls: str | None) -> int | None:
    parts = (cls or "").split(".")
    if len(parts) != 3 or parts[0] != "db" or parts[1] not in FAMILIES:
        return None
    if parts[2] in ("micro", "small", "medium") and parts[1] not in BURSTABLE:
        return None
    return SIZE_VCPU.get(parts[2])


def major_of(engine: str, version: str, majors: dict[tuple[str, str], list]) -> str | None:
    found = [m for (e, m) in majors if e == engine and (version == m or version.startswith(m + "."))]
    return max(found, key=len) if found else None


@check(
    id="rds-extended-support",
    category="cost",
    severity="high",
    title={"en": "RDS or Aurora database in or near paid extended support",
           "pt-BR": "Banco RDS ou Aurora no suporte estendido pago, ou perto dele"},
    requires=[RDS_INSTANCES, RDS_CLUSTERS, RDS_MAJOR_VERSIONS],
    catalog_ids=["rds-extended-support-enrolled", "rds-end-of-extended-support-forced-upgrade"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        majors = {(m["engine"], m["major"]): m.get("lifecycles") or []
                  for m in snap.items(RDS_MAJOR_VERSIONS, region) if m}
        instances = {i["id"]: i for i in snap.items(RDS_INSTANCES, region) if i}
        targets = []
        for i in instances.values():
            if not i.get("cluster"):
                targets.append(("instance", i, vcpus(i.get("cls")), [i.get("cls")]))
        for c in snap.items(RDS_CLUSTERS, region):
            if not c or c.get("mode") == "serverless":
                continue
            members = [instances.get(m) for m in c.get("members") or []]
            counts = [vcpus(m.get("cls")) if m else None for m in members]
            total = sum(counts) if members and all(n is not None for n in counts) else None
            targets.append(("cluster", c, total, [m.get("cls") if m else "?" for m in members]))
        for kind, db, vcpu, classes in targets:
            f = _evaluate(snap, ctx, region, kind, db, vcpu, classes, majors)
            if f:
                findings.append(f)
    return findings


def _evaluate(snap, ctx, region, kind, db, vcpu, classes, majors):
    engine, version = db.get("engine"), str(db.get("version") or "")
    if engine not in ENGINES:
        return None
    major = major_of(engine, version, majors)
    if not major:
        return None
    lifecycles = {lc["name"]: lc for lc in majors[(engine, major)] if lc}
    std_end = parse_time((lifecycles.get(STANDARD) or {}).get("end"))
    ext_end = parse_time((lifecycles.get(EXTENDED) or {}).get("end"))
    if not std_end:
        return None
    disabled = db.get("lifecycle") == DISABLED
    std_days = (std_end - ctx.now).days
    in_extended = std_end <= ctx.now
    if not in_extended and std_days > WARN_DAYS:
        return None
    ext_days = (ext_end - ctx.now).days if ext_end else None
    forced = in_extended and (disabled or (ext_days is not None and ext_days <= FORCED_DAYS))
    years_in = max(0, (ctx.now - std_end).days) / 365
    rate_key = "rds_extended_support_vcpu_hour_y3" if years_in >= 2 else "rds_extended_support_vcpu_hour_y1"
    billed = not disabled
    monthly = round(vcpu * price(rate_key) * HOURS_PER_MONTH, 2) if billed and vcpu else None
    name, arn = db["id"], db.get("arn") or db["id"]
    class_list = ", ".join(c or "?" for c in classes)
    std_when = std_end.strftime("%Y-%m-%d")
    ext_when = ext_end.strftime("%Y-%m-%d") if ext_end else "unknown"
    label_en = "Aurora/Multi-AZ cluster" if kind == "cluster" else "DB instance"
    label_pt = "O cluster Aurora/Multi-AZ" if kind == "cluster" else "A instância"
    if in_extended and disabled:
        state_en = f"is past standard support (ended {std_when}) with extended support disabled, so AWS upgrades it"
        state_pt = (f"passou do suporte padrão (fim em {std_when}) com o suporte estendido desligado, então a AWS "
                    "faz o upgrade")
    elif in_extended:
        state_en = f"is in paid extended support since {std_when}"
        state_pt = f"está no suporte estendido pago desde {std_when}"
    else:
        state_en = f"leaves standard support in {std_days} days ({std_when})"
        state_pt = f"sai do suporte padrão em {std_days} dias ({std_when})"
    if monthly is not None:
        cost_en = f"Extended support bills {vcpu} vCPU x US${price(rate_key)}/vCPU-hour, about US${monthly:,.2f}/month."
        cost_pt = (f"O suporte estendido cobra {vcpu} vCPU x US$ {price(rate_key)}/vCPU-hora, cerca de "
                   f"US$ {monthly:,.2f}/mês.")
    elif billed:
        cost_en = (f"Extended support bills per vCPU, but the vCPU count of {class_list} is not in the class "
                   "table.")
        cost_pt = (f"O suporte estendido cobra por vCPU, mas a contagem de vCPU de {class_list} não está na "
                   "tabela de classes.")
    else:
        cost_en = ("Extended support is disabled, so there is no surcharge, but AWS upgrades the major version on "
                   "its own schedule.")
        cost_pt = ("O suporte estendido está desligado, então não há cobrança extra, mas a AWS sobe a versão major "
                   "no horário dela.")
    if forced and not disabled:
        cost_en += f" Extended support itself ends on {ext_when}, then AWS upgrades the major version automatically."
        cost_pt += f" O próprio suporte estendido acaba em {ext_when}, depois disso a AWS sobe a versão major sozinha."
    severity = "high" if in_extended or forced else "medium"
    if not in_extended:
        deadline = std_end
    elif ext_end and ext_end > ctx.now:
        deadline = ext_end
    else:
        deadline = None
    notes = [{"en": f"Rate {rate_key} is the us-east-1 list price for RDS for PostgreSQL; other engines and regions "
                   "differ.",
              "pt-BR": f"A tarifa {rate_key} é o preço de lista do RDS for PostgreSQL em us-east-1; outros motores e "
                       "regiões têm preços diferentes."}]
    if monthly is None and billed:
        notes.append("vCPU count unknown for this instance class, no dollar figure.")
    describe = ("aws rds describe-db-clusters --db-cluster-identifier" if kind == "cluster"
                else "aws rds describe-db-instances --db-instance-identifier")
    root = "DBClusters" if kind == "cluster" else "DBInstances"
    pm_filter = "db-cluster-id" if kind == "cluster" else "db-instance-id"
    return Finding(
        check_id="rds-extended-support",
        resource=arn,
        severity=severity,
        category="cost" if billed and in_extended else "outdated",
        region=region,
        text={
            "en": {
                "title": f"{label_en} {name} runs {engine} {version}, which {state_en}",
                "what": f"{engine} {major} standard support ends {std_when} and extended support ends {ext_when}. "
                        f"Enrollment: {db.get('lifecycle') or 'not reported'}.",
                "risk": cost_en,
                "fix": "Plan the major version upgrade (test with a snapshot restore or a blue/green deployment). "
                       "If a surcharge is not acceptable, create new databases with "
                       "--engine-lifecycle-support open-source-rds-extended-support-disabled.",
            },
            "pt-BR": {
                "title": f"{label_pt} {name} roda {engine} {version}, que {state_pt}",
                "what": f"O suporte padrão do {engine} {major} acaba em {std_when} e o estendido em {ext_when}. "
                        f"Inscrição: {db.get('lifecycle') or 'não informada'}.",
                "risk": cost_pt,
                "fix": "Planejar o upgrade de versão major (testar com restore de snapshot ou blue/green). Se a "
                       "cobrança extra não for aceitável, criar bancos novos com "
                       "--engine-lifecycle-support open-source-rds-extended-support-disabled.",
            },
        },
        claims=[
            Claim(f"rds:Describe{root}@{region}", f"{name}.EngineVersion", version),
            Claim(f"rds:Describe{root}@{region}", f"{name}.EngineLifecycleSupport", db.get("lifecycle")),
            Claim(f"rds:DescribeDBMajorEngineVersions@{region}", f"{engine}/{major}.{STANDARD}.end",
                  (lifecycles.get(STANDARD) or {}).get("end")),
        ],
        monthly_usd=monthly,
        usd_calc=(f"{vcpu} vCPU ({class_list}) x US${price(rate_key)}/vCPU-hour x "
                  f"{HOURS_PER_MONTH} h = US${monthly:,.2f}/month ({source(rate_key)})") if monthly is not None else "",
        deadline=deadline.isoformat() if deadline else "",
        confidence="medium" if monthly is not None else "high",
        notes=notes,
        verify=[
            f"{describe} {quote(name)} --region {quote(region)} "
            f"--query '{root}[].[Engine,EngineVersion,EngineLifecycleSupport]' --output table",
            f"aws rds describe-db-major-engine-versions --engine {quote(engine)} --major-engine-version {quote(major)} "
            f"--region {quote(region)} --query 'DBMajorEngineVersions[].SupportedEngineLifecycles[]."
            "[LifecycleSupportName,LifecycleSupportStartDate,LifecycleSupportEndDate]' --output table",
            f"aws rds describe-pending-maintenance-actions --filters Name={pm_filter},Values={quote(arn)} "
            f"--region {quote(region)} "
            "--query 'PendingMaintenanceActions[].PendingMaintenanceActionDetails[]."
            "[Action,AutoAppliedAfterDate,ForcedApplyDate]' --output table",
        ],
    )
