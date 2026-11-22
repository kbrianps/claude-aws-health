from __future__ import annotations

from ..calls_compute import NETWORK_INTERFACES, SECURITY_GROUPS
from ..model import Claim, Finding
from ..registry import check

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 6379: "Redis",
               9200: "Elasticsearch", 27017: "MongoDB", 2375: "Docker API", 5900: "VNC"}
OPEN = {"0.0.0.0/0", "::/0"}
TCP = {"tcp", "6", "-1"}


def open_ports(rule: dict) -> tuple[list[int], list[str]]:
    if str(rule.get("proto")) not in TCP:
        return [], []
    sources = sorted(OPEN & set((rule.get("v4") or []) + (rule.get("v6") or [])))
    if not sources:
        return [], []
    if str(rule.get("proto")) == "-1" or rule.get("from") is None:
        return sorted(ADMIN_PORTS), sources
    lo, hi = rule["from"], rule.get("to", rule["from"])
    return [p for p in sorted(ADMIN_PORTS) if lo <= p <= hi], sources


def _owner(eni: dict) -> str:
    who = eni.get("instance") or (eni.get("description") or "")[:60] or eni.get("type") or "interface"
    ip = f", public {eni['public_ip']}" if eni.get("public_ip") else ""
    return f"{eni['id']} ({who}{ip})"


@check(
    id="sg-open-admin-ports",
    category="security",
    severity="high",
    title={"en": "Security group open to the internet on admin or database ports",
           "pt-BR": "Security group aberto para a internet em portas de administração ou banco"},
    requires=[SECURITY_GROUPS, NETWORK_INTERFACES],
    catalog_ids=["ec2-sg-open-admin-db-ports"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        enis_by_group: dict[str, list[dict]] = {}
        for e in snap.items(NETWORK_INTERFACES, region):
            for g in (e or {}).get("groups") or []:
                enis_by_group.setdefault(g, []).append(e)
        known_enis = snap.status(NETWORK_INTERFACES, region) == "ok"
        for sg in snap.items(SECURITY_GROUPS, region):
            if not sg:
                continue
            ports, sources = set(), set()
            for rule in sg.get("ingress") or []:
                p, s = open_ports(rule)
                if p:
                    ports.update(p)
                    sources.update(s)
            if not ports:
                continue
            gid, name = sg["id"], sg.get("name")
            enis = enis_by_group.get(gid, [])
            public = [e for e in enis if e.get("public_ip")]
            if enis and public:
                severity = "high"
            elif enis:
                severity = "medium"
            else:
                severity = "low"
            port_list = ", ".join(f"{p} ({ADMIN_PORTS[p]})" for p in sorted(ports))
            owners = ", ".join(_owner(e) for e in enis[:10]) + (f" and {len(enis) - 10} more" if len(enis) > 10 else "")
            if enis:
                use_en = f"It is attached to {len(enis)} network interfaces ({len(public)} with a public IP): {owners}."
                use_pt = f"Ele está anexado a {len(enis)} interfaces de rede ({len(public)} com IP público): {owners}."
            elif known_enis:
                use_en = "It is not attached to any network interface today."
                use_pt = "Ele não está anexado a nenhuma interface de rede hoje."
            else:
                use_en = "Network interfaces could not be read, so attachment is unknown."
                use_pt = "Não foi possível ler as interfaces de rede, então o uso é desconhecido."
            findings.append(Finding(
                check_id="sg-open-admin-ports",
                resource=f"arn:aws:ec2:{region}:{snap.account_id}:security-group/{gid}",
                severity=severity,
                category="security",
                region=region,
                text={
                    "en": {
                        "title": f"Security group {gid} ({name}) allows {', '.join(sorted(sources))} on {port_list}",
                        "what": f"Ingress from {', '.join(sorted(sources))} reaches {port_list}. {use_en}",
                        "risk": "Admin and database ports open to the whole internet get scanned within minutes and "
                                "are a common way in through weak passwords or unpatched services."
                                if enis else "Unused today, but anything attached later is exposed at once.",
                        "fix": "Remove the 0.0.0.0/0 and ::/0 rules. Use SSM Session Manager or a VPN for admin "
                               "access and allow database ports only from the application security groups."
                               + ("" if enis else " Delete the group if nothing needs it."),
                    },
                    "pt-BR": {
                        "title": f"O security group {gid} ({name}) libera {', '.join(sorted(sources))} em {port_list}",
                        "what": f"Entrada de {', '.join(sorted(sources))} chega em {port_list}. {use_pt}",
                        "risk": "Portas de administração e banco abertas para a internet inteira são varridas em "
                                "minutos e são uma porta de entrada comum por senha fraca ou serviço sem patch."
                                if enis else "Sem uso hoje, mas qualquer coisa anexada depois fica exposta na hora.",
                        "fix": "Remover as regras 0.0.0.0/0 e ::/0. Usar SSM Session Manager ou VPN para acesso de "
                               "administração e liberar portas de banco só a partir dos security groups da aplicação."
                               + ("" if enis else " Apagar o grupo se nada precisa dele."),
                    },
                },
                claims=[Claim(f"ec2:DescribeSecurityGroups@{region}", f"{gid}.IpPermissions", sorted(ports)),
                        Claim(f"ec2:DescribeNetworkInterfaces@{region}", f"group-id={gid}", [e["id"] for e in enis])],
                confidence="high" if known_enis else "medium",
                notes=[] if public or not enis else ["No attached interface has a public IP; exposure depends on "
                                                     "load balancers or NAT in front of them."],
                verify=[
                    f"aws ec2 describe-security-group-rules --filters Name=group-id,Values={gid} --region {region} "
                    "--query 'SecurityGroupRules[?!IsEgress].[SecurityGroupRuleId,IpProtocol,FromPort,ToPort,"
                    "CidrIpv4,CidrIpv6]' --output table",
                    f"aws ec2 describe-network-interfaces --filters Name=group-id,Values={gid} --region {region} "
                    "--query 'NetworkInterfaces[].[NetworkInterfaceId,InterfaceType,Attachment.InstanceId,"
                    "Association.PublicIp,Description]' --output table",
                ],
            ))
    return findings
