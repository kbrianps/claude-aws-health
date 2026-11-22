from __future__ import annotations

from ..calls_security import ALARMS, TOPIC_ATTRS, TOPICS, is_prod, per_item_error
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "sns-alarm-topic-no-subscribers"


@check(
    id=CHECK_ID,
    category="errors",
    severity="high",
    title={"en": "Alarms notify an SNS topic that nobody receives",
           "pt-BR": "Alarmes avisam um tópico SNS que ninguém recebe"},
    requires=[ALARMS, TOPICS, TOPIC_ATTRS],
    catalog_ids=["cloudwatch-alarm-action-target-broken", "sns-subscription-pending-confirmation"],
)
def run(snap, ctx):
    by_topic: dict[str, list[str]] = {}
    for region in snap.regions:
        for a in snap.items(ALARMS, region):
            if not a or a.get("enabled") is False:
                continue
            for action in a.get("actions") or []:
                if action.startswith("arn:") and action.split(":")[2] == "sns":
                    by_topic.setdefault(action, []).append(a["name"])
    findings = []
    for topic, alarms in sorted(by_topic.items()):
        parts = topic.split(":")
        region, account, topic_name = parts[3], parts[4], parts[5]
        if account != ctx.account_id or region not in snap.regions or snap.status(TOPICS, region) != "ok":
            continue
        attrs = snap.per_item(TOPIC_ATTRS, region).get(topic)
        missing = topic not in snap.items(TOPICS, region) or per_item_error(attrs) in ("NotFound", "NotFoundException")
        if not missing:
            if not isinstance(attrs, dict) or "__error__" in attrs or int(attrs.get("confirmed") or 0) > 0:
                continue
        pending = 0 if missing else int(attrs.get("pending") or 0)
        alarms = sorted(set(alarms))
        prod = is_prod(None, topic_name, *alarms)
        names = ", ".join(alarms[:5]) + (f" and {len(alarms) - 5} more" if len(alarms) > 5 else "")
        names_pt = ", ".join(alarms[:5]) + (f" e mais {len(alarms) - 5}" if len(alarms) > 5 else "")
        if missing:
            what_en = f"{len(alarms)} alarm(s) send to {topic_name}, which does not exist in {region}: {names}."
            what_pt = f"{len(alarms)} alarme(s) enviam para {topic_name}, que não existe em {region}: {names_pt}."
            title_en = f"{len(alarms)} alarm(s) notify SNS topic {topic_name}, which no longer exists"
            title_pt = f"{len(alarms)} alarme(s) avisam o tópico SNS {topic_name}, que não existe mais"
        else:
            pend_en = f" {pending} subscription(s) are still pending confirmation." if pending else ""
            pend_pt = f" {pending} inscrição(ões) ainda aguardam confirmação." if pending else ""
            what_en = (f"{len(alarms)} alarm(s) send to {topic_name}, which has 0 confirmed subscriptions: "
                       f"{names}.{pend_en}")
            what_pt = (f"{len(alarms)} alarme(s) enviam para {topic_name}, que tem 0 inscrições confirmadas: "
                       f"{names_pt}.{pend_pt}")
            title_en = f"{len(alarms)} alarm(s) notify SNS topic {topic_name}, which has no confirmed subscribers"
            title_pt = f"{len(alarms)} alarme(s) avisam o tópico SNS {topic_name}, que não tem inscritos confirmados"
        claims = [Claim(f"cloudwatch:DescribeAlarms@{region}", ("MetricAlarms[?contains(AlarmActions, "
                                                                f"'{topic}')].AlarmName"), alarms)]
        if missing:
            claims.append(Claim(f"sns:ListTopics@{region}", topic, "absent"))
        else:
            claims.append(Claim(f"sns:GetTopicAttributes@{region}", f"{topic}.SubscriptionsConfirmed", 0))
            claims.append(Claim(f"sns:GetTopicAttributes@{region}", f"{topic}.SubscriptionsPending", pending))
        findings.append(Finding(
            check_id=CHECK_ID,
            resource=topic,
            resources=[topic] + [f"arn:aws:cloudwatch:{region}:{account}:alarm:{n}" for n in alarms],
            severity="high" if prod else "medium",
            category="errors",
            region=region,
            text={
                "en": {
                    "title": title_en,
                    "what": what_en,
                    "risk": "When these alarms fire, nobody is told. The outage is found by customers instead.",
                    "fix": ("Subscribe the on-call channel to the topic and confirm the subscription, or point the "
                            "alarms at a topic that has subscribers. Then test with set-alarm-state."),
                },
                "pt-BR": {
                    "title": title_pt,
                    "what": what_pt,
                    "risk": ("Quando esses alarmes disparam, ninguém fica sabendo. Quem descobre a queda são os "
                             "clientes."),
                    "fix": ("Inscrever o canal de plantão no tópico e confirmar a inscrição, ou apontar os alarmes "
                            "para um tópico com inscritos. Depois testar com set-alarm-state."),
                },
            },
            claims=claims,
            verify=[
                (f"aws sns get-topic-attributes --topic-arn {topic} --region {region} --query "
                 "'Attributes.[SubscriptionsConfirmed,SubscriptionsPending]' --output text"),
                (f"aws cloudwatch describe-alarms --region {region} --query \"MetricAlarms[?contains(AlarmActions, "
                 f"'{topic}')].AlarmName\" --output text"),
            ],
        ))
    return findings
