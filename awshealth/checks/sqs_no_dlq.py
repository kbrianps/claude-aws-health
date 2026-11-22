from __future__ import annotations

import json
import re

from ..calls_security import QUEUE_ATTRS, QUEUES
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "sqs-no-dlq"
_DLQ_NAME = re.compile(r"dlq|dead[-_]?letter|[-_]dl(\.fifo)?$", re.I)


def _dlq_target(redrive) -> str:
    if not redrive:
        return ""
    try:
        return json.loads(redrive).get("deadLetterTargetArn", "")
    except (ValueError, AttributeError):
        return ""


@check(
    id=CHECK_ID,
    category="resilience",
    severity="low",
    title={"en": "SQS queue without a dead-letter queue", "pt-BR": "Fila SQS sem fila de dead-letter"},
    requires=[QUEUES, QUEUE_ATTRS],
    catalog_ids=["sqs-dlq-has-messages", "messaging-orphan-sns-sqs"],
)
def run(snap, ctx):
    findings = []
    for region in snap.regions:
        attrs = {url: a for url, a in snap.per_item(QUEUE_ATTRS, region).items()
                 if isinstance(a, dict) and "__error__" not in a}
        dlqs = {_dlq_target(a.get("redrive")) for a in attrs.values()}
        for url, a in sorted(attrs.items()):
            arn = a.get("arn") or url
            name = url.rstrip("/").split("/")[-1]
            if a.get("redrive") or arn in dlqs or _DLQ_NAME.search(name):
                continue
            retention = int(a.get("retention") or 0)
            hours = retention / 3600
            short = 0 < retention <= 3600
            findings.append(Finding(
                check_id=CHECK_ID,
                resource=arn,
                severity="medium" if short else "low",
                category="resilience",
                region=region,
                text={
                    "en": {
                        "title": f"SQS queue {name} has no dead-letter queue",
                        "what": f"Queue {name} in {region} has no redrive policy. Messages are kept for {hours:g} "
                                "hour(s).",
                        "risk": "A message that always fails is retried until it expires and is then lost without a "
                                "trace."
                                + (" With retention this short, a one-hour consumer outage loses data."
                                   if short else ""),
                        "fix": "Create a dead-letter queue, set a redrive policy with a sensible maxReceiveCount, "
                               "and alarm on the DLQ depth.",
                    },
                    "pt-BR": {
                        "title": f"A fila SQS {name} não tem fila de dead-letter",
                        "what": f"A fila {name} em {region} não tem redrive policy. As mensagens ficam guardadas por "
                                f"{hours:g} hora(s).",
                        "risk": "Uma mensagem que sempre falha é reprocessada até expirar e depois some sem rastro."
                                + (" Com retenção tão curta, uma hora de consumidor parado perde dados."
                                   if short else ""),
                        "fix": "Criar uma fila de dead-letter, definir uma redrive policy com maxReceiveCount "
                               "razoável e criar alarme na profundidade da DLQ.",
                    },
                },
                claims=[Claim(f"sqs:GetQueueAttributes@{region}", f"{url}.RedrivePolicy", None),
                        Claim(f"sqs:GetQueueAttributes@{region}", f"{url}.MessageRetentionPeriod", retention)],
                verify=[
                    f"aws sqs get-queue-attributes --queue-url {url} --attribute-names RedrivePolicy "
                    f"MessageRetentionPeriod --region {region} --query 'Attributes' --output table",
                ],
            ))
    return findings
