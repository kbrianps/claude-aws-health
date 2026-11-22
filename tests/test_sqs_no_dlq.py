import json

from awshealth.calls_security import QUEUE_ATTRS, QUEUES
from awshealth.testing import run_one, snap_with

BASE = "https://sqs.us-east-1.amazonaws.com/111122223333/"


def q(name, redrive=None, retention="345600"):
    return {"redrive": redrive, "retention": retention, "arn": f"arn:aws:sqs:us-east-1:111122223333:{name}"}


def snap(attrs):
    return snap_with({QUEUES: {"us-east-1": [BASE + n for n in attrs]},
                      QUEUE_ATTRS: {"us-east-1": {"__by_id__": {BASE + n: a for n, a in attrs.items()}}}})


def test_queue_without_dlq_is_low_and_short_retention_medium():
    found = run_one("sqs-no-dlq", snap({"jobs": q("jobs"), "events": q("events", retention="3600")}))
    findings = {f.resource.split(":")[-1]: f for f in found}
    assert findings["jobs"].severity == "low"
    assert findings["events"].severity == "medium"
    assert "1 hour" in findings["events"].t("what")


def test_dlq_targets_and_dlq_names_are_skipped():
    redrive = json.dumps({"deadLetterTargetArn": "arn:aws:sqs:us-east-1:111122223333:orders-failed",
                          "maxReceiveCount": 5})
    attrs = {"orders": q("orders", redrive=redrive), "orders-failed": q("orders-failed"),
             "payments-dlq.fifo": q("payments-dlq.fifo"), "billing_dead_letter": q("billing_dead_letter")}
    assert run_one("sqs-no-dlq", snap(attrs)) == []


def test_errors_are_quiet():
    assert run_one("sqs-no-dlq", snap({"gone": {"__error__": "QueueDoesNotExist"}})) == []
