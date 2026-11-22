from awshealth.calls_security import ALARMS, TOPIC_ATTRS, TOPICS
from awshealth.testing import run_one, snap_with

TOPIC = "arn:aws:sns:us-east-1:111122223333:ops-alerts"


def alarm(name, action=TOPIC, enabled=True):
    return {"name": name, "arn": f"arn:aws:cloudwatch:us-east-1:111122223333:alarm:{name}", "state": "OK",
            "updated": "2026-01-01T00:00:00Z", "actions": [action], "enabled": enabled}


def snap(alarms, topics=(TOPIC,), attrs=None):
    return snap_with({
        ALARMS: {"us-east-1": alarms},
        TOPICS: {"us-east-1": list(topics)},
        TOPIC_ATTRS: {"us-east-1": {"__by_id__": attrs if attrs is not None
                                    else {TOPIC: {"confirmed": "0", "pending": "1"}}}},
    })


def test_prod_alarms_to_unsubscribed_topic_aggregate_and_high():
    [f] = run_one("sns-alarm-topic-no-subscribers", snap([alarm("prod-api-5xx"), alarm("prod-db-cpu")]))
    assert f.severity == "high"
    assert f.resource == TOPIC
    assert "2 alarm" in f.t("title")
    assert "pending" in f.t("what")
    assert len(f.resources) == 3


def test_missing_topic_is_reported():
    [f] = run_one("sns-alarm-topic-no-subscribers", snap([alarm("api-latency")], topics=(), attrs={}))
    assert f.severity == "medium"
    assert "no longer exists" in f.t("title")


def test_cross_account_disabled_actions_and_subscribed_are_quiet():
    other = "arn:aws:sns:us-east-1:444455556666:shared"
    assert run_one("sns-alarm-topic-no-subscribers", snap([alarm("x", action=other)])) == []
    assert run_one("sns-alarm-topic-no-subscribers", snap([alarm("x", enabled=False)])) == []
    assert run_one("sns-alarm-topic-no-subscribers",
                   snap([alarm("x")], attrs={TOPIC: {"confirmed": "2", "pending": "0"}})) == []
    assert run_one("sns-alarm-topic-no-subscribers",
                   snap([alarm("x", action="arn:aws:autoscaling:us-east-1:111122223333:scalingPolicy:p")])) == []
