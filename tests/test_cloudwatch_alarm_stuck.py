from awshealth.calls_security import ALARMS
from awshealth.testing import run_one, snap_with


def alarm(name, state, updated, enabled=True, treat="missing"):
    return {"name": name, "arn": f"arn:aws:cloudwatch:us-east-1:111122223333:alarm:{name}", "state": state,
            "updated": updated, "actions": [], "enabled": enabled, "treat_missing": treat}


def run(*alarms):
    return run_one("cloudwatch-alarm-stuck", snap_with({ALARMS: {"us-east-1": list(alarms)}}))


def test_aggregates_stuck_alarms_per_region():
    [f] = run(alarm("api-5xx", "ALARM", "2025-11-01T00:00:00Z"),
              alarm("old-instance-cpu", "INSUFFICIENT_DATA", "2025-10-01T00:00:00Z"))
    assert f.severity == "low"
    assert f.resource == "cloudwatch-alarms/us-east-1"
    assert "2 CloudWatch alarm" in f.t("title")
    assert "old-instance-cpu (INSUFFICIENT_DATA, 106 days)" in f.t("what")
    assert len(f.resources) == 2


def test_known_traps_are_skipped():
    assert run(alarm("dash", "ALARM", "2025-01-01T00:00:00Z", enabled=False),
               alarm("batch-errors", "INSUFFICIENT_DATA", "2025-01-01T00:00:00Z", treat="notBreaching"),
               alarm("heartbeat-ingest", "ALARM", "2025-01-01T00:00:00Z")) == []


def test_recent_or_ok_alarms_are_quiet():
    assert run(alarm("fresh", "ALARM", "2026-01-10T00:00:00Z"), alarm("fine", "OK", "2024-01-01T00:00:00Z")) == []
