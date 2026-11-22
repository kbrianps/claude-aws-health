from awshealth.calls_compute import CACHE_UPDATE_ACTIONS
from awshealth.testing import run_one, snap_with


def action(update, severity, apply_by, group="sessions", cluster=None, status="not-applied"):
    return {"update": update, "severity": severity, "status": status, "apply_by": apply_by, "sla_met": "no",
            "group": group, "cluster": cluster, "engine": "redis"}


def snap(*actions):
    return snap_with({CACHE_UPDATE_ACTIONS: {"us-east-1": list(actions)}})


def test_critical_update_groups_per_replication_group_with_deadline():
    [f] = run_one("elasticache-pending-updates", snap(
        action("elasticache-20251201-002", "important", "2026-03-01T00:00:00Z"),
        action("elasticache-20251115-001", "critical", "2026-02-01T00:00:00Z")))
    assert f.severity == "high"
    assert f.deadline.startswith("2026-02-01")
    assert "2 pending service updates" in f.t("title")
    assert "replicationgroup:sessions" in f.resource
    assert "--replication-group-ids sessions" in f.verify[0]


def test_overdue_important_update_on_cluster_is_medium():
    [f] = run_one("elasticache-pending-updates", snap(
        action("elasticache-20250901-001", "important", "2025-12-01T00:00:00Z", group=None, cluster="cache-01")))
    assert f.severity == "medium"
    assert "has passed" in f.t("what")
    assert "--cache-cluster-ids cache-01" in f.verify[0]


def test_low_severity_updates_are_quiet():
    assert run_one("elasticache-pending-updates", snap(action("x", "low", "2026-02-01T00:00:00Z"))) == []
    assert run_one("elasticache-pending-updates", snap()) == []
