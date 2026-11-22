from awshealth.calls_compute import ADDRESSES, INSTANCES, VOLUMES
from awshealth.checks.ec2_stopped_long import stopped_at
from awshealth.testing import run_one, snap_with


def instance(iid="i-0a1", reason="User initiated (2025-10-01 10:00:00 GMT)", tags=None, state="stopped"):
    return {"id": iid, "state": state, "reason": reason, "type": "m5.large", "public_ip": None,
            "volumes": ["vol-root", "vol-data"], "tags": tags or [{"Key": "Name", "Value": "build-box"}]}


def snap(inst, eips=None):
    return snap_with({
        INSTANCES: {"us-east-1": [inst]},
        VOLUMES: {"us-east-1": [{"id": "vol-root", "size": 20, "type": "gp3"},
                                {"id": "vol-data", "size": 30, "type": "gp2"}]},
        ADDRESSES: {"us-east-1": eips or []},
    })


def test_long_stopped_instance_counts_ebs_and_eip():
    eip = {"ip": "203.0.113.20", "allocation": "eipalloc-0a1", "association": "eipassoc-0a1", "instance": "i-0a1",
           "pool": "amazon"}
    [f] = run_one("ec2-stopped-long", snap(instance(), [eip]))
    assert f.monthly_usd == round(20 * 0.08 + 30 * 0.10 + 0.005 * 730, 2)
    assert "106 days" in f.t("title")
    assert "build-box" in f.owner_question["en"]
    assert len(f.verify) == 3


def test_auto_scaling_warm_pool_instances_are_skipped():
    tags = [{"Key": "aws:autoscaling:groupName", "Value": "web-asg"}]
    assert run_one("ec2-stopped-long", snap(instance(tags=tags))) == []


def test_recent_or_unparseable_stops_are_quiet():
    assert run_one("ec2-stopped-long", snap(instance(reason="User initiated (2026-01-10 08:00:00 GMT)"))) == []
    assert run_one("ec2-stopped-long", snap(instance(reason=""))) == []
    assert run_one("ec2-stopped-long", snap(instance(state="running"))) == []


def test_stop_date_parser():
    assert stopped_at("User initiated (2025-10-01 10:00:00 GMT)").isoformat() == "2025-10-01T10:00:00+00:00"
    assert stopped_at("Server.SpotInstanceTermination") is None
