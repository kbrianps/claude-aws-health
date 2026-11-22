from awshealth.calls_compute import LISTENERS, LOAD_BALANCERS, TARGET_GROUPS, TARGET_HEALTH
from awshealth.testing import run_one, snap_with

LB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/old-api/0a1b2c"
TG_A = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/blue/0a1"
TG_B = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/green/0b2"


def snap(tgs, health, listeners=None, created="2025-06-01T00:00:00Z"):
    lb = {"arn": LB, "name": "old-api", "dns": "old-api.example.com", "type": "application",
          "scheme": "internet-facing", "state": "active", "created": created}
    return snap_with({
        LOAD_BALANCERS: {"us-east-1": [lb]},
        TARGET_GROUPS: {"us-east-1": tgs},
        TARGET_HEALTH: {"us-east-1": {"__by_id__": health}},
        LISTENERS: {"us-east-1": {"__by_id__": {LB: listeners if listeners is not None
                                                else [{"port": 443, "protocol": "HTTPS", "actions": ["forward"]}]}}},
    })


def tg(arn, name):
    return {"arn": arn, "name": name, "type": "instance", "lbs": [LB]}


def test_flags_lb_whose_target_groups_are_empty():
    [f] = run_one("elb-no-targets", snap([tg(TG_A, "blue")], {TG_A: []}))
    assert f.resource == LB
    assert f.severity == "medium"
    assert f.monthly_usd == round(0.0225 * 730, 2)
    assert "LCU" in f.usd_calc
    assert any("describe-target-health" in c and TG_A in c for c in f.verify)


def test_blue_green_with_one_live_colour_is_quiet():
    health = {TG_A: [], TG_B: [{"id": "i-0a1", "state": "healthy"}]}
    assert run_one("elb-no-targets", snap([tg(TG_A, "blue"), tg(TG_B, "green")], health)) == []


def test_redirect_only_lb_is_an_owner_question():
    listeners = [{"port": 80, "protocol": "HTTP", "actions": ["redirect"]}]
    [f] = run_one("elb-no-targets", snap([], {}, listeners))
    assert f.severity == "low"
    assert f.owner_question["en"]
    assert "redirect" in f.t("what")


def test_lb_without_listeners_or_target_groups_is_flagged():
    [f] = run_one("elb-no-targets", snap([], {}, []))
    assert "no listeners" in f.t("what")
    assert f.severity == "medium"


def test_new_lb_and_unknown_health_are_quiet():
    assert run_one("elb-no-targets", snap([tg(TG_A, "blue")], {TG_A: []}, created="2026-01-14T00:00:00Z")) == []
    assert run_one("elb-no-targets", snap([tg(TG_A, "blue")], {})) == []
