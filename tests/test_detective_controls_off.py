from awshealth.calls_security import (
    ANALYZERS,
    CONFIG_RECORDERS,
    DB_INSTANCES,
    FUNCTIONS,
    GD_DETECTOR,
    GD_DETECTORS,
    INSTANCES,
    SECURITY_HUB,
    TRAIL_STATUS,
    TRAILS,
)
from awshealth.testing import run_one, snap_with

REGIONS = ["us-east-1", "sa-east-1"]
TRAIL = "arn:aws:cloudtrail:us-east-1:111122223333:trail/main"


def base():
    calls = {
        INSTANCES: {"us-east-1": [{"id": "i-1", "state": "running"}, {"id": "i-2", "state": "running"}],
                    "sa-east-1": [{"id": "i-3", "state": "running"}]},
        FUNCTIONS: {"us-east-1": [], "sa-east-1": []},
        DB_INSTANCES: {"us-east-1": [], "sa-east-1": []},
        GD_DETECTORS: {"us-east-1": ["d1"], "sa-east-1": ["d2"]},
        GD_DETECTOR: {"us-east-1": {"__by_id__": {"d1": {"status": "ENABLED"}}},
                      "sa-east-1": {"__by_id__": {"d2": {"status": "ENABLED"}}}},
        CONFIG_RECORDERS: {r: [{"name": "default", "recording": True, "last": "SUCCESS"}] for r in REGIONS},
        ANALYZERS: {r: [{"name": "a", "type": "ACCOUNT", "status": "ACTIVE"}] for r in REGIONS},
        SECURITY_HUB: {r: {"arn": f"arn:aws:securityhub:{r}:111122223333:hub/default"} for r in REGIONS},
        TRAILS: {"us-east-1": [{"name": "main", "arn": TRAIL, "multi": True, "home": "us-east-1",
                                "validation": True, "org": False}]},
        TRAIL_STATUS: {"us-east-1": {"__by_id__": {TRAIL: {"logging": True}}}},
    }
    return snap_with(calls, regions=REGIONS)


def test_all_on_is_quiet():
    assert run_one("detective-controls-off", base()) == []


def test_region_with_most_workloads_is_high_and_others_medium():
    snap = base()
    snap.put(GD_DETECTORS, "us-east-1", "ok", value=[])
    snap.put(GD_DETECTORS, "sa-east-1", "ok", value=[])
    snap.put(CONFIG_RECORDERS, "sa-east-1", "ok", value=[{"name": "default", "recording": False}])
    findings = {f.region: f for f in run_one("detective-controls-off", snap)}
    assert findings["us-east-1"].severity == "high"
    assert findings["sa-east-1"].severity == "medium"
    assert "AWS Config" in findings["sa-east-1"].t("what")


def test_security_hub_invalid_access_is_off_but_denied_is_unknown():
    snap = base()
    snap.put(SECURITY_HUB, "us-east-1", "unsupported", error="InvalidAccessException")
    snap.put(SECURITY_HUB, "sa-east-1", "denied", error="AccessDeniedException")
    [f] = run_one("detective-controls-off", snap)
    assert f.region == "us-east-1"
    assert "Security Hub" in f.t("title")


def test_region_without_workloads_is_quiet():
    snap = base()
    snap.put(INSTANCES, "sa-east-1", "ok", value=[{"id": "i-3", "state": "terminated"}])
    snap.put(GD_DETECTORS, "sa-east-1", "ok", value=[])
    assert run_one("detective-controls-off", snap) == []


def test_cloudtrail_not_logging_and_validation_off():
    snap = base()
    snap.put(TRAIL_STATUS, "us-east-1", "ok", by_id={TRAIL: {"logging": False}})
    [f] = run_one("detective-controls-off", snap)
    assert f.resource == "cloudtrail/multi-region" and f.severity == "high"
    snap = base()
    snap.put(TRAILS, "us-east-1", "ok", value=[{"name": "main", "arn": TRAIL, "multi": True, "validation": False}])
    [f] = run_one("detective-controls-off", snap)
    assert f.severity == "medium"
    assert "validation" in f.t("title")


def test_org_trail_with_unreadable_status_counts_as_logging():
    snap = base()
    snap.put(TRAILS, "us-east-1", "ok", value=[{"name": "org", "arn": TRAIL, "multi": True, "validation": True,
                                                 "org": True}])
    snap.put(TRAIL_STATUS, "us-east-1", "ok", by_id={TRAIL: {"__error__": "TrailNotFoundException"}})
    assert run_one("detective-controls-off", snap) == []
