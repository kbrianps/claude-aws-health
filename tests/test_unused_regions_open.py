from awshealth.calls_compute import (
    ECS_CLUSTERS,
    FUNCTIONS,
    GUARDDUTY_DETECTORS,
    INSTANCES,
    LOAD_BALANCERS,
    RDS_INSTANCES,
    VOLUMES,
)
from awshealth.checks.eks_extended_support import LIST_CLUSTERS
from awshealth.testing import run_one, snap_with

REGIONS = ["us-east-1", "eu-west-3", "ap-south-1", "sa-east-1"]
INVENTORY = [INSTANCES, VOLUMES, FUNCTIONS, RDS_INSTANCES, ECS_CLUSTERS, LIST_CLUSTERS, LOAD_BALANCERS]


def snap(detectors, overrides=None):
    data = {c: {r: [] for r in REGIONS} for c in INVENTORY}
    data[INSTANCES]["us-east-1"] = [{"id": "i-0a1", "state": "running"}]
    data[GUARDDUTY_DETECTORS] = {r: detectors.get(r, []) for r in REGIONS}
    for (c, r), v in (overrides or {}).items():
        data[c][r] = v
    return snap_with(data, regions=REGIONS)


def test_lists_empty_regions_without_guardduty():
    [f] = run_one("unused-regions-open", snap({"us-east-1": ["d1"]}))
    assert f.region == "global"
    assert f.severity == "high"
    assert "eu-west-3, ap-south-1, sa-east-1" in f.t("title")
    assert "management account" in f.t("risk")
    assert "aws:RequestedRegion" in f.t("fix")
    assert "us-east-1" not in f.t("title")


def test_guardduty_on_or_unknown_inventory_excludes_region():
    overrides = {(FUNCTIONS, "sa-east-1"): {"__status__": "denied"}}
    [f] = run_one("unused-regions-open", snap({"us-east-1": ["d1"], "ap-south-1": ["d2"]}, overrides))
    assert "eu-west-3" in f.t("title")
    assert "ap-south-1" not in f.t("title")
    assert "sa-east-1" not in f.t("title")


def test_every_region_watched_is_quiet():
    assert run_one("unused-regions-open", snap({r: ["d"] for r in REGIONS})) == []
