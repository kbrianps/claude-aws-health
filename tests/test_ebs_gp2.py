from awshealth.calls_compute import VOLUMES
from awshealth.testing import run_one, snap_with


def vol(vid, size, vtype="gp2"):
    return {"id": vid, "state": "in-use", "size": size, "type": vtype, "attachments": ["i-0a1"], "tags": []}


def snap(*volumes):
    return snap_with({VOLUMES: {"us-east-1": list(volumes)}})


def test_aggregates_gp2_saving_per_region():
    [f] = run_one("ebs-gp2", snap(vol("vol-1", 100), vol("vol-2", 160), vol("vol-3", 50, "gp3")))
    assert f.severity == "low"
    assert f.monthly_usd == 5.2
    assert len(f.resources) == 2
    assert "upper bound" not in f.usd_calc
    assert f.confidence == "high"


def test_large_gp2_volume_marks_saving_as_upper_bound():
    [f] = run_one("ebs-gp2", snap(vol("vol-big", 2000)))
    assert "upper bound" in f.usd_calc
    assert f.confidence == "medium"
    assert "provisioned IOPS" in f.t("risk")


def test_no_gp2_is_quiet():
    assert run_one("ebs-gp2", snap(vol("vol-3", 50, "gp3"))) == []
