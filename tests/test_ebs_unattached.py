from awshealth.calls_compute import VOLUMES
from awshealth.testing import run_one, snap_with


def snap(*volumes):
    return snap_with({VOLUMES: {"us-east-1": list(volumes)}})


def vol(vid="vol-0a1", state="available", size=100, vtype="gp3", tags=None):
    return {"id": vid, "state": state, "size": size, "type": vtype, "created": "2025-10-01T00:00:00Z",
            "attachments": [], "tags": tags or []}


def test_flags_available_volume_with_dollars():
    [f] = run_one("ebs-unattached", snap(vol(tags=[{"Key": "Name", "Value": "old-data"}])))
    assert f.severity == "medium"
    assert f.monthly_usd == 8.0
    assert "old-data" in f.t("title")
    assert "106 days" in f.t("what")
    assert all("--region us-east-1" in c and "--query" in c and "--output" in c for c in f.verify)
    assert "anexado" in f.t("title", "pt-BR")


def test_kubernetes_pvc_volume_becomes_owner_question():
    tags = [{"Key": "kubernetes.io/created-for/pvc/name", "Value": "data-postgres-0"}]
    [f] = run_one("ebs-unattached", snap(vol(tags=tags)))
    assert f.severity == "low"
    assert f.confidence == "low"
    assert "data-postgres-0" in f.owner_question["en"]
    assert f.owner_question["pt-BR"]


def test_attached_volume_is_quiet():
    assert run_one("ebs-unattached", snap(vol(state="in-use"))) == []


def test_unknown_type_has_no_dollars():
    [f] = run_one("ebs-unattached", snap(vol(vtype="io2")))
    assert f.monthly_usd is None
    assert f.usd_calc == ""
