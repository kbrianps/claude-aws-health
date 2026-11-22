from awshealth.calls_compute import ADDRESSES
from awshealth.testing import run_one, snap_with


def snap(*addresses):
    return snap_with({ADDRESSES: {"us-east-1": list(addresses)}})


def eip(ip="203.0.113.10", alloc="eipalloc-0a1", association=None, pool="amazon"):
    return {"ip": ip, "allocation": alloc, "association": association, "instance": None, "eni": None,
            "pool": pool, "tags": []}


def test_flags_unassociated_eip_as_owner_question():
    [f] = run_one("eip-unassociated", snap(eip()))
    assert f.monthly_usd == 3.65
    assert f.severity == "low"
    assert "203.0.113.10" in f.owner_question["en"]
    assert "para sempre" in f.owner_question["pt-BR"]
    assert all("--region us-east-1" in c for c in f.verify)


def test_byoip_address_has_no_charge():
    [f] = run_one("eip-unassociated", snap(eip(pool="ipv4pool-ec2-0abc")))
    assert f.monthly_usd is None
    assert "BYOIP" in f.t("risk")


def test_associated_eip_is_quiet():
    assert run_one("eip-unassociated", snap(eip(association="eipassoc-0a1"))) == []
