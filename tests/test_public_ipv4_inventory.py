from awshealth.calls_compute import ADDRESSES, INSTANCES, NETWORK_INTERFACES
from awshealth.testing import run_one, snap_with


def snap(enis, eips=None, instances=None):
    return snap_with({
        NETWORK_INTERFACES: {"us-east-1": enis},
        ADDRESSES: {"us-east-1": eips or []},
        INSTANCES: {"us-east-1": instances or []},
    })


def test_counts_distinct_billed_addresses_and_skips_byoip():
    enis = [
        {"id": "eni-1", "type": "interface", "public_ip": "203.0.113.10", "instance": "i-0a1", "description": ""},
        {"id": "eni-2", "type": "nat_gateway", "public_ip": "203.0.113.11", "description": "Interface for NAT"},
        {"id": "eni-3", "type": "interface", "public_ip": "203.0.113.12", "description": "ELB app/web/0a1"},
        {"id": "eni-4", "type": "interface", "public_ip": "198.51.100.6", "instance": "i-0b2", "description": ""},
        {"id": "eni-5", "type": "interface", "public_ip": None, "description": ""},
    ]
    eips = [{"ip": "198.51.100.5", "association": None, "pool": "amazon"},
            {"ip": "198.51.100.6", "association": "eipassoc-1", "pool": "ipv4pool-ec2-0abc"}]
    instances = [{"id": "i-0a1", "public_ip": "203.0.113.10"}]
    [f] = run_one("public-ipv4-inventory", snap(enis, eips, instances))
    assert f.severity == "info"
    assert "4 public IPv4" in f.t("title")
    assert f.monthly_usd == round(4 * 0.005 * 730, 2)
    assert "1 BYOIP" in f.t("what")
    assert "load_balancer 1" in f.t("what") and "nat_gateway 1" in f.t("what")


def test_only_byoip_addresses_is_quiet():
    eips = [{"ip": "198.51.100.6", "association": None, "pool": "ipv4pool-ec2-0abc"}]
    assert run_one("public-ipv4-inventory", snap([], eips)) == []


def test_no_public_addresses_is_quiet():
    assert run_one("public-ipv4-inventory", snap([{"id": "eni-5", "type": "interface", "public_ip": None}])) == []
