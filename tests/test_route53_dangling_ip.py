import jmespath

from awshealth.calls_core import IP_RANGES
from awshealth.calls_security import ADDRESSES, ENI_PUBLIC_IPS, HOSTED_ZONES, RECORD_SETS
from awshealth.testing import run_one, snap_with

RANGES = [{"cidr": "198.51.100.0/24", "region": "us-east-1", "service": "EC2"},
          {"cidr": "203.0.113.0/24", "region": "us-east-1", "service": "GLOBALACCELERATOR"},
          {"cidr": "192.0.2.0/24", "region": "eu-west-1", "service": "EC2"}]


def snap(value="198.51.100.10", private=False, owned="198.51.100.20", addresses_status="ok"):
    records = [{"name": "app.example.com.", "type": "A", "ttl": 300, "values": [value], "alias": None},
               {"name": "www.example.com.", "type": "CNAME", "ttl": 300, "values": ["app.example.com"], "alias": None}]
    return snap_with({
        IP_RANGES: {"global": RANGES},
        HOSTED_ZONES: {"global": [{"id": "/hostedzone/Z1", "name": "example.com.", "private": private}]},
        RECORD_SETS: {"global": {"__by_id__": {"/hostedzone/Z1": records}}},
        ADDRESSES: {"us-east-1": [{"ip": owned}] if addresses_status == "ok" else {"__status__": addresses_status}},
        ENI_PUBLIC_IPS: {"us-east-1": [{"public_ip": "198.51.100.30"}, {"public_ip": None}]},
    })


def test_flags_unowned_ec2_ip():
    [f] = run_one("route53-dangling-ip", snap())
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.resource == "Z1/app.example.com/A/198.51.100.10"
    assert "198.51.100.10" in f.t("title")
    assert all("--region" in c and "--query" in c and "--output" in c for c in f.verify)


def test_owned_ip_is_quiet():
    assert run_one("route53-dangling-ip", snap(owned="198.51.100.10")) == []
    assert run_one("route53-dangling-ip", snap(value="198.51.100.30")) == []


def test_non_ec2_range_private_zone_and_outside_aws_are_quiet():
    assert run_one("route53-dangling-ip", snap(value="203.0.113.5")) == []
    assert run_one("route53-dangling-ip", snap(private=True)) == []
    assert run_one("route53-dangling-ip", snap(value="10.0.0.1")) == []


def test_denied_addresses_is_unknown_not_finding():
    assert run_one("route53-dangling-ip", snap(addresses_status="denied")) == []


def test_unscanned_region_lowers_confidence():
    [f] = run_one("route53-dangling-ip", snap(value="192.0.2.9"))
    assert f.confidence == "medium"
    assert "eu-west-1" in f.t("what")
    assert "eu-west-1" in f.t("what", "pt-BR")


def test_record_sets_keep_only_address_and_alias_records():
    page = {"ResourceRecordSets": [
        {"Name": "a.example.com.", "Type": "A", "TTL": 300, "ResourceRecords": [{"Value": "192.0.2.10"}]},
        {"Name": "b.example.com.", "Type": "AAAA", "TTL": 300, "ResourceRecords": [{"Value": "2001:db8::1"}]},
        {"Name": "c.example.com.", "Type": "CNAME", "TTL": 300, "ResourceRecords": [{"Value": "a.example.com."}]},
        {"Name": "d.example.com.", "Type": "A", "AliasTarget": {"DNSName": "lb.example.com.", "HostedZoneId": "Z1"}},
        {"Name": "example.com.", "Type": "TXT", "TTL": 300, "ResourceRecords": [{"Value": "verification=x"}]},
        {"Name": "s._domainkey.example.com.", "Type": "TXT", "ResourceRecords": [{"Value": "v=DKIM1; p=x"}]},
        {"Name": "example.com.", "Type": "MX", "TTL": 300, "ResourceRecords": [{"Value": "10 mail.example.com."}]},
    ]}
    kept = jmespath.search(RECORD_SETS.keep, page)
    assert [r["name"] for r in kept] == ["a.example.com.", "b.example.com.", "c.example.com.", "d.example.com."]
    assert "verification" not in str(kept) and "DKIM" not in str(kept)
