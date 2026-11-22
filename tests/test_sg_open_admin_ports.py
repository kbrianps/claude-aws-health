from awshealth.calls_compute import NETWORK_INTERFACES, SECURITY_GROUPS
from awshealth.checks.sg_open_admin_ports import open_ports
from awshealth.testing import run_one, snap_with


def sg(gid, rules):
    return {"id": gid, "name": f"name-{gid}", "vpc": "vpc-0a1", "ingress": rules}


def rule(proto="tcp", lo=22, hi=22, v4=None, v6=None):
    return {"proto": proto, "from": lo, "to": hi, "v4": v4 or [], "v6": v6 or []}


def snap(groups, enis=None):
    return snap_with({SECURITY_GROUPS: {"us-east-1": groups}, NETWORK_INTERFACES: {"us-east-1": enis or []}})


def eni(eid, group, public_ip=None):
    return {"id": eid, "type": "interface", "public_ip": public_ip, "instance": "i-0a1", "groups": [group]}


def test_ssh_open_on_public_instance_is_high():
    [f] = run_one("sg-open-admin-ports", snap([sg("sg-1", [rule(v4=["0.0.0.0/0"])])],
                                             [eni("eni-1", "sg-1", "203.0.113.10")]))
    assert f.severity == "high"
    assert "22 (SSH)" in f.t("title")
    assert "eni-1" in f.t("what")
    assert all("Values=sg-1" in c for c in f.verify)


def test_private_only_attachment_is_medium_and_unused_is_low():
    groups = [sg("sg-2", [rule(lo=5432, hi=5432, v6=["::/0"])]), sg("sg-3", [rule(proto="-1", lo=None, hi=None,
                                                                                   v4=["0.0.0.0/0"])])]
    found = {f.resource.rsplit("/", 1)[1]: f for f in run_one("sg-open-admin-ports",
                                                             snap(groups, [eni("eni-2", "sg-2")]))}
    assert found["sg-2"].severity == "medium"
    assert found["sg-2"].notes
    assert found["sg-3"].severity == "low"
    assert "27017 (MongoDB)" in found["sg-3"].t("title")


def test_private_cidr_web_ports_and_udp_are_quiet():
    groups = [sg("sg-4", [rule(v4=["10.0.0.0/8"]), rule(lo=443, hi=443, v4=["0.0.0.0/0"]),
                          rule(proto="udp", lo=0, hi=65535, v4=["0.0.0.0/0"])])]
    assert run_one("sg-open-admin-ports", snap(groups)) == []


def test_port_range_matching():
    assert open_ports(rule(lo=3000, hi=3400, v4=["0.0.0.0/0"])) == ([3306, 3389], ["0.0.0.0/0"])
    assert open_ports(rule(proto="6", lo=6379, hi=6379, v4=["0.0.0.0/0"]))[0] == [6379]
