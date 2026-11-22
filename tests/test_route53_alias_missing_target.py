import shlex

import jmespath

from awshealth.calls_security import ELB_CLASSIC, ELBV2, HOSTED_ZONES, RECORD_SETS
from awshealth.testing import run_one, snap_with

ALB = "app-123456.us-east-1.elb.amazonaws.com"
NLB = "net-abcdef0123456789.elb.us-east-1.amazonaws.com"


def snap(target=f"dualstack.{ALB}.", lbs=(ALB,), classic=(), elbv2_status="ok", name="api.example.com."):
    record = {"name": name, "type": "A", "ttl": None, "values": None,
              "alias": {"DNSName": target, "HostedZoneId": "Z35SXDOTRQ7X7K", "EvaluateTargetHealth": False}}
    return snap_with({
        HOSTED_ZONES: {"global": [{"id": "/hostedzone/Z1", "name": "example.com.", "private": False}]},
        RECORD_SETS: {"global": {"__by_id__": {"/hostedzone/Z1": [record]}}},
        ELBV2: {"us-east-1": [{"name": "app", "dns": d, "arn": "arn", "type": "application"} for d in lbs]
                if elbv2_status == "ok" else {"__status__": elbv2_status}},
        ELB_CLASSIC: {"us-east-1": [{"name": "old", "dns": d} for d in classic]},
    })


def test_flags_alias_to_deleted_alb():
    [f] = run_one("route53-alias-missing-target", snap(lbs=()))
    assert f.severity == "medium"
    assert ALB in f.t("title")
    assert f.region == "us-east-1"


def test_flags_alias_to_deleted_nlb():
    [f] = run_one("route53-alias-missing-target", snap(target=NLB + ".", lbs=(ALB,)))
    assert NLB in f.t("what")


def test_existing_target_case_insensitive_is_quiet():
    assert run_one("route53-alias-missing-target", snap(lbs=(ALB.replace("app", "App"),))) == []
    assert run_one("route53-alias-missing-target", snap(target=ALB, lbs=(), classic=(ALB,))) == []


def test_unknown_region_data_and_non_elb_alias_are_quiet():
    assert run_one("route53-alias-missing-target", snap(lbs=(), elbv2_status="denied")) == []
    assert run_one("route53-alias-missing-target", snap(target="d111.cloudfront.net.", lbs=())) == []
    assert run_one("route53-alias-missing-target",
                   snap(target="app-1.eu-west-1.elb.amazonaws.com.", lbs=())) == []


def test_hostile_record_name_keeps_a_quoted_verify_command():
    name = "\\052 $(touch x).example.com."
    [f] = run_one("route53-alias-missing-target", snap(lbs=(), name=name))
    assert len(f.verify) == 3
    args = shlex.split(f.verify[0])
    query = args[args.index("--query") + 1]
    page = {"ResourceRecordSets": [{"Name": name, "AliasTarget": {"DNSName": "x"}}, {"Name": "other."}]}
    assert jmespath.search(query, page) == ["x"]
