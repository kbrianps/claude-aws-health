import json

from awshealth.calls_security import ACCOUNT_BPA, BUCKET_BPA, BUCKET_POLICY, BUCKETS
from awshealth.testing import run_one, snap_with


def policy(principal="*", action="s3:GetObject", condition=None, effect="Allow", extra=()):
    stmt = {"Effect": effect, "Principal": principal, "Action": action,
            "Resource": "arn:aws:s3:::site.example.com/*"}
    if condition:
        stmt["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [stmt, *extra]})


def snap(pol, bucket_bpa=None, account_bpa=None):
    return snap_with({
        BUCKETS: {"global": ["site.example.com", "private-bucket"]},
        BUCKET_POLICY: {"global": {"__by_id__": {"site.example.com": pol,
                                                 "private-bucket": {"__error__": "NoSuchBucketPolicy"}}}},
        BUCKET_BPA: {"global": {"__by_id__": {
            "site.example.com": bucket_bpa or {"__error__": "NoSuchPublicAccessBlockConfiguration"}}}},
        ACCOUNT_BPA: {"us-east-1": account_bpa if account_bpa is not None else {"RestrictPublicBuckets": False}},
    })


def test_flags_public_get_object():
    [f] = run_one("s3-public-policy", snap(policy()))
    assert f.severity == "high"
    assert f.resource == "arn:aws:s3:::site.example.com"
    assert "s3:GetObject" in f.t("title")
    assert f.owner_question


def test_wildcard_action_and_aws_star_principal():
    [f] = run_one("s3-public-policy", snap(policy(principal={"AWS": ["*"]}, action="s3:*")))
    assert "s3:PutObject" in f.t("what")


def test_referer_condition_is_still_public_and_says_so():
    [f] = run_one("s3-public-policy", snap(policy(condition={"StringLike": {"aws:Referer": "https://example.com/*"}})))
    assert "aws:referer" in f.t("what")
    assert "forjar" in f.t("what", "pt-BR")


def test_restricting_conditions_and_bpa_are_quiet():
    assert run_one("s3-public-policy", snap(policy(condition={"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}}))) == []
    assert run_one("s3-public-policy", snap(policy(condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}}))) == []
    assert run_one("s3-public-policy", snap(policy(), bucket_bpa={"RestrictPublicBuckets": True})) == []
    assert run_one("s3-public-policy", snap(policy(), account_bpa={"RestrictPublicBuckets": True})) == []


def test_deny_with_source_ip_restricts_and_service_principal_is_quiet():
    deny = {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
            "Condition": {"NotIpAddress": {"aws:SourceIp": "192.0.2.0/24"}}}
    assert run_one("s3-public-policy", snap(policy(extra=[deny]))) == []
    assert run_one("s3-public-policy", snap(policy(principal={"Service": "cloudfront.amazonaws.com"}))) == []
