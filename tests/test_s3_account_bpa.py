from awshealth.calls_security import ACCOUNT_BPA
from awshealth.testing import run_one, snap_with

ALL_ON = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def test_partly_off_is_medium():
    [f] = run_one("s3-account-bpa", snap_with({ACCOUNT_BPA: {"us-east-1": {**ALL_ON, "RestrictPublicBuckets": False}}}))
    assert f.severity == "medium"
    assert "RestrictPublicBuckets" in f.t("what")
    assert "--account-id 111122223333" in f.verify[0]


def test_missing_configuration_is_high():
    snap = snap_with({})
    snap.put(ACCOUNT_BPA, "us-east-1", "error", error="NoSuchPublicAccessBlockConfiguration")
    [f] = run_one("s3-account-bpa", snap)
    assert f.severity == "high"
    assert "no S3 Block Public Access" in f.t("what")


def test_other_errors_and_all_on_are_quiet():
    snap = snap_with({})
    snap.put(ACCOUNT_BPA, "us-east-1", "error", error="Throttling")
    assert run_one("s3-account-bpa", snap) == []
    assert run_one("s3-account-bpa", snap_with({ACCOUNT_BPA: {"us-east-1": ALL_ON}})) == []
