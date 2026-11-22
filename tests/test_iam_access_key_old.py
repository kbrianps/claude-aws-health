from awshealth.calls_security import ACCESS_KEYS, KEY_LAST_USED, USERS
from awshealth.testing import run_one, snap_with


def snap(keys, last_used):
    return snap_with({
        USERS: {"global": [{"name": "ci", "arn": "arn:aws:iam::111122223333:user/ci"}]},
        ACCESS_KEYS: {"global": {"__by_id__": {"ci": keys}}},
        KEY_LAST_USED: {"global": {"__by_id__": last_used}},
    })


def key(kid, created, status="Active"):
    return {"id": kid, "status": status, "created": created}


def test_old_key_is_medium_one_finding_per_user():
    keys = [key("AKIAOLD1", "2025-01-01T00:00:00Z"), key("AKIAOLD2", "2025-02-01T00:00:00Z")]
    used = {"AKIAOLD1": {"last_used": "2026-01-14T00:00:00Z"}, "AKIAOLD2": {"last_used": "2026-01-14T00:00:00Z"}}
    [f] = run_one("iam-access-key-old", snap(keys, used))
    assert f.severity == "medium"
    assert "AKIAOLD1" in f.t("what") and "AKIAOLD2" in f.t("what")
    assert f.resource == "arn:aws:iam::111122223333:user/ci"


def test_unused_key_is_low_with_question():
    [f] = run_one("iam-access-key-old", snap([key("AKIAIDLE", "2025-10-01T00:00:00Z")],
                                             {"AKIAIDLE": {"last_used": "2025-10-02T00:00:00Z"}}))
    assert f.severity == "low"
    assert f.owner_question
    assert "AKIAIDLE" in f.t("what")


def test_missing_last_used_is_not_called_unused():
    assert run_one("iam-access-key-old", snap([key("AKIANEW", "2025-12-01T00:00:00Z")], {})) == []


def test_fresh_or_inactive_keys_are_quiet():
    keys = [key("AKIAFRESH", "2025-12-01T00:00:00Z"), key("AKIAOFF", "2020-01-01T00:00:00Z", "Inactive")]
    assert run_one("iam-access-key-old", snap(keys, {"AKIAFRESH": {"last_used": "2026-01-14T00:00:00Z"}})) == []
