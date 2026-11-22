from awshealth.calls_security import AUTH_DETAILS
from awshealth.testing import run_one, snap_with

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
EXT = "arn:aws:iam::444455556666:root"


def role(principal, keys=(), attached=(ADMIN,), last_used="2026-01-01T00:00:00Z", path="/",
         created="2024-01-01T00:00:00Z"):
    return {"name": "vendor", "arn": "arn:aws:iam::111122223333:role/vendor", "path": path, "created": created,
            "last_used": last_used, "attached": list(attached), "inline": [],
            "trust": [{"effect": "Allow", "principal": principal, "condition_keys": list(keys)}]}


def snap(*roles):
    return snap_with({AUTH_DETAILS: {"global": {"users": [], "groups": [], "roles": list(roles), "policies": []}}})


def test_external_admin_without_external_id_is_high():
    [f] = run_one("iam-role-external-admin-trust", snap(role({"AWS": EXT})))
    assert f.severity == "high"
    assert "444455556666" in f.t("title")


def test_any_principal_is_called_out():
    [f] = run_one("iam-role-external-admin-trust", snap(role("*")))
    assert "any AWS account" in f.t("what")


def test_external_id_same_account_service_and_org_are_quiet():
    assert run_one("iam-role-external-admin-trust", snap(role({"AWS": EXT}, keys=["sts:ExternalId"]))) == []
    assert run_one("iam-role-external-admin-trust", snap(role({"AWS": "arn:aws:iam::111122223333:root"}))) == []
    assert run_one("iam-role-external-admin-trust", snap(role({"Service": "ec2.amazonaws.com"}))) == []
    assert run_one("iam-role-external-admin-trust", snap(role("*", keys=["aws:PrincipalOrgID"]))) == []
    assert run_one("iam-role-external-admin-trust", snap(role({"AWS": EXT}, path="/aws-service-role/"))) == []


def test_unused_external_role_is_low_with_question():
    [f] = run_one("iam-role-external-admin-trust",
                  snap(role({"AWS": ["444455556666"]}, keys=["sts:ExternalId"], attached=(), last_used=None)))
    assert f.severity == "low"
    assert f.owner_question["en"]
    assert run_one("iam-role-external-admin-trust",
                   snap(role({"AWS": EXT}, keys=["sts:ExternalId"], attached=(), last_used=None,
                             created="2025-12-01T00:00:00Z"))) == []
