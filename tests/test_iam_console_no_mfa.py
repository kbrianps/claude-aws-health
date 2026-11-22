from awshealth.calls_security import AUTH_DETAILS, LOGIN_PROFILE, MFA_DEVICES, USERS
from awshealth.testing import run_one, snap_with

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def snap(profile=None, mfa=0, last_used="2026-01-01T00:00:00Z", attached=()):
    profile = profile if profile is not None else {"created": "2025-01-01T00:00:00Z"}
    return snap_with({
        USERS: {"global": [{"name": "alice", "arn": "arn:aws:iam::111122223333:user/alice",
                            "created": "2025-01-01T00:00:00Z", "password_last_used": last_used}]},
        LOGIN_PROFILE: {"global": {"__by_id__": {"alice": profile}}},
        MFA_DEVICES: {"global": {"__by_id__": {"alice": mfa}}},
        AUTH_DETAILS: {"global": {"users": [{"name": "alice", "attached": list(attached), "groups": [], "inline": []}],
                                  "groups": [], "roles": [], "policies": []}},
    })


def test_admin_without_mfa_is_high():
    [f] = run_one("iam-console-no-mfa", snap(attached=[ADMIN]))
    assert f.severity == "high"
    assert "administrator" in f.t("what")


def test_regular_user_without_mfa_is_medium():
    [f] = run_one("iam-console-no-mfa", snap())
    assert f.severity == "medium"
    assert not f.owner_question


def test_never_used_old_password_is_low_with_question():
    [f] = run_one("iam-console-no-mfa", snap(last_used=None))
    assert f.severity == "low"
    assert f.owner_question["pt-BR"]


def test_no_login_profile_or_mfa_present_is_quiet():
    assert run_one("iam-console-no-mfa", snap(profile={"__error__": "NoSuchEntity"})) == []
    assert run_one("iam-console-no-mfa", snap(mfa=1)) == []
