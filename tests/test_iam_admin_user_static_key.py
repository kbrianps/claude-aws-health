from awshealth.calls_security import ACCESS_KEYS, AUTH_DETAILS, KEY_LAST_USED
from awshealth.testing import run_one, snap_with

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def auth(attached=(), groups=(), inline=(), group_attached=(), policies=()):
    return {
        "users": [{"name": "deploy", "arn": "arn:aws:iam::111122223333:user/deploy", "groups": list(groups),
                   "attached": list(attached), "inline": list(inline), "tags": []}],
        "groups": [{"name": "ops", "attached": list(group_attached), "inline": []}],
        "roles": [],
        "policies": list(policies),
    }


def snap(details, created="2025-06-01T00:00:00Z", status="Active", last_used="2026-01-10T00:00:00Z"):
    return snap_with({
        AUTH_DETAILS: {"global": details},
        ACCESS_KEYS: {"global": {"__by_id__": {"deploy": [{"id": "AKIAEXAMPLE1", "status": status,
                                                           "created": created}]}}},
        KEY_LAST_USED: {"global": {"__by_id__": {"AKIAEXAMPLE1": {"user": "deploy", "last_used": last_used,
                                                                 "service": "s3"}}}},
    })


def test_direct_admin_with_young_key_is_high():
    [f] = run_one("iam-admin-user-static-key", snap(auth(attached=[ADMIN])))
    assert f.severity == "high"
    assert "AdministratorAccess" in f.t("what")
    assert "2026-01-10" in f.t("what")


def test_admin_through_group_with_old_key_is_critical():
    [f] = run_one("iam-admin-user-static-key", snap(auth(groups=["ops"], group_attached=[ADMIN]),
                                                    created="2024-01-01T00:00:00Z", last_used=None))
    assert f.severity == "critical"
    assert "group ops" in f.t("what")
    assert "never" in f.t("what")


def test_inline_and_custom_full_access_count_as_admin():
    inline = [{"effect": "Allow", "action": "*", "resource": "*"}]
    assert run_one("iam-admin-user-static-key", snap(auth(inline=inline)))
    custom = [{"arn": "arn:aws:iam::111122223333:policy/All", "name": "All",
               "statements": [{"effect": "Allow", "action": ["*"], "resource": ["*"]}]}]
    assert run_one("iam-admin-user-static-key",
                   snap(auth(attached=["arn:aws:iam::111122223333:policy/All"], policies=custom)))


def test_inactive_key_or_non_admin_is_quiet():
    assert run_one("iam-admin-user-static-key", snap(auth(attached=[ADMIN]), status="Inactive")) == []
    scoped = [{"effect": "Allow", "action": "s3:*", "resource": "*"}]
    assert run_one("iam-admin-user-static-key", snap(auth(inline=scoped))) == []


def test_missing_last_used_data_says_unknown():
    snap_ = snap(auth(attached=[ADMIN]))
    snap_.put(KEY_LAST_USED, "global", "ok", by_id={})
    [f] = run_one("iam-admin-user-static-key", snap_)
    assert "last used unknown" in f.t("what")
    assert "desconhecido" in f.t("what", "pt-BR")


def test_single_key_title_is_singular():
    [f] = run_one("iam-admin-user-static-key", snap(auth(attached=[ADMIN])))
    assert "and 1 active access key" in f.t("title") and "(s)" not in f.t("title")
    assert f.t("title", "pt-BR").endswith("1 chave de acesso ativa")
