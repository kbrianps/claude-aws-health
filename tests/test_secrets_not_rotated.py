from awshealth.calls_security import SECRETS
from awshealth.testing import run_one, snap_with


def secret(name="app/db", rotation=False, changed="2024-06-01T00:00:00Z", accessed="2026-01-14T00:00:00Z",
           created="2024-06-01T00:00:00Z", owner=None):
    return {"name": name, "arn": f"arn:aws:secretsmanager:us-east-1:111122223333:secret:{name}-AbCdEf",
            "rotation": rotation, "changed": changed, "accessed": accessed, "created": created, "owner": owner,
            "tags": []}


def run(*secrets):
    return run_one("secrets-not-rotated", snap_with({SECRETS: {"us-east-1": list(secrets)}}))


def test_unrotated_old_secret_in_use_has_no_dollars():
    [f] = run(secret())
    assert f.severity == "low"
    assert f.monthly_usd is None
    assert "not rotated" in f.t("title")


def test_unused_secret_costs_forty_cents():
    [f] = run(secret(changed="2025-12-01T00:00:00Z", accessed="2025-09-01T00:00:00Z"))
    assert f.monthly_usd == 0.40
    assert "unused" in f.t("title")
    assert f.owner_question
    assert "0.40" in f.usd_calc


def test_never_accessed_old_secret_is_unused():
    [f] = run(secret(rotation=True, accessed=None))
    assert "never read" in f.t("what")


def test_rotated_recent_and_managed_secrets_are_quiet():
    assert run(secret(rotation=True)) == []
    assert run(secret(changed="2025-12-01T00:00:00Z")) == []
    assert run(secret(owner="rds", accessed=None)) == []
