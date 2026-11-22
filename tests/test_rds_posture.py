from awshealth.calls_compute import RDS_CLUSTERS, RDS_INSTANCES
from awshealth.testing import run_one, snap_with


def inst(iid, env=None, **kw):
    base = {"id": iid, "arn": f"arn:aws:rds:us-east-1:111122223333:db:{iid}", "engine": "postgres",
            "encrypted": True, "multi_az": True, "retention": 7, "public": False, "deletion_protection": True,
            "cluster": None, "replica_of": None, "tags": [{"Key": "Environment", "Value": env}] if env else []}
    return base | kw


def snap(instances, clusters=None):
    return snap_with({RDS_INSTANCES: {"us-east-1": instances}, RDS_CLUSTERS: {"us-east-1": clusters or []}})


def test_untagged_unencrypted_public_instance_is_high():
    [f] = run_one("rds-posture", snap([inst("legacy", encrypted=False, public=True)]))
    assert f.severity == "high"
    assert f.category == "security"
    assert {c.path for c in f.claims} == {"legacy.StorageEncrypted", "legacy.PubliclyAccessible"}
    assert f.confidence == "medium"


def test_production_resilience_issues_aggregate_in_one_finding():
    [f] = run_one("rds-posture", snap([inst("orders", env="production", multi_az=False, retention=3,
                                            deletion_protection=False)]))
    assert f.severity == "medium"
    assert f.category == "resilience"
    assert len(f.claims) == 3
    assert "3 posture issues" in f.t("title")


def test_staging_downgrades_encryption_and_skips_prod_only_rules():
    [f] = run_one("rds-posture", snap([inst("stg", env="staging", encrypted=False, multi_az=False,
                                         deletion_protection=False)]))
    assert f.severity == "medium"
    assert len(f.claims) == 1


def test_replica_backups_and_healthy_instances_are_quiet():
    assert run_one("rds-posture", snap([inst("ok", env="prod"), inst("replica", retention=0, replica_of="ok")])) == []


def test_aurora_members_are_judged_once_at_cluster_level():
    members = [inst(m, cluster="ledger", multi_az=False, retention=1, deletion_protection=False)
               for m in ("ledger-1", "ledger-2")]
    cluster = {"id": "ledger", "arn": "arn:aws:rds:us-east-1:111122223333:cluster:ledger",
               "engine": "aurora-postgresql",
               "encrypted": True, "multi_az": True, "retention": 1, "deletion_protection": True,
               "tags": [{"Key": "env", "Value": "prod"}]}
    [f] = run_one("rds-posture", snap(members, [cluster]))
    assert f.resource.endswith("cluster:ledger")
    assert [c.path for c in f.claims] == ["ledger.BackupRetentionPeriod"]
