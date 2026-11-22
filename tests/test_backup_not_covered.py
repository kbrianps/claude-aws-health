from awshealth.calls_security import (
    BACKUP_SELECTION,
    DB_INSTANCES,
    DYNAMO_PITR,
    DYNAMO_TABLES,
    EFS,
    PROTECTED,
    TAGGED_RESOURCES,
)
from awshealth.testing import run_one, snap_with

DB = "arn:aws:rds:us-east-1:111122223333:db:orders"


def snap(retention=1, protected=(), selection=None, tags=None, pitr="DISABLED", replica=None):
    return snap_with({
        PROTECTED: {"us-east-1": [{"arn": a, "type": "RDS", "last": "2026-01-14T00:00:00Z"} for a in protected]},
        BACKUP_SELECTION: {"us-east-1": {"__by_id__": {"p|s": selection} if selection else {}}},
        TAGGED_RESOURCES: {"us-east-1": []},
        DB_INSTANCES: {"us-east-1": [{"id": "orders", "arn": DB, "engine": "postgres", "retention": retention,
                                      "cluster": None, "replica_of": replica,
                                      "tags": tags or [{"Key": "env", "Value": "prod"}]}]},
        DYNAMO_TABLES: {"us-east-1": ["sessions"]},
        DYNAMO_PITR: {"us-east-1": {"__by_id__": {"sessions": pitr}}},
        EFS: {"us-east-1": []},
    })


def test_prod_rds_with_one_day_and_unprotected_table():
    findings = {f.resource: f for f in run_one("backup-not-covered", snap())}
    assert findings[DB].severity == "high"
    assert "1 day" in findings[DB].t("what")
    table = findings["arn:aws:dynamodb:us-east-1:111122223333:table/sessions"]
    assert table.severity == "medium"
    assert "Point-in-time" in table.t("what")


def test_protected_selected_pitr_and_replica_are_quiet():
    sel = {"list_of_tags": [{"ConditionKey": "env", "ConditionValue": "prod"}]}
    assert run_one("backup-not-covered", snap(protected=[DB], pitr="ENABLED")) == []
    assert run_one("backup-not-covered", snap(selection=sel, pitr="ENABLED")) == []
    assert run_one("backup-not-covered", snap(replica="orders-primary", pitr="ENABLED")) == []


def test_rds_with_longer_retention_is_quiet():
    assert run_one("backup-not-covered", snap(retention=7, pitr="ENABLED")) == []


def test_unknown_protection_data_is_quiet():
    snap_ = snap()
    snap_.put(PROTECTED, "us-east-1", "denied")
    assert run_one("backup-not-covered", snap_) == []
