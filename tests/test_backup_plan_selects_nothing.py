from awshealth.calls_security import BACKUP_PLAN, BACKUP_PLANS, BACKUP_SELECTION, BACKUP_VAULTS, TAGGED_RESOURCES
from awshealth.testing import run_one, snap_with

DB = "arn:aws:rds:us-east-1:111122223333:db:orders"


def snap(selection, resources):
    return snap_with({
        BACKUP_PLANS: {"us-east-1": [{"id": "plan-1", "name": "daily"}]},
        BACKUP_PLAN: {"us-east-1": {"__by_id__": {"plan-1": ["Default"]}}},
        BACKUP_SELECTION: {"us-east-1": {"__by_id__": {"plan-1|sel-1": {"plan": "plan-1", "id": "sel-1",
                                                                         "name": "tagged", **selection}}}},
        BACKUP_VAULTS: {"us-east-1": [{"name": "Default", "recovery_points": 0}]},
        TAGGED_RESOURCES: {"us-east-1": resources},
    })


LIST_OF_TAGS = {"list_of_tags": [{"ConditionType": "STRINGEQUALS", "ConditionKey": "Aws-Backup",
                                  "ConditionValue": "true"}]}


def test_typo_tag_on_production_database_is_high():
    resources = [{"arn": DB, "tags": [{"Key": "AWS-bakcup", "Value": "true"}, {"Key": "env", "Value": "production"}]}]
    [f] = run_one("backup-plan-selects-nothing", snap(LIST_OF_TAGS, resources))
    assert f.severity == "high"
    assert "AWS-bakcup=true" in f.t("what")
    assert "Default" in f.t("what")
    assert DB in f.resources


def test_no_near_miss_is_medium():
    resources = [{"arn": DB, "tags": [{"Key": "team", "Value": "data"}]}]
    [f] = run_one("backup-plan-selects-nothing", snap(LIST_OF_TAGS, resources))
    assert f.severity == "medium"
    assert "Near misses" not in f.t("what")


def test_matching_resource_is_quiet():
    resources = [{"arn": DB, "tags": [{"Key": "Aws-Backup", "Value": "true"}]}]
    assert run_one("backup-plan-selects-nothing", snap(LIST_OF_TAGS, resources)) == []


def test_conditions_with_resource_type_and_unsupported_types():
    sel = {"resources": ["arn:aws:rds:*:*:db:*"],
           "conditions": {"StringEquals": [{"ConditionKey": "aws:ResourceTag/backup", "ConditionValue": "daily"}]}}
    queue = {"arn": "arn:aws:sqs:us-east-1:111122223333:jobs", "tags": [{"Key": "backup", "Value": "daily"}]}
    volume = {"arn": "arn:aws:ec2:us-east-1:111122223333:volume/vol-1", "tags": [{"Key": "backup", "Value": "daily"}]}
    [f] = run_one("backup-plan-selects-nothing", snap(sel, [queue, volume]))
    assert "backup=daily" in f.t("what")
    db = {"arn": DB, "tags": [{"Key": "backup", "Value": "daily"}]}
    assert run_one("backup-plan-selects-nothing", snap(sel, [db])) == []


def test_resource_only_or_not_equals_selections_are_quiet():
    assert run_one("backup-plan-selects-nothing", snap({"resources": ["*"]}, [])) == []
    sel = {"conditions": {"StringNotEquals": [{"ConditionKey": "aws:ResourceTag/skip", "ConditionValue": "yes"}]}}
    assert run_one("backup-plan-selects-nothing", snap(sel, [])) == []


def test_short_keys_need_exact_case_insensitive_match():
    sel = {"list_of_tags": [{"ConditionKey": "env", "ConditionValue": "prod"}]}
    resources = [{"arn": DB, "tags": [{"Key": "eng", "Value": "prod"}]}]
    [f] = run_one("backup-plan-selects-nothing", snap(sel, resources))
    assert f.severity == "medium"
    assert "Near misses" not in f.t("what")
