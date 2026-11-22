from awshealth.calls_security import FUNCTIONS, RULE_TARGETS, RULES
from awshealth.testing import run_one, snap_with

FN = "arn:aws:lambda:us-east-1:111122223333:function:nightly-report"


def snap(state="ENABLED", functions=(), target=FN, functions_status="ok"):
    return snap_with({
        RULES: {"us-east-1": [{"name": "nightly", "arn": "arn:aws:events:us-east-1:111122223333:rule/nightly",
                               "state": state}]},
        RULE_TARGETS: {"us-east-1": {"__by_id__": {"nightly": [{"id": "t1", "arn": target}]}}},
        FUNCTIONS: {"us-east-1": [{"name": n, "arn": f"arn:aws:lambda:us-east-1:111122223333:function:{n}"}
                                  for n in functions]
                    if functions_status == "ok" else {"__status__": functions_status}},
    })


def test_enabled_rule_with_deleted_function():
    [f] = run_one("eventbridge-target-missing", snap())
    assert f.severity == "medium"
    assert FN in f.t("what")
    assert FN in f.resources


def test_alias_target_of_existing_function_is_quiet():
    assert run_one("eventbridge-target-missing", snap(functions=["nightly-report"], target=FN + ":live")) == []


def test_disabled_rule_cross_account_and_unknown_are_quiet():
    assert run_one("eventbridge-target-missing", snap(state="DISABLED")) == []
    assert run_one("eventbridge-target-missing",
                   snap(target="arn:aws:lambda:us-east-1:444455556666:function:partner")) == []
    assert run_one("eventbridge-target-missing", snap(functions_status="denied")) == []
    assert run_one("eventbridge-target-missing", snap(target="arn:aws:sqs:us-east-1:111122223333:q")) == []
