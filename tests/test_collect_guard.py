import json
import re
from pathlib import Path

import boto3
import botocore.session
import pytest
import yaml
from botocore.stub import Stubber

from awshealth import calls_core
from awshealth.collect.guard import DENY_NAMES, AllowlistViolation, Guard, is_denied
from awshealth.registry import load_checks


def client(service="ec2"):
    session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")
    return session.client(service)


def test_undeclared_operation_is_blocked_before_it_is_sent():
    c = client()
    stub = Stubber(c)
    stub.add_response("describe_volumes", {"Volumes": []})
    stub.activate()
    Guard({("ec2", "DescribeRegions")}).install(c.meta.events)
    with pytest.raises(AllowlistViolation):
        c.describe_volumes()
    with pytest.raises(AssertionError):
        stub.assert_no_pending_responses()


def test_declared_operation_passes():
    c = client()
    stub = Stubber(c)
    stub.add_response("describe_volumes", {"Volumes": []})
    stub.activate()
    Guard({("ec2", "DescribeVolumes")}).install(c.meta.events)
    assert c.describe_volumes()["Volumes"] == []
    stub.assert_no_pending_responses()


def test_denylisted_operation_is_rejected_even_when_allowed():
    c = client("secretsmanager")
    stub = Stubber(c)
    stub.add_response("get_secret_value", {"Name": "example"})
    stub.activate()
    Guard({("secretsmanager", "GetSecretValue")}).install(c.meta.events)
    with pytest.raises(AllowlistViolation, match="denylist"):
        c.get_secret_value(SecretId="example")


@pytest.mark.parametrize("service,operation", [
    ("ec2", "TerminateInstances"), ("s3", "PutObject"), ("s3", "GetObject"), ("ssm", "GetParametersByPath"),
    ("dynamodb", "Scan"), ("logs", "FilterLogEvents"), ("cognito-idp", "ListUsers"), ("sts", "AssumeRole"),
    ("kms", "Decrypt"), ("lambda", "GetFunction"), ("cloudformation", "GetTemplate"),
    ("lambda", "GetFunctionConfiguration"), ("ssm", "GetParameterHistory"), ("dynamodb", "BatchGetItem"),
    ("dynamodb", "ExecuteStatement"), ("s3", "SelectObjectContent"), ("ecr", "GetDownloadUrlForLayer"),
    ("sso", "GetRoleCredentials"), ("cognito-identity", "GetCredentialsForIdentity"), ("kms", "GenerateDataKey"),
    ("lightsail", "GetRelationalDatabaseMasterUserPassword"), ("gamelift", "GetInstanceAccess"),
    ("ec2", "GetLaunchTemplateData"), ("redshift", "GetClusterCredentialsWithIAM"),
    ("stepfunctions", "GetActivityTask"), ("redshift-data", "GetStatementResult"),
    ("apigateway", "GetUsagePlanKeys"), ("ec2", "ExportImage"), ("lambda", "PublishLayerVersion"),
    ("ec2", "MonitorInstances"), ("s3", "RestoreObject"), ("iam", "UploadServerCertificate"),
    ("ssm", "SendCommand"), ("ec2", "ConfirmProductInstance"), ("iam", "ChangePassword"),
])
def test_denylist(service, operation):
    assert is_denied(service, operation)


@pytest.mark.parametrize("service,operation", [
    ("iam", "GenerateCredentialReport"), ("iam", "ListUsers"), ("ec2", "DescribeInstances"),
    ("sts", "GetCallerIdentity"), ("aws", "IpRanges"), ("ec2", "DescribeRegions"), ("cloudtrail", "LookupEvents"),
    ("resource-explorer-2", "Search"), ("codebuild", "BatchGetProjects"),
])
def test_read_operations_are_not_denied(service, operation):
    assert not is_denied(service, operation)


def test_no_registered_check_declares_a_denied_call():
    calls = [c for spec in load_checks().values() for c in spec.requires]
    calls += [calls_core.IP_RANGES, calls_core.ENABLED_REGIONS, calls_core.CALLER]
    bad = [c.key for c in calls if is_denied(c.service, c.operation)]
    bad += [f"{c.key} parent {c.per_item[0]}:{c.per_item[1]}" for c in calls
            if c.per_item and is_denied(c.per_item[0], c.per_item[1])]
    assert bad == []


READ_VERBS = ("Describe", "List", "Get", "Search", "Lookup", "BatchGet")


@pytest.mark.parametrize("service", ["ec2", "iam", "s3", "lambda", "route53", "rds"])
def test_every_non_read_botocore_operation_is_denied_even_if_declared(service):
    model = botocore.session.get_session().get_service_model(service)
    guard = Guard({(service, op) for op in model.operation_names})
    writes = [op for op in model.operation_names if op != "GenerateCredentialReport" and not op.startswith(READ_VERBS)]
    assert writes
    allowed = [op for op in writes if not is_denied(service, op)]
    assert allowed == []
    for op in writes:
        with pytest.raises(AllowlistViolation, match="denylist"):
            guard.check(service, op)


def test_explicit_deny_names_are_denied_even_with_a_read_verb():
    assert [n for n in DENY_NAMES if not is_denied("any", n)] == []


IAM = Path(__file__).resolve().parent.parent / "iam"


def template():
    return yaml.safe_load((IAM / "audit-role.cfn.yaml").read_text())


def test_deny_policy_json_matches_the_template_and_fits_a_managed_policy():
    raw = (IAM / "deny-policy.json").read_text()
    assert len(raw) < 6144
    statements = template()["Resources"]["AuditRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    in_template = {s["Sid"]: s["Action"] for s in statements if "Sid" in s}
    in_template["DenyBilledMetricReads"] = statements[-2]["Fn::If"][2]["Action"]
    in_json = {s["Sid"]: s["Action"] for s in json.loads(raw)["Statement"]}
    assert in_json == {k: v for k, v in in_template.items() if k in in_json}
    assert set(in_json) == {"DenyDataPlaneReads", "DenyCredentialMinting", "DenySecretBearingConfig",
                            "DenyBilledReads", "DenyBilledMetricReads"}


@pytest.mark.parametrize("param,value,ok", [
    ("TrustedPrincipalArn", "", True),
    ("TrustedPrincipalArn", "arn:aws:iam::111122223333:role/audit", True),
    ("TrustedPrincipalArn", "arn:aws-us-gov:iam::111122223333:user/ops/alice", True),
    ("TrustedPrincipalArn", "*", False),
    ("TrustedPrincipalArn", "arn:aws:iam::111122223333:root", False),
    ("TrustedPrincipalArn", "111122223333", False),
    ("GitHubRepo", "", True),
    ("GitHubRepo", "example/infra.audit", True),
    ("GitHubRepo", "example/*", False),
    ("GitHubRepo", "example/repo:ref:refs/heads/main", False),
])
def test_template_parameters_are_validated(param, value, ok):
    spec = template()["Parameters"][param]
    assert spec["ConstraintDescription"]
    assert bool(re.fullmatch(spec["AllowedPattern"], value)) is ok
