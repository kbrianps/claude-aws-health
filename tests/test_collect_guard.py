import boto3
import pytest
from botocore.stub import Stubber

from awshealth import calls_core
from awshealth.collect.guard import AllowlistViolation, Guard, is_denied
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
])
def test_denylist(service, operation):
    assert is_denied(service, operation)


@pytest.mark.parametrize("service,operation", [
    ("iam", "GenerateCredentialReport"), ("iam", "ListUsers"), ("ec2", "DescribeInstances"),
    ("lambda", "GetFunctionConfiguration"), ("sts", "GetCallerIdentity"),
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
