from awshealth.calls_security import FUNCTION_URLS, FUNCTIONS
from awshealth.testing import run_one, snap_with

ARN = "arn:aws:lambda:us-east-1:111122223333:function:hook"


def snap(auth="NONE", origins=None):
    return snap_with({
        FUNCTIONS: {"us-east-1": [{"name": "hook", "arn": ARN}]},
        FUNCTION_URLS: {"us-east-1": {"__by_id__": {"hook": [{"url": "https://abc.lambda-url.us-east-1.on.aws/",
                                                               "auth": auth, "origins": origins}]}}},
    })


def test_public_url_is_medium_with_owner_question():
    [f] = run_one("lambda-url-public-no-auth", snap())
    assert f.severity == "medium"
    assert f.resource == ARN
    assert f.owner_question


def test_cors_star_is_high():
    [f] = run_one("lambda-url-public-no-auth", snap(origins=["*"]))
    assert f.severity == "high"
    assert "CORS" in f.t("what")


def test_iam_auth_and_no_url_are_quiet():
    assert run_one("lambda-url-public-no-auth", snap(auth="AWS_IAM")) == []
    empty = snap_with({FUNCTIONS: {"us-east-1": [{"name": "hook", "arn": ARN}]},
                       FUNCTION_URLS: {"us-east-1": {"__by_id__": {"hook": []}}}})
    assert run_one("lambda-url-public-no-auth", empty) == []
