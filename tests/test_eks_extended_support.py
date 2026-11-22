from awshealth.checks.eks_extended_support import CLUSTER_VERSIONS, DESCRIBE_CLUSTER, LIST_CLUSTERS
from awshealth.testing import run_one, snap_with

ARN = "arn:aws:eks:us-east-1:111122223333:cluster/prod"


def snap(policy="EXTENDED", end="2026-02-01T00:00:00Z", status="ok"):
    return snap_with({
        LIST_CLUSTERS: {"us-east-1": ["prod"]},
        DESCRIBE_CLUSTER: {"us-east-1": {"__by_id__": {"prod": {
            "name": "prod", "arn": ARN, "version": "1.34", "status": "ACTIVE",
            "upgradePolicy": {"supportType": policy}, "tags": {}}}}},
        CLUSTER_VERSIONS: {"us-east-1": [{"version": "1.34", "status": "STANDARD_SUPPORT",
                                          "endOfStandardSupportDate": end,
                                          "endOfExtendedSupportDate": "2027-02-01T00:00:00Z"}]},
    })


def test_flags_extended_policy_near_deadline_with_dollars():
    [f] = run_one("eks-extended-support", snap())
    assert f.severity == "high"
    assert f.monthly_usd == 365.0
    assert f.resource == ARN
    assert "16 days" in f.t("title")
    assert f.verify and all("--region us-east-1" in c for c in f.verify)


def test_standard_policy_has_no_dollar_cost():
    [f] = run_one("eks-extended-support", snap(policy="STANDARD"))
    assert f.monthly_usd is None
    assert "STANDARD" in f.t("risk")


def test_far_deadline_is_quiet():
    assert run_one("eks-extended-support", snap(end="2027-01-01T00:00:00Z")) == []


def test_portuguese_text_exists():
    [f] = run_one("eks-extended-support", snap())
    assert "suporte" in f.t("title", "pt-BR")
