from awshealth.calls_compute import LOG_GROUPS
from awshealth.testing import run_one, snap_with

GIB = 1024 ** 3


def group(name, gib, retention=None):
    return {"name": name, "arn": f"arn:aws:logs:us-east-1:111122223333:log-group:{name}", "retention": retention,
            "bytes": int(gib * GIB)}


def snap(*groups):
    return snap_with({LOG_GROUPS: {"us-east-1": list(groups)}})


def test_aggregates_large_groups_without_retention():
    [f] = run_one("logs-no-retention", snap(group("/aws/lambda/a", 5), group("/aws/eks/b/cluster", 3)))
    assert f.monthly_usd == 0.24
    assert "2 log groups" in f.t("title")
    assert f.t("what").index("/aws/lambda/a") < f.t("what").index("/aws/eks/b/cluster")
    assert any("describe-subscription-filters" in c and "/aws/lambda/a" in c for c in f.verify)


def test_top_ten_only_in_text_but_all_in_resources():
    groups = [group(f"/app/g{i:02d}", 2 + i) for i in range(12)]
    [f] = run_one("logs-no-retention", snap(*groups))
    assert len(f.resources) == 12
    assert "/app/g00" not in f.t("what")
    assert "/app/g11" in f.t("what")


def test_retention_set_or_small_groups_are_quiet():
    assert run_one("logs-no-retention", snap(group("/big", 50, retention=30), group("/small", 0.5))) == []
