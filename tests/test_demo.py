import json

import pytest

from awshealth.demo import run_demo
from awshealth.render.common import load_run

INJECTION = "<script>alert(1)</script>"


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    out = tmp_path_factory.mktemp("demo")
    run_demo(out)
    return out


def findings(out):
    return json.loads((out / "findings.json").read_text())


def by_check(out, check_id):
    return [f for f in findings(out) if f["check_id"] == check_id]


def test_demo_has_many_findings(demo):
    assert len(findings(demo)) >= 25


def test_every_check_ran(demo):
    statuses = {c["check_id"]: c["status"] for c in json.loads((demo / "checks.json").read_text())}
    assert not [cid for cid, s in statuses.items() if s not in ("ok", "finding")]


def test_eks_clusters_hit_the_standard_support_cliff(demo):
    eks = by_check(demo, "eks-extended-support")
    assert sorted(f["resource"].split("/")[-1] for f in eks) == ["prod", "staging"]
    assert sum(f["monthly_usd"] for f in eks) == pytest.approx(730)
    assert all(f["deadline"].startswith("2026-02-01") for f in eks)


def test_backup_near_miss_names_the_misspelled_tag(demo):
    [f] = by_check(demo, "backup-plan-selects-nothing")
    assert "Bakcup=daily" in f["text"]["en"]["what"]
    assert "rds-daily-vault" in f["text"]["en"]["what"]
    assert f["severity"] == "high"


def test_dangling_dns_records(demo):
    [ip] = by_check(demo, "route53-dangling-ip")
    assert ip["resource"].endswith("old.example.com/A/203.0.113.10")
    [alias] = by_check(demo, "route53-alias-missing-target")
    assert "legacy-api.example.com" in alias["resource"]


def test_public_bucket_guarded_only_by_referer(demo):
    [f] = by_check(demo, "s3-public-policy")
    assert f["resource"] == "arn:aws:s3:::acme-frames-example"
    assert "aws:referer" in f["text"]["en"]["what"]


def test_alarm_topic_without_subscribers(demo):
    [f] = by_check(demo, "sns-alarm-topic-no-subscribers")
    assert f["resource"].endswith(":prod-alerts")
    assert len(f["resources"]) == 5


def test_injection_tag_renders_as_text(demo):
    html = (demo / "report.html").read_text()
    assert INJECTION not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_adjustments_are_applied(demo):
    run = load_run(demo)
    assert [k.finding.check_id for k in run.killed] == ["ec2-stopped-long"]
    statuses = {f.check_id: f.status for f in run.findings if f.status != "open"}
    assert statuses == {"backup-plan-selects-nothing": "confirmed", "logs-no-retention": "question"}
    webhook = next(f for f in run.findings if f.check_id == "lambda-url-public-no-auth")
    assert webhook.severity == "medium"


def test_coverage_shows_denied_and_throttled_calls(demo):
    run = load_run(demo)
    problems = {(p["call"], p["region"], p["status"]) for p in run.api_problems}
    assert ("securityhub:DescribeHub", "sa-east-1", "denied") in problems
    assert ("secretsmanager:ListSecrets", "sa-east-1", "throttled") in problems
    assert run.calls and run.blocked == 0


def test_demo_renders_in_portuguese(tmp_path):
    paths = run_demo(tmp_path, lang="pt-BR")
    assert (tmp_path / "report.html") in paths
    assert "Relatório de saúde da AWS" in (tmp_path / "report.md").read_text()
