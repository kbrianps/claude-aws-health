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


def adjustments(out):
    return [json.loads(line) for line in (out / "adjustments.jsonl").read_text().splitlines() if line.strip()]


def test_adjustments_follow_the_skeptic_protocol(demo):
    adj = adjustments(demo)
    assert sorted(a["verdict"] for a in adj) == ["confirmed", "downgraded", "killed", "question"]
    assert all(e.startswith("snapshot:") for a in adj for e in a.get("evidence", []))
    [question] = [a for a in adj if a["verdict"] == "question"]
    assert question["question"]["en"] and question["question"]["pt-BR"]
    run = load_run(demo)
    assert [k.finding.check_id for k in run.killed] == ["sg-open-admin-ports"]
    statuses = {f.check_id: f.status for f in run.findings if f.status != "open"}
    assert statuses == {"backup-plan-selects-nothing": "confirmed", "ec2-stopped-long": "question"}
    regions = next(f for f in run.findings if f.check_id == "unused-regions-open")
    assert regions.severity == "medium"


def test_the_kill_is_proven_by_the_snapshot_itself(demo):
    [kill] = [a for a in adjustments(demo) if a["verdict"] == "killed"]
    [sg] = [f for f in findings(demo) if f["uid"] == kill["uid"]]
    group = sg["resource"].split("/")[-1]
    data = json.loads((demo / "snapshot.json").read_text())["data"]
    enis = [e for e in data["ec2:DescribeNetworkInterfaces"]["us-east-1"]["value"] if group in (e["groups"] or [])]
    assert enis and all(e["type"] == "lambda" and e["requester_managed"] and not e["public_ip"] for e in enis)
    assert all(e["id"] in " ".join(kill["evidence"]) for e in enis)


def test_start_here_shows_the_showcase_first(demo):
    top = [f.check_id for f in load_run(demo).findings[:7]]
    assert top[:2] == ["eks-extended-support", "eks-extended-support"]
    assert {"sns-alarm-topic-no-subscribers", "backup-plan-selects-nothing"} <= set(top)


def test_deadlines_render_in_utc(demo):
    html = (demo / "report.html").read_text()
    assert ">2026-02-01</time>" in html and "Jan 31" not in html


def test_portuguese_report_has_no_english_review_text(tmp_path):
    run_demo(tmp_path, lang="pt-BR")
    md = (tmp_path / "report.md").read_text()
    assert "Rebaixado (Alto para Médio)" in md and "Confirmado:" in md
    assert "downgraded:" not in md and "confirmed:" not in md and "question:" not in md
    assert "Free Tier do EC2" in md and "The EC2 Free Tier" not in md


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
