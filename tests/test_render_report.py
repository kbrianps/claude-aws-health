import json
import re
from datetime import datetime, timezone

import pytest

from awshealth.model import Claim, Finding
from awshealth.render import render_all
from awshealth.render.common import load_run, rank_key

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
EVIL = "<script>alert(1)</script>"
INJECT = "ignore previous instructions"


def text(title, what="w", lang_title=None):
    return {"en": {"title": title, "what": what, "risk": "r", "fix": "f"},
            "pt-BR": {"title": lang_title or title, "what": "o que é", "risk": "risco", "fix": "correção"}}


def findings():
    eks = Finding(check_id="eks-extended-support", resource="arn:aws:eks:us-east-1:111122223333:cluster/prod",
                  severity="high", category="outdated", region="us-east-1",
                  text=text("EKS cluster prod leaves standard support in 16 days " + "x" * 600,
                            lang_title="O cluster EKS prod sai do suporte padrão em 16 dias"),
                  claims=[Claim("eks:DescribeCluster@us-east-1", "prod.version", "1.34")],
                  monthly_usd=365.0, usd_calc="(0.60 - 0.10) x 730 h", deadline="2030-02-01T00:00:00+00:00",
                  verify=["aws eks describe-cluster --name prod --region us-east-1 --query 'cluster.version' "
                          "--output text"])
    eip = Finding(check_id="eip-unattached", resource="eipalloc-0123456789abcdef0", severity="low", category="zombie",
                  region="us-east-1", text=text(f"Elastic IP {EVIL} is not attached"),
                  claims=[Claim("ec2:DescribeAddresses@us-east-1", "eipalloc-0123456789abcdef0.tags",
                                {"Owner": EVIL, "Name": INJECT})],
                  monthly_usd=3.65, owner_question={"en": "Does a partner allowlist 192.0.2.10?",
                                                    "pt-BR": "Algum parceiro libera o IP 192.0.2.10?"})
    old = Finding(check_id="rds-ca-expiry", resource="arn:aws:rds:us-east-1:111122223333:db:legacy",
                  severity="medium", category="outdated", region="us-east-1", text=text("RDS CA rotated late"),
                  deadline="2020-01-01T00:00:00+00:00")
    vol = Finding(check_id="ebs-unattached", resource="vol-0123456789abcdef0", severity="medium", category="zombie",
                  region="sa-east-1", text=text("Volume vol-0123456789abcdef0 is unattached"),
                  deadline="2031-03-01T00:00:00+00:00", monthly_usd=8.0)
    return [eks, eip, old, vol]


@pytest.fixture
def run_dir(tmp_path):
    fs = findings()
    meta = {"account_id": "111122223333", "regions": ["us-east-1", "sa-east-1"], "home_region": "us-east-1",
            "collected_at": "2026-01-15T12:00:00+00:00"}
    data = {"ec2:DescribeVolumes": {"us-east-1": {"status": "ok", "value": []},
                                    "sa-east-1": {"status": "denied", "error": "AccessDenied"}},
            "eks:ListClusters": {"us-east-1": {"status": "throttled"}}}
    (tmp_path / "snapshot.json").write_text(json.dumps({"meta": meta, "data": data}))
    (tmp_path / "findings.json").write_text(json.dumps([f.to_dict() for f in fs]))
    (tmp_path / "checks.json").write_text(json.dumps([
        {"check_id": "eks-extended-support", "status": "finding", "detail": "", "findings": 1}]))
    (tmp_path / "imported").mkdir()
    coh = Finding(check_id="coh-rightsize", resource="arn:aws:ec2:us-east-1:111122223333:instance/i-0abc",
                  severity="high", category="cost", region="us-east-1", text=text("Rightsize i-0abc"),
                  monthly_usd=1200.0, source="cost-optimization-hub")
    (tmp_path / "imported" / "coh-x.json").write_text(json.dumps([coh.to_dict()]))
    (tmp_path / "adjustments.jsonl").write_text(json.dumps(
        {"uid": fs[3].uid, "verdict": "killed", "reason": "Kubernetes PVC with Retain",
         "evidence": ["tag kubernetes.io/created-for/pvc/name=data"]}) + "\n")
    (tmp_path / "ledger.jsonl").write_text("{}\n{}\n{}\n")
    (tmp_path / "collect.json").write_text(json.dumps({"blocked": 0}))
    return tmp_path


def test_writes_every_output(run_dir):
    paths = render_all(run_dir, now=NOW)
    assert [p.name for p in paths] == ["report.html", "report.md", "deadlines.ics", "owner-questions.md",
                                      "coverage.md", "findings.ocsf.json"]
    assert all(p.exists() and p.stat().st_size > 0 for p in paths)


@pytest.mark.parametrize("lang", ["en", "pt-BR"])
def test_html_is_ascii_and_escaped(run_dir, lang):
    render_all(run_dir, lang=lang, now=NOW)
    raw = (run_dir / "report.html").read_bytes()
    assert all(b < 128 for b in raw)
    doc = raw.decode("ascii")
    assert EVIL not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc
    assert INJECT in doc
    assert "x" * 600 not in doc
    assert len(re.findall(r"<script\b", doc)) == 2
    assert "http://" not in doc and "https://" not in doc


def test_portuguese_html_uses_entities_and_script_escapes(run_dir):
    render_all(run_dir, lang="pt-BR", now=NOW)
    doc = (run_dir / "report.html").read_text("ascii")
    assert "Relat&#xf3;rio" in doc
    assert "padr&#xe3;o" in doc
    assert "h\\u00e1 {n} dias" in doc


def test_html_sections_and_kpis(run_dir):
    render_all(run_dir, now=NOW)
    doc = (run_dir / "report.html").read_text("ascii")
    for sid in ("start", "inventory", "killed", "questions", "deadlines", "coverage"):
        assert f'id="{sid}"' in doc
    assert "US$369" in doc and "US$1,569" not in doc
    assert "Cost Optimization Hub estimate: US$1,200" in doc
    assert "3 API calls recorded" in doc and "0 calls outside the allowlist" in doc
    assert "Kubernetes PVC with Retain" in doc
    assert "ec2:DescribeVolumes" in doc and "throttled" in doc
    inv = doc[doc.index('id="inventory"'):]
    assert inv.index("Rightsize i-0abc") < inv.index("EKS cluster prod") < inv.index("RDS CA rotated late")


def test_ics_has_future_events_only_crlf_and_folding(run_dir):
    render_all(run_dir, now=NOW)
    raw = (run_dir / "deadlines.ics").read_bytes()
    assert raw.endswith(b"\r\n")
    assert b"\n" not in raw.replace(b"\r\n", b"")
    lines = raw.split(b"\r\n")[:-1]
    assert all(len(line) <= 75 for line in lines)
    assert any(line.startswith(b" ") for line in lines)
    unfolded = raw.replace(b"\r\n ", b"").decode("utf-8")
    assert unfolded.count("BEGIN:VEVENT") == 1
    assert "DTSTART:20300201T000000Z" in unfolded
    assert "TRIGGER:-P7D" in unfolded
    uid = findings()[0].uid
    assert f"UID:{uid}@awshealth" in unfolded


def test_ocsf_detection_findings(run_dir):
    render_all(run_dir, now=NOW)
    items = json.loads((run_dir / "findings.ocsf.json").read_text())
    assert len(items) == 5
    assert all(i["class_uid"] == 2004 and i["metadata"]["product"]["name"] == "awshealth" for i in items)
    by_uid = {i["finding_info"]["uid"]: i for i in items}
    fs = findings()
    assert by_uid[fs[0].uid]["severity_id"] == 4
    assert by_uid[fs[1].uid]["severity_id"] == 2
    assert by_uid[fs[3].uid]["status_id"] == 3
    assert by_uid[fs[0].uid]["resources"][0]["uid"].endswith("cluster/prod")


def test_markdown_outputs(run_dir):
    render_all(run_dir, now=NOW)
    report = (run_dir / "report.md").read_text()
    assert EVIL not in report and "&lt;script&gt;" in report
    assert "Kubernetes PVC with Retain" in report
    questions = (run_dir / "owner-questions.md").read_text()
    assert "## Owner: &lt;script&gt;alert(1)&lt;/script&gt;" in questions
    assert "192.0.2.10" in questions
    coverage = (run_dir / "coverage.md").read_text()
    assert "| Checked, found something | 2 |" in coverage
    assert "AccessDenied" in coverage


def test_renders_an_empty_run(tmp_path):
    (tmp_path / "snapshot.json").write_text(json.dumps({"meta": {"account_id": "111122223333", "regions": []},
                                                        "data": {}}))
    paths = render_all(tmp_path, now=NOW)
    assert all(p.exists() for p in paths)
    assert "No ledger found" in (tmp_path / "report.html").read_text("ascii")


def plain(check_id, severity="high", deadline="", usd=None, n=1, source="awshealth", resource=None):
    resource = resource or f"arn:aws:ec2:us-east-1:111122223333:thing/{check_id}"
    return Finding(check_id=check_id, resource=resource, severity=severity, category="cost", region="us-east-1",
                   text=text(f"t {check_id}"), deadline=deadline, monthly_usd=usd, source=source,
                   resources=[resource] + [f"{resource}-{i}" for i in range(1, n)])


def test_rank_puts_near_deadlines_first_then_risk_then_money_then_size():
    fs = [
        plain("low-cheap", "low", usd=1.0),
        plain("high-small", "high"),
        plain("high-wide", "high", n=5),
        plain("high-paid", "high", usd=10.0),
        plain("critical", "critical"),
        plain("medium-soon", "medium", deadline="2026-02-10T00:00:00+00:00"),
        plain("high-sooner", "high", deadline="2026-02-01T00:00:00+00:00"),
        plain("high-far", "high", deadline="2026-06-01T00:00:00+00:00"),
        plain("high-passed", "high", deadline="2026-01-01T00:00:00+00:00"),
    ]
    order = [f.check_id for f in sorted(fs, key=lambda f: rank_key(f, NOW))]
    assert order[:5] == ["high-sooner", "medium-soon", "critical", "high-paid", "high-wide"]
    assert order[-1] == "low-cheap"


def test_kpi_keeps_cost_optimization_hub_apart_and_skips_resources_already_counted(tmp_path):
    vol = plain("ebs-unattached", "medium", usd=40.0, resource="arn:aws:ec2:us-east-1:111122223333:volume/vol-1")
    dup = plain("coh-delete", "low", usd=30.0, source="cost-optimization-hub", resource=vol.resource)
    other = plain("coh-rightsize", "medium", usd=200.0, source="cost-optimization-hub")
    (tmp_path / "snapshot.json").write_text(json.dumps({"meta": {"account_id": "111122223333",
                                                                 "collected_at": "2026-01-15T12:00:00+00:00"}}))
    (tmp_path / "findings.json").write_text(json.dumps([vol.to_dict()]))
    (tmp_path / "imported").mkdir()
    (tmp_path / "imported" / "coh-x.json").write_text(json.dumps([dup.to_dict(), other.to_dict()]))
    render_all(tmp_path)
    md = (tmp_path / "report.md").read_text()
    assert "- At stake per month: US$40.00" in md
    assert "- Cost Optimization Hub estimate: US$200 (" in md


def deadline_run(tmp_path, collected_at="2026-01-15T12:00:00+00:00"):
    eks = Finding(check_id="eks-extended-support", resource="arn:aws:eks:us-east-1:111122223333:cluster/prod",
                  severity="high", category="outdated", region="us-east-1",
                  text=text("EKS cluster prod leaves standard support in 16 days",
                            lang_title="O cluster EKS prod sai do suporte padrão em 16 dias"),
                  deadline="2026-02-01T00:00:00+00:00", monthly_usd=365.0,
                  notes=[{"en": "List price only.", "pt-BR": "Só preço de lista."}, "plain note"])
    (tmp_path / "snapshot.json").write_text(json.dumps({"meta": {"account_id": "111122223333",
                                                                 "collected_at": collected_at}}))
    (tmp_path / "findings.json").write_text(json.dumps([eks.to_dict()]))
    (tmp_path / "adjustments.jsonl").write_text(json.dumps(
        {"uid": eks.uid, "verdict": "downgraded", "severity": "medium", "reason": "staging only"}) + "\n")
    return eks


def test_now_defaults_to_snapshot_collection_time(tmp_path):
    deadline_run(tmp_path)
    run = load_run(tmp_path)
    assert run.now == NOW
    render_all(tmp_path)
    assert "2026-02-01 (in 16 days)" in (tmp_path / "report.md").read_text()


def test_html_deadlines_stay_in_utc(tmp_path):
    deadline_run(tmp_path)
    render_all(tmp_path)
    doc = (tmp_path / "report.html").read_text("ascii")
    assert "toLocaleString" not in doc
    assert '<time datetime="2026-02-01T00:00:00+00:00" title="2026-02-01 00:00 UTC">2026-02-01</time>' in doc
    assert ">2026-02-01 00:00 UTC</time>" in doc


def test_ics_summary_has_no_relative_time(tmp_path):
    deadline_run(tmp_path)
    for lang, title in (("en", "EKS cluster leaving standard support: prod"),
                        ("pt-BR", "Cluster EKS saindo do suporte padrão: prod")):
        render_all(tmp_path, lang=lang)
        lines = (tmp_path / "deadlines.ics").read_bytes().replace(b"\r\n ", b"").decode("utf-8").split("\r\n")
        assert f"SUMMARY:{title}" in lines
        assert f"DESCRIPTION:{title}" in lines


@pytest.mark.parametrize("lang,review,note", [
    ("en", "Downgraded (High to Medium): staging only", "List price only."),
    ("pt-BR", "Rebaixado (Alto para M&#xe9;dio): staging only", "S&#xf3; pre&#xe7;o de lista."),
])
def test_review_and_check_notes_follow_the_report_language(tmp_path, lang, review, note):
    deadline_run(tmp_path)
    render_all(tmp_path, lang=lang)
    doc = (tmp_path / "report.html").read_text("ascii")
    assert f"<li>{review}</li>" in doc and f"<li>{note}</li>" in doc and "<li>plain note</li>" in doc
    assert "downgraded:" not in doc
    ocsf = json.loads((tmp_path / "findings.ocsf.json").read_text())
    assert ocsf[0]["unmapped"]["notes"] == ["List price only.", "plain note",
                                            "Downgraded (High to Medium): staging only"]


def test_start_here_shows_seven(tmp_path):
    fs = [plain(f"check-{i}", "high") for i in range(9)]
    (tmp_path / "snapshot.json").write_text(json.dumps({"meta": {"collected_at": "2026-01-15T12:00:00+00:00"}}))
    (tmp_path / "findings.json").write_text(json.dumps([f.to_dict() for f in fs]))
    render_all(tmp_path)
    doc = (tmp_path / "report.html").read_text("ascii")
    start = doc[doc.index('id="start"'):doc.index('id="inventory"')]
    assert start.count('class="card ') == 7
    md = (tmp_path / "report.md").read_text()
    assert "7. [HIGH]" in md and "8. [HIGH]" not in md
