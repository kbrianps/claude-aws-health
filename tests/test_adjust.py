import json

import pytest

from awshealth.adjust import apply
from awshealth.model import Finding


def finding(resource, severity="high"):
    return Finding(check_id="demo-check", resource=resource, severity=severity, category="zombie", region="us-east-1",
                   text={"en": {"title": f"t {resource}", "what": "", "risk": "", "fix": ""},
                         "pt-BR": {"title": f"t {resource}", "what": "", "risk": "", "fix": ""}})


def write(tmp_path, *lines):
    p = tmp_path / "adjustments.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    return p


def test_downgrade_kill_and_question(tmp_path):
    a, b, c, d = finding("a"), finding("b"), finding("c"), finding("d")
    path = write(tmp_path,
                 {"uid": a.uid, "verdict": "downgraded", "severity": "low", "reason": "dev account", "evidence": "tag"},
                 {"uid": b.uid, "verdict": "killed", "reason": "Retain PVC", "evidence": ["kubernetes.io/pvc tag"]},
                 {"uid": c.uid, "verdict": "question", "reason": "intent unclear", "evidence": "",
                  "question": {"en": "Is this a DR replica?", "pt-BR": "Isto é uma réplica de DR?"}},
                 {"uid": d.uid, "verdict": "confirmed", "reason": "checked", "evidence": "describe output"})
    kept, killed, questions = apply([a, b, c, d], path)
    assert [f.uid for f in kept] == [a.uid, c.uid, d.uid]
    assert a.severity == "low" and "high -> low" in a.notes[0]
    assert killed[0].finding.uid == b.uid and killed[0].evidence == ["kubernetes.io/pvc tag"]
    assert [f.uid for f in questions] == [c.uid]
    assert c.owner_question["pt-BR"].startswith("Isto")
    assert d.status == "confirmed"


def test_missing_file_keeps_everything(tmp_path):
    a = finding("a")
    kept, killed, questions = apply([a], tmp_path / "adjustments.jsonl")
    assert kept == [a] and killed == [] and questions == []


def test_rejects_severity_upgrade(tmp_path):
    a = finding("a", severity="medium")
    path = write(tmp_path,
                 {"uid": a.uid, "verdict": "confirmed", "severity": "critical", "reason": "x", "evidence": "y"})
    with pytest.raises(ValueError, match="only lower severity"):
        apply([a], path)
    assert a.severity == "medium"


def test_rejects_kill_without_evidence(tmp_path):
    a = finding("a")
    path = write(tmp_path, {"uid": a.uid, "verdict": "killed", "reason": "looks fine", "evidence": ""})
    with pytest.raises(ValueError, match="needs evidence"):
        apply([a], path)


def test_rejects_unknown_uid(tmp_path):
    path = write(tmp_path, {"uid": "nope:000000000000", "verdict": "confirmed", "reason": "x", "evidence": "y"})
    with pytest.raises(ValueError, match="unknown uid"):
        apply([finding("a")], path)


def test_rejects_upgrade_after_earlier_downgrade(tmp_path):
    a = finding("a")
    path = write(tmp_path,
                 {"uid": a.uid, "verdict": "downgraded", "severity": "low", "reason": "x", "evidence": "y"},
                 {"uid": a.uid, "verdict": "downgraded", "severity": "medium", "reason": "x", "evidence": "y"})
    with pytest.raises(ValueError, match="line 2"):
        apply([a], path)
