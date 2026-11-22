import json
from pathlib import Path

import pytest

from awshealth.importers import load_any
from awshealth.model import Finding

FIXTURES = Path(__file__).parent / "fixtures"


def test_prowler_keeps_only_failures_and_maps_fields():
    found = load_any(FIXTURES / "prowler-ocsf.json", "prowler")
    assert [f.check_id for f in found] == ["prowler-s3_bucket_public_access", "prowler-backup_plans_exist"]
    s3, backup = found
    assert s3.severity == "critical"
    assert s3.category == "security"
    assert s3.source == "prowler"
    assert s3.resource == "arn:aws:s3:::example-logs"
    assert s3.region == "us-east-1"
    assert s3.t("title") == "Ensure there are no S3 buckets open to Everyone or Any AWS user."
    assert s3.t("risk").startswith("Anyone on the internet")
    assert s3.t("fix") == "Block public access at the bucket and account level."
    assert s3.t("what", "pt-BR").startswith("Importado do Prowler.")
    assert backup.severity == "low"
    assert backup.category == "resilience"


def test_coh_maps_savings_to_severity_and_dollars():
    found = load_any(FIXTURES / "coh-recommendations.json", "coh")
    assert [f.severity for f in found] == ["high", "medium", "low"]
    big = found[0]
    assert big.category == "cost"
    assert big.monthly_usd == 1250.5
    assert big.check_id == "coh-rightsize"
    assert big.resource.endswith("instance/i-0123456789abcdef0")
    assert "Precisa reiniciar" in big.t("what", "pt-BR")
    assert big.verify and "--region us-east-1" in big.verify[0]
    assert found[1].check_id == "coh-delete"


def test_coh_unsafe_recommendation_id_gets_no_verify_command():
    found = load_any(FIXTURES / "coh-recommendations.json", "coh")
    assert found[2].verify == []


def test_auto_detect_and_round_trip():
    prowler = load_any(FIXTURES / "prowler-ocsf.json", None)
    coh = load_any(FIXTURES / "coh-recommendations.json", None)
    assert {f.source for f in prowler} == {"prowler"}
    assert {f.source for f in coh} == {"cost-optimization-hub"}
    for f in prowler + coh:
        assert Finding.from_dict(json.loads(json.dumps(f.to_dict()))).uid == f.uid


def test_unknown_file_is_rejected(tmp_path):
    p = tmp_path / "other.json"
    p.write_text(json.dumps([{"foo": 1}]))
    with pytest.raises(ValueError, match="cannot detect"):
        load_any(p, None)


def test_coh_accepts_a_bare_list(tmp_path):
    p = tmp_path / "coh.json"
    p.write_text(json.dumps([{"recommendationId": "abc", "actionType": "Stop", "estimatedMonthlySavings": 99.9}]))
    [f] = load_any(p, None)
    assert f.severity == "low"
    assert f.region == "global"
