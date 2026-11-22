import json

from awshealth.catalog import catalog_coverage, load_catalog, print_catalog


def test_catalog_has_282_entries():
    assert len(load_catalog()) == 282


def test_coverage_without_checks_json_marks_covered_as_not_collected(tmp_path):
    cov = catalog_coverage(tmp_path)
    assert cov["total"] == 282
    assert sum(cov["counts"].values()) == 282
    entry = next(e for e in cov["entries"] if e["id"] == "eks-cluster-extended-support-billing")
    assert entry["checks"] == ["eks-extended-support"]
    assert entry["status"] == "not_collected"
    assert cov["counts"]["agent"] == 282 - cov["deterministic"]


def test_coverage_uses_check_status(tmp_path):
    (tmp_path / "checks.json").write_text(json.dumps([{"check_id": "eks-extended-support", "status": "finding"}]))
    cov = catalog_coverage(tmp_path)
    entry = next(e for e in cov["entries"] if e["id"] == "eks-cluster-extended-support-billing")
    assert entry["status"] == "finding"
    assert cov["checked"] >= 1


def test_print_catalog_table_and_json(capsys):
    print_catalog(category="quota")
    out = capsys.readouterr().out
    assert "covered by" in out and "3 entries" in out
    print_catalog(category="quota", fmt="json")
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 3 and all("covered_by" in r for r in rows)
