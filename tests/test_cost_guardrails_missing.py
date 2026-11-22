from awshealth.calls_security import ANOMALY_MONITORS, BUDGET_HISTORY, BUDGETS
from awshealth.testing import run_one, snap_with

MONTHLY = {"name": "monthly", "type": "COST", "unit": "MONTHLY", "limit": "1000.0"}


def history(*rows):
    return [{"start": s, "budgeted": "1000.0", "actual": a} for s, a in rows]


def test_no_budgets_and_no_monitor():
    snap = snap_with({BUDGETS: {"us-east-1": []}, ANOMALY_MONITORS: {"us-east-1": []}})
    [f] = run_one("cost-guardrails-missing", snap)
    assert f.severity == "medium"
    assert "no AWS Budgets" in f.t("what")
    assert "Anomaly" in f.t("what")


def test_budgets_over_limit_for_a_month_are_stale():
    hist = history(("2025-11-01T00:00:00Z", "900"), ("2025-12-01T00:00:00Z", "1500"), ("2026-01-01T00:00:00Z", "1200"))
    snap = snap_with({BUDGETS: {"us-east-1": [MONTHLY]},
                      BUDGET_HISTORY: {"us-east-1": {"__by_id__": {"monthly": hist}}}})
    [f] = run_one("cost-guardrails-missing", snap)
    assert "monthly (45 days)" in f.t("what")


def test_anomaly_data_missing_is_optional_and_healthy_budget_is_quiet():
    hist = history(("2025-12-01T00:00:00Z", "900"), ("2026-01-01T00:00:00Z", "1200"))
    snap = snap_with({BUDGETS: {"us-east-1": [MONTHLY]},
                      BUDGET_HISTORY: {"us-east-1": {"__by_id__": {"monthly": hist}}}})
    assert run_one("cost-guardrails-missing", snap) == []


def test_denied_budgets_are_not_reported_as_missing():
    snap = snap_with({BUDGETS: {"us-east-1": {"__status__": "denied"}},
                      ANOMALY_MONITORS: {"us-east-1": [{"name": "services", "type": "DIMENSIONAL"}]}})
    assert run_one("cost-guardrails-missing", snap) == []
