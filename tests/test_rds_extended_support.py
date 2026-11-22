from awshealth.calls_compute import RDS_CLUSTERS, RDS_INSTANCES, RDS_MAJOR_VERSIONS
from awshealth.checks.rds_extended_support import major_of, vcpus
from awshealth.testing import run_one, snap_with


def lifecycles(std_end, ext_end):
    return [{"name": "open-source-rds-standard-support", "start": "2019-01-01T00:00:00Z", "end": std_end},
            {"name": "open-source-rds-extended-support", "start": std_end, "end": ext_end}]


MAJORS = [
    {"engine": "postgres", "major": "11", "lifecycles": lifecycles("2024-02-29T00:00:00Z", "2027-03-31T00:00:00Z")},
    {"engine": "postgres", "major": "16", "lifecycles": lifecycles("2029-02-28T00:00:00Z", "2032-02-29T00:00:00Z")},
    {"engine": "aurora-postgresql", "major": "13",
     "lifecycles": lifecycles("2026-02-28T00:00:00Z", "2029-02-28T00:00:00Z")},
]


def inst(iid, version="11.22", cls="db.m5.large", lifecycle="open-source-rds-extended-support", cluster=None,
         engine="postgres"):
    return {"id": iid, "arn": f"arn:aws:rds:us-east-1:111122223333:db:{iid}", "engine": engine, "version": version,
            "cls": cls, "cluster": cluster, "lifecycle": lifecycle, "tags": []}


def snap(instances, clusters=None):
    return snap_with({
        RDS_INSTANCES: {"us-east-1": instances},
        RDS_CLUSTERS: {"us-east-1": clusters or []},
        RDS_MAJOR_VERSIONS: {"us-east-1": MAJORS},
    })


def test_instance_in_extended_support_is_billed():
    [f] = run_one("rds-extended-support", snap([inst("orders")]))
    assert f.severity == "high"
    assert f.category == "cost"
    assert f.monthly_usd == 146.0
    assert "2 vCPU" in f.usd_calc
    assert f.deadline.startswith("2027-03-31")
    assert any("describe-db-major-engine-versions --engine postgres --major-engine-version 11" in c for c in f.verify)


def test_disabled_enrollment_has_no_dollars_and_unknown_class_has_a_note():
    [f] = run_one("rds-extended-support", snap([inst("a", lifecycle="open-source-rds-extended-support-disabled")]))
    assert f.monthly_usd is None
    assert "disabled" in f.t("risk")
    [g] = run_one("rds-extended-support", snap([inst("b", cls="db.x2g.large")]))
    assert g.monthly_usd is None
    assert any("vCPU count unknown" in n for n in g.notes)


def test_aurora_cluster_near_standard_end_sums_member_vcpus():
    members = [inst(m, version="13.12", cls="db.r6g.xlarge", cluster="ledger", engine="aurora-postgresql")
               for m in ("ledger-1", "ledger-2")]
    cluster = {"id": "ledger", "arn": "arn:aws:rds:us-east-1:111122223333:cluster:ledger",
               "engine": "aurora-postgresql", "version": "13.12", "mode": "provisioned",
               "lifecycle": "open-source-rds-extended-support", "members": ["ledger-1", "ledger-2"], "tags": []}
    [f] = run_one("rds-extended-support", snap(members, [cluster]))
    assert f.resource.endswith("cluster:ledger")
    assert f.severity == "medium"
    assert f.monthly_usd == 584.0
    assert "43 days" in f.t("title")


def test_current_version_is_quiet():
    assert run_one("rds-extended-support", snap([inst("fresh", version="16.4")])) == []


def test_helpers():
    assert vcpus("db.t3.micro") == 2
    assert vcpus("db.m5.micro") is None
    assert vcpus("db.r6i.24xlarge") == 96
    majors = {("aurora-mysql", "8.0"): [], ("aurora-mysql", "5.7"): [], ("postgres", "9.6"): []}
    assert major_of("aurora-mysql", "8.0.mysql_aurora.3.05.2", majors) == "8.0"
    assert major_of("postgres", "9.6.24", majors) == "9.6"
    assert major_of("postgres", "96.1", majors) is None
