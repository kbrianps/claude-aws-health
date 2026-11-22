import io
import json
import os
import stat
import urllib.error
import urllib.request
from collections import defaultdict

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber

from awshealth import calls_core
from awshealth.collect import engine
from awshealth.collect.engine import classify, collect, merge_pages
from awshealth.collect.guard import AllowlistViolation
from awshealth.registry import CheckSpec, call
from awshealth.snapshot import Snapshot

ACCOUNT = "111122223333"
REAL_OPEN_URL = engine.open_url
ARN = "arn:aws:iam::111122223333:user/audit"


class Fake:
    def __init__(self):
        self.plan = defaultdict(list)
        self.stubbers = {}
        self.ok("sts", "us-east-1", "get_caller_identity", {"Account": ACCOUNT, "Arn": ARN, "UserId": "AIDAEXAMPLE"})

    def ok(self, service, region, method, response, params=None):
        self.plan[(service, region)].append(("ok", method, response, params))

    def err(self, service, region, method, code, params=None):
        self.plan[(service, region)].append(("err", method, code, params))

    def factory(self, session, service, region, config):
        client = session.client(service, region_name=region, config=config)
        stub = Stubber(client)
        for kind, method, payload, params in self.plan[(service, region)]:
            if kind == "ok":
                stub.add_response(method, payload, params)
            else:
                stub.add_client_error(method, service_error_code=payload, http_status_code=400, expected_params=params)
        stub.activate()
        self.stubbers[(service, region)] = stub
        return client


def specs(*calls, needs_metrics=False):
    return {"t": CheckSpec("t", "zombie", "low", {"en": "t", "pt-BR": "t"}, list(calls), lambda s, c: [], [],
                           needs_metrics)}


def run(tmp_path, fake, spec, regions=("us-east-1",), **kw):
    session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")
    return collect(None, list(regions) if regions else None, tmp_path / "run", session=session,
                   client_factory=fake.factory, specs=spec, **kw)


def ledger(tmp_path):
    return [json.loads(line) for line in (tmp_path / "run" / "ledger.jsonl").read_text().splitlines()]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def offline(*a, **kw):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(engine, "open_url", offline)


VOLUMES = call("ec2", "DescribeVolumes", keep="Volumes[].{id: VolumeId, size: Size}", result_key="Volumes")


def vol(i):
    return {"VolumeId": f"vol-{i}", "Size": 8, "Encrypted": True, "KmsKeyId": "example-key", "State": "available"}


def test_pagination_merges_pages_and_keep_drops_unlisted_fields(tmp_path):
    fake = Fake()
    fake.ok("ec2", "us-east-1", "describe_volumes", {"Volumes": [vol(1)], "NextToken": "t1"})
    fake.ok("ec2", "us-east-1", "describe_volumes", {"Volumes": [vol(2)]}, {"NextToken": "t1"})
    snap = run(tmp_path, fake, specs(VOLUMES))
    assert snap.status(VOLUMES, "us-east-1") == "ok"
    assert snap.items(VOLUMES, "us-east-1") == [{"id": "vol-1", "size": 8}, {"id": "vol-2", "size": 8}]
    raw = (tmp_path / "run" / "snapshot.json").read_text()
    assert "KmsKeyId" not in raw and "example-key" not in raw and "NextToken" not in raw
    fake.stubbers[("ec2", "us-east-1")].assert_no_pending_responses()


def test_merge_pages_without_result_key_concatenates_list_keys():
    pages = [{"A": [1], "B": "x", "C": [3]}, {"A": [2], "B": "y", "C": []}]
    assert merge_pages(pages, "") == {"A": [1, 2], "B": "x", "C": [3]}
    assert merge_pages(pages, "A") == {"A": [1, 2], "B": "x", "C": [3]}


def test_ledger_has_one_line_per_request(tmp_path):
    fake = Fake()
    fake.ok("ec2", "us-east-1", "describe_volumes", {"Volumes": [vol(1)], "NextToken": "t1"})
    fake.ok("ec2", "us-east-1", "describe_volumes", {"Volumes": [vol(2)]}, {"NextToken": "t1"})
    run(tmp_path, fake, specs(VOLUMES))
    lines = ledger(tmp_path)
    ops = [(e["service"], e["operation"], e["region"], e["status"]) for e in lines]
    assert ops.count(("sts", "GetCallerIdentity", "us-east-1", "ok")) == 1
    assert ops.count(("ec2", "DescribeVolumes", "us-east-1", "ok")) == 2
    assert ("aws", "IpRanges", "global", "error") in ops
    assert all({"ts", "service", "operation", "region", "status", "ms"} <= set(e) for e in lines)


def test_collect_summary_and_run_dir_mode(tmp_path, capsys):
    fake = Fake()
    fake.ok("ec2", "us-east-1", "describe_volumes", {"Volumes": []})
    run(tmp_path, fake, specs(VOLUMES))
    summary = json.loads((tmp_path / "run" / "collect.json").read_text())
    assert summary["account_id"] == ACCOUNT
    assert summary["regions"] == ["us-east-1"]
    assert summary["counts"] == {"error": 1, "ok": 2}
    assert stat.S_IMODE((tmp_path / "run").stat().st_mode) == 0o700
    loaded = Snapshot.load(tmp_path / "run")
    assert loaded.get(calls_core.CALLER) == {"account": ACCOUNT, "arn": ARN}
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ec2 done" in captured.err


def test_enabled_regions_when_no_list_is_given(tmp_path):
    fake = Fake()
    fake.ok("ec2", "us-east-1", "describe_regions",
            {"Regions": [{"RegionName": "sa-east-1"}, {"RegionName": "us-east-1"}]})
    snap = run(tmp_path, fake, specs(), regions=None)
    assert snap.regions == ["sa-east-1", "us-east-1"]
    assert snap.get(calls_core.ENABLED_REGIONS) == ["sa-east-1", "us-east-1"]


CLUSTERS = call("eks", "ListClusters", keep="clusters", result_key="clusters")
DESCRIBE = call("eks", "DescribeCluster", keep="cluster.{name: name, version: version}",
                per_item=("eks", "ListClusters", "[]", "name"))


def test_per_item_by_id_with_one_failing_id(tmp_path):
    fake = Fake()
    fake.ok("eks", "us-east-1", "list_clusters", {"clusters": ["a", "b"]})
    fake.ok("eks", "us-east-1", "describe_cluster", {"cluster": {"name": "a", "version": "1.34", "arn": "x"}},
            {"name": "a"})
    fake.err("eks", "us-east-1", "describe_cluster", "ResourceNotFoundException", {"name": "b"})
    snap = run(tmp_path, fake, specs(CLUSTERS, DESCRIBE))
    assert snap.status(DESCRIBE, "us-east-1") == "ok"
    assert snap.per_item(DESCRIBE, "us-east-1") == {
        "a": {"name": "a", "version": "1.34"},
        "b": {"__error__": "ResourceNotFoundException"},
    }
    ops = [(e["operation"], e["status"]) for e in ledger(tmp_path)]
    assert ops.count(("DescribeCluster", "ok")) == 1
    assert ops.count(("DescribeCluster", "error")) == 1


def test_per_item_caps_ids(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_IDS", 2)
    fake = Fake()
    fake.ok("eks", "us-east-1", "list_clusters", {"clusters": ["a", "b", "c"]})
    for name in ("a", "b"):
        fake.ok("eks", "us-east-1", "describe_cluster", {"cluster": {"name": name}}, {"name": name})
    snap = run(tmp_path, fake, specs(CLUSTERS, DESCRIBE))
    assert sorted(snap.per_item(DESCRIBE, "us-east-1")) == ["a", "b"]
    summary = json.loads((tmp_path / "run" / "collect.json").read_text())
    assert summary["capped"] == [{"call": DESCRIBE.key, "region": "us-east-1", "ids": 3, "kept": 2}]


def test_per_item_without_declared_parent_fails_at_load(tmp_path):
    with pytest.raises(ValueError, match="parent"):
        run(tmp_path, Fake(), specs(DESCRIBE))


ALARMS = call("cloudwatch", "DescribeAlarms", keep="MetricAlarms[].AlarmName", result_key="MetricAlarms")
COSTS = call("ce", "GetCostAndUsage", keep="ResultsByTime", scope="home", paginate=False,
             params={"TimePeriod": {"Start": "2026-01-01", "End": "2026-01-15"}, "Granularity": "DAILY",
                     "Metrics": ["UnblendedCost"]})
SNAPSHOTS = call("ec2", "DescribeSnapshots", keep="Snapshots[].SnapshotId", result_key="Snapshots",
                 params={"OwnerIds": ["self"]})


METRIC_DATA = call("cloudwatch", "GetMetricData", keep="MetricDataResults[].Id",
                   result_key="MetricDataResults",
                   params={"MetricDataQueries": [], "StartTime": "2026-01-01T00:00:00Z",
                           "EndTime": "2026-01-02T00:00:00Z"})


def test_billed_metric_reads_cost_explorer_and_metric_checks_are_opt_in(tmp_path):
    fake = Fake()
    fake.ok("cloudwatch", "us-east-1", "describe_alarms", {"MetricAlarms": [{"AlarmName": "cpu-high"}]})
    spec = specs(ALARMS, METRIC_DATA, COSTS) | {"m": CheckSpec("m", "cost", "low", {"en": "m", "pt-BR": "m"},
                                                                [SNAPSHOTS], lambda s, c: [], [], True)}
    snap = run(tmp_path, fake, spec)
    assert snap.get(ALARMS, "us-east-1") == ["cpu-high"]
    for c in (METRIC_DATA, COSTS, SNAPSHOTS):
        assert snap.status(c, "us-east-1") == "missing"
        assert snap.data[c.key]["us-east-1"]["error"] == "opt-in"
    assert ("ce", "us-east-1") not in fake.stubbers
    summary = json.loads((tmp_path / "run" / "collect.json").read_text())
    assert summary["opt_in_skipped"] == sorted([METRIC_DATA.key, COSTS.key, SNAPSHOTS.key])


def test_metrics_flag_runs_cloudwatch(tmp_path):
    fake = Fake()
    fake.ok("cloudwatch", "us-east-1", "describe_alarms", {"MetricAlarms": [{"AlarmName": "cpu-high"}]})
    snap = run(tmp_path, fake, specs(ALARMS), metrics=True)
    assert snap.get(ALARMS, "us-east-1") == ["cpu-high"]


DENIED = call("iam", "GetAccountSummary", keep="SummaryMap", scope="global", paginate=False)
THROTTLED = call("ec2", "DescribeAddresses", keep="Addresses[].PublicIp", paginate=False)
OPTIN = call("ec2", "DescribeVpcs", keep="Vpcs[].VpcId", result_key="Vpcs")


def test_status_mapping_from_client_errors(tmp_path):
    fake = Fake()
    fake.err("iam", "us-east-1", "get_account_summary", "AccessDenied")
    fake.err("ec2", "us-east-1", "describe_addresses", "RequestLimitExceeded")
    fake.err("ec2", "us-east-1", "describe_vpcs", "OptInRequired")
    snap = run(tmp_path, fake, specs(DENIED, THROTTLED, OPTIN))
    assert snap.status(DENIED) == "denied"
    assert snap.data[DENIED.key]["global"]["error"] == "AccessDenied"
    assert snap.status(THROTTLED, "us-east-1") == "throttled"
    assert snap.status(OPTIN, "us-east-1") == "unsupported"


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "m"}}, "Op")


@pytest.mark.parametrize("exc,regional,expected", [
    (client_error("AccessDeniedException"), True, "denied"),
    (client_error("UnauthorizedOperation"), True, "denied"),
    (client_error("AuthorizationError"), True, "denied"),
    (client_error("ThrottlingException"), True, "throttled"),
    (client_error("TooManyRequestsException"), True, "throttled"),
    (client_error("SubscriptionRequiredException"), True, "unsupported"),
    (client_error("InvalidAction"), True, "unsupported"),
    (client_error("UnrecognizedClientException"), True, "unsupported"),
    (client_error("UnrecognizedClientException"), False, "error"),
    (client_error("ValidationException"), True, "error"),
    (EndpointConnectionError(endpoint_url="https://example.com"), True, "unsupported"),
    (AllowlistViolation("x"), True, "error"),
])
def test_classify(exc, regional, expected):
    assert classify(exc, regional)[0] == expected


def test_allowlist_violation_maps_to_allowlist_error():
    assert classify(AllowlistViolation("x"), True) == ("error", "allowlist")


TERMINATE = call("ec2", "TerminateInstances", keep="TerminatingInstances[].InstanceId", paginate=False,
                 params={"InstanceIds": ["i-0123456789abcdef0"]})


def test_declared_denylist_call_is_never_sent(tmp_path):
    fake = Fake()
    fake.ok("ec2", "us-east-1", "terminate_instances", {"TerminatingInstances": []})
    snap = run(tmp_path, fake, specs(TERMINATE))
    assert snap.status(TERMINATE, "us-east-1") == "error"
    assert snap.data[TERMINATE.key]["us-east-1"]["error"] == "allowlist"
    with pytest.raises(AssertionError):
        fake.stubbers[("ec2", "us-east-1")].assert_no_pending_responses()
    assert ("ec2", "TerminateInstances", "blocked") in [(e["service"], e["operation"], e["status"])
                                                       for e in ledger(tmp_path)]


PUBLIC_BLOCK = call("s3control", "GetPublicAccessBlock", keep="PublicAccessBlockConfiguration", scope="home",
                    paginate=False, params={"AccountId": "{account}"})


def test_account_placeholder_is_replaced(tmp_path):
    fake = Fake()
    fake.ok("s3control", "us-east-1", "get_public_access_block",
            {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}, {"AccountId": ACCOUNT})
    snap = run(tmp_path, fake, specs(PUBLIC_BLOCK))
    assert snap.get(PUBLIC_BLOCK) == {"BlockPublicAcls": True}
    fake.stubbers[("s3control", "us-east-1")].assert_no_pending_responses()


def test_ip_ranges_are_filtered_deduplicated_and_sorted(tmp_path, monkeypatch):
    doc = {"prefixes": [
        {"ip_prefix": "198.51.100.0/24", "region": "us-east-1", "service": "AMAZON"},
        {"ip_prefix": "198.51.100.0/24", "region": "us-east-1", "service": "EC2"},
        {"ip_prefix": "192.0.2.0/24", "region": "sa-east-1", "service": "AMAZON"},
        {"ip_prefix": "203.0.113.0/24", "region": "GLOBAL", "service": "CLOUDFRONT"},
        {"ip_prefix": "203.0.113.128/25", "region": "GLOBAL", "service": "GLOBALACCELERATOR"},
    ], "ipv6_prefixes": [{"ipv6_prefix": "2001:db8::/32", "region": "us-east-1", "service": "AMAZON"}]}
    seen = {}

    def fake_open(url):
        seen.update(url=url)
        return io.BytesIO(json.dumps(doc).encode())

    monkeypatch.setattr(engine, "open_url", fake_open)
    snap = run(tmp_path, Fake(), specs())
    assert seen == {"url": "https://ip-ranges.amazonaws.com/ip-ranges.json"}
    assert snap.status(calls_core.IP_RANGES) == "ok"
    assert snap.get(calls_core.IP_RANGES) == [
        {"cidr": "192.0.2.0/24", "region": "sa-east-1", "service": "AMAZON"},
        {"cidr": "198.51.100.0/24", "region": "us-east-1", "service": "EC2"},
        {"cidr": "203.0.113.128/25", "region": "GLOBAL", "service": "GLOBALACCELERATOR"},
    ]


def test_ip_ranges_network_failure_is_error(tmp_path):
    snap = run(tmp_path, Fake(), specs())
    assert snap.status(calls_core.IP_RANGES) == "error"


def test_ip_ranges_larger_than_cap_is_error(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_IP_RANGES_BYTES", 16)
    monkeypatch.setattr(engine, "open_url", lambda url: io.BytesIO(json.dumps({"prefixes": []}).encode() + b" " * 20))
    snap = run(tmp_path, Fake(), specs())
    assert snap.status(calls_core.IP_RANGES) == "error"
    assert snap.data[calls_core.IP_RANGES.key]["global"]["error"] == "ValueError"


def test_ip_ranges_redirect_is_refused():
    req = urllib.request.Request(engine.IP_RANGES_URL)
    with pytest.raises(urllib.error.HTTPError, match="refusing redirect"):
        engine.NoRedirect().redirect_request(req, io.BytesIO(), 302, "Found", {}, "https://example.com/ip.json")


def test_ip_ranges_opener_keeps_tls_verification_and_refuses_redirects(monkeypatch):
    built = {}

    class Opener:
        def open(self, url, timeout):
            built.update(url=url, timeout=timeout)
            return io.BytesIO(b"{}")

    def fake_build(*handlers):
        built["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build)
    REAL_OPEN_URL(engine.IP_RANGES_URL)
    assert built["handlers"] == (engine.NoRedirect,)
    assert built["url"].startswith("https://") and built["timeout"] == 20


def test_existing_run_dir_keeps_its_mode(tmp_path):
    (tmp_path / "run").mkdir(mode=0o755)
    os.chmod(tmp_path / "run", 0o755)
    fake = Fake()
    fake.ok("ec2", "us-east-1", "describe_volumes", {"Volumes": []})
    run(tmp_path, fake, specs(VOLUMES))
    assert stat.S_IMODE((tmp_path / "run").stat().st_mode) == 0o755


ASSUMED = {"Credentials": {"AccessKeyId": "ASIAIOSFODNN7EXAMPLE", "SecretAccessKey": "x", "SessionToken": "y",
                           "Expiration": "2026-01-01T00:00:00Z"}}


def test_session_clients_are_not_guarded_but_collector_clients_are(tmp_path):
    session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")
    made = []
    fake = Fake()
    fake.ok("sts", "us-east-1", "assume_role", ASSUMED)

    def factory(sess, service, region, config):
        client = fake.factory(sess, service, region, config)
        made.append(client)
        return client

    collect(None, ["us-east-1"], tmp_path / "run", session=session, client_factory=factory, specs=specs())
    guarded = made[0]
    with pytest.raises(AllowlistViolation):
        guarded.assume_role(RoleArn="arn:aws:iam::111122223333:role/audit", RoleSessionName="audit")
    plain = session.client("sts", region_name="us-east-1")
    stub = Stubber(plain)
    stub.add_response("assume_role", ASSUMED)
    stub.activate()
    assert plain.assume_role(RoleArn="arn:aws:iam::111122223333:role/audit",
                             RoleSessionName="audit")["Credentials"]["AccessKeyId"] == "ASIAIOSFODNN7EXAMPLE"
    stub.assert_no_pending_responses()


SELECTIONS = call("backup", "ListBackupSelections",
                  keep="BackupSelectionsList[].{id: SelectionId, plan: BackupPlanId}",
                  result_key="BackupSelectionsList", per_item=("backup", "ListBackupPlans", "[].id", "BackupPlanId"))
PLANS = call("backup", "ListBackupPlans", keep="BackupPlansList[].{id: BackupPlanId}", result_key="BackupPlansList")
SELECTION = call("backup", "GetBackupSelection", keep="BackupSelection.SelectionName", paginate=False,
                 per_item=("backup", "ListBackupSelections",
                           "values(@)[][].{BackupPlanId: plan, SelectionId: id}", "*"))


def test_nested_per_item_with_multi_param_ids(tmp_path):
    fake = Fake()
    fake.ok("backup", "us-east-1", "list_backup_plans", {"BackupPlansList": [{"BackupPlanId": "p1"}]})
    fake.ok("backup", "us-east-1", "list_backup_selections",
            {"BackupSelectionsList": [{"SelectionId": "s1", "BackupPlanId": "p1"}]}, {"BackupPlanId": "p1"})
    fake.ok("backup", "us-east-1", "get_backup_selection",
            {"BackupSelection": {"SelectionName": "daily", "IamRoleArn": "arn:aws:iam::111122223333:role/b"},
             "SelectionId": "s1", "BackupPlanId": "p1"},
            {"BackupPlanId": "p1", "SelectionId": "s1"})
    snap = run(tmp_path, fake, specs(PLANS, SELECTIONS, SELECTION))
    assert snap.per_item(SELECTIONS, "us-east-1") == {"p1": [{"id": "s1", "plan": "p1"}]}
    assert snap.per_item(SELECTION, "us-east-1") == {"p1|s1": "daily"}
