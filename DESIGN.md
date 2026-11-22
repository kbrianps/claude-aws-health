# Design

claude-aws-health is a read-only AWS health audit. It finds deadlines that turn into bills, forgotten resources, silent failures and security gaps, and it explains each one with evidence, a dollar figure when there is one, and read-only commands to re-check it.

It has two layers:

1. **`awshealth`**, a deterministic Python CLI. It is the only component that touches AWS credentials.
2. **The `aws-health` Claude Code plugin**, a skill plus a skeptic agent and a guard hook. It reads the run directory, challenges findings, asks owner questions and writes the report. It never needs credentials for the default flow.

## Principles

- **IAM is the boundary.** The audit role is `SecurityAudit` + `ViewOnlyAccess` plus an explicit deny for data-plane reads, credential minting, secret-bearing config and billed calls (`iam/`).
- **The agent never holds credentials.** The human (or CI) runs `awshealth collect`. Claude runs `check`, `render`, `verify` and reads files. Deep mode, where Claude calls the aws CLI itself, is opt-in and runs under the guard hook.
- **Exact allowlist, not verb regexes.** `collect` builds a botocore `before-call` allowlist from the `requires` of every registered check. A call outside it raises before it is signed.
- **Projection, not redaction.** Every collected call declares a JMESPath `keep` projection. Only the projected value is written to disk.
- **Deterministic findings.** Only check code creates findings. The LLM may confirm, downgrade, kill with evidence, or turn a finding into an owner question, recorded in `adjustments.jsonl`.
- **Unknown is a first-class state.** A check whose data was denied, throttled or not collected reports `no_access` or `not_collected`, never "ok".
- **Outputs live outside the repo**, in `$AWSHEALTH_HOME/runs`, else `~/.local/share/awshealth/runs`, mode 0700. `awshealth demo` writes to `./awshealth-demo` (or `--out`) and never to the runs directory.
- **The snapshot is the clock.** `check`, `render` and `demo` use the snapshot's `collected_at` as "now", so re-checking an old run gives the same days-left and never says something expired today.

## Run directory

```
<run>/
  snapshot.json        projected API data: {meta, data: {call_key: {region|global: {status, value|by_id, error}}}}
  ledger.jsonl         one line per API call: ts, service, operation, region, status, ms, throttled
  collect.json         collection summary: account_id, regions, home_region, collected_at, duration_s,
                       requests, calls (same count as requests), blocked, counts (snapshot entries per status),
                       capped, opt_in_skipped
  findings.json        deterministic findings (Finding.to_dict list)
  checks.json          per-check status: ok | finding | no_access | not_collected | error
  imported/*.json      findings imported from Prowler OCSF or Cost Optimization Hub
  adjustments.jsonl    skeptic verdicts: {uid, verdict, severity?, reason, evidence, question?}
  report.html          single-file report, all free text HTML-escaped
  report.md
  deadlines.ics
  owner-questions.md
  coverage.md          catalog coverage: which of the 282 catalog checks ran, how, and the result
  findings.ocsf.json   OCSF 1.x Detection Finding (class_uid 2004) / Compliance Finding (2003)
  deep/*.jsonl         deep-mode coverage and observations; not rendered into the reports in v0.1
```

## Report order

"Start here" lists the first 7 findings and the inventory uses the same order: deadlines in the next 45 days first (nearest first), then critical and high findings by severity, then the rest by severity; ties go to the larger monthly dollar figure, then to the finding with more resources. The "at stake per month" figure sums awshealth findings at list price; Cost Optimization Hub savings are shown on their own line, without resources that an awshealth finding already counts.

## Writing a check

A check is one module in `awshealth/checks/`. See `eks_extended_support.py` for the reference.

```python
from ..model import Claim, Finding
from ..registry import call, check

VOLUMES = call("ec2", "DescribeVolumes", keep="Volumes[].{id: VolumeId, state: State, size: Size, type: VolumeType, tags: Tags}",
               result_key="Volumes")

@check(id="ebs-unattached", category="zombie", severity="low",
       title={"en": "...", "pt-BR": "..."}, requires=[VOLUMES], catalog_ids=["ebs-unattached-volume"])
def run(snap, ctx):
    for region in snap.regions:
        for v in snap.items(VOLUMES, region):
            ...
    return [Finding(...)]
```

Rules:

- **`call(service, Operation, keep=...)`**: boto3 client name and the API operation name in PascalCase. `keep` is applied to the full (paginated, merged) response and must keep only the fields the check reads. Never keep UserData, environment variables, policies' secrets, passwords, tokens or object contents. For fields that may hold secrets keep a boolean or a count instead (for example `length(Environment.Variables)`, never the values).
- `result_key` names the list key that pagination merges. `scope` is `regional` (every collected region), `global` (IAM, Route 53, S3 bucket list, Organizations, called once in us-east-1) or `home` (Cost Explorer, Budgets, Health, called once).
- **Per-resource calls** use `per_item=(parent_service, ParentOperation, id_jmespath, param_name)`. The engine runs the parent call, applies `id_jmespath` to the parent's kept value to get ids, calls the operation once per id with `{param_name: id}`, and stores `by_id`. Read them with `snap.per_item(CALL, region)`.
- Two checks that need the same operation with the same params must share the same `Call` object. Put shared calls in `awshealth/calls_<your-area>.py` and import them. Conflicting declarations fail at load time.
- **Findings** need `text["en"]` and `text["pt-BR"]` with `title`, `what`, `risk` (may be empty) and `fix`. Text is plain, short, concrete and names the resource. No em dashes.
- **Claims** point at the data: `Claim(source="service:Operation@region", path="<id or jmespath>", value=<the value>)`. Every number in the text must come from a claim or from `prices.py`.
- **Dollars** only from `prices.py` (list prices with a source URL) and only when the math is direct. Put the formula in `usd_calc`.
- **Deadlines** as ISO 8601 with offset.
- **Owner questions** (`owner_question={"en": ..., "pt-BR": ...}`) when the right action depends on intent: Elastic IPs that partners may allowlist, DR replicas, break-glass users, seasonal capacity.
- **`verify`**: 1-3 complete read-only aws CLI v2 commands with an explicit `--region`, `--query` and `--output text|table` (`json` only when the answer is a nested structure, such as tag conditions). Never commands that print secret values.
- **False positives**: encode the known traps in code (Kubernetes PVC volumes with Retain, requester-managed ENIs, AMI-backing snapshots, DLM/Backup snapshots, break-glass tags, DR tags) and downgrade or skip.
- **Tests**: `tests/test_<module>.py` with at least one positive case, one false-positive case and one quiet case, using `awshealth.testing.snap_with` and `run_one`. Fixed clock: `awshealth.testing.NOW` (2026-01-15 12:00 UTC). Account id `111122223333`. Never real account ids, names or IPs; use documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `example.com`.
- No comments in code. English identifiers and messages.
