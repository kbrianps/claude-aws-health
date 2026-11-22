# Demo fixture

`awshealth demo` runs the full pipeline on the files in this folder. No AWS access is needed.

- `snapshot.json` (required): a run snapshot in the `Snapshot.save` format, `{meta, data}`, for the fictional account 111122223333. The checks and the report use `meta.collected_at` as their clock, so the demo output does not drift over time.
- `adjustments.jsonl` (optional): skeptic verdicts applied before rendering.
- `collect.json` and `ledger.jsonl` (optional): copied into the run so the report footer shows a ledger summary.

Use only fictional data: account 111122223333 (444455556666 for external), example.com, and the documentation IP ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
