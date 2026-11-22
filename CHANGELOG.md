# Changelog

## 0.1.0

First public release.

- `awshealth` CLI: `collect`, `check`, `import`, `render`, `verify`, `demo`, `catalog`.
- Collector with an exact API allowlist generated from the checks, field projection, per-service rate limits and a call ledger.
- 34 deterministic checks across cost, security, lifecycle, resilience, silent failures and governance.
- Reports: single-file HTML (English and Brazilian Portuguese), Markdown, calendar of deadlines, owner questions, catalog coverage and OCSF findings.
- Importers for Prowler OCSF and AWS Cost Optimization Hub.
- Claude Code plugin `aws-health`: audit skill, skeptic agent, guard hook with strict and deep modes.
- CloudFormation audit role with an explicit deny on data-plane reads, credential minting and billed calls.
- Catalog of 282 AWS health checks with detection steps, sources and false-positive traps.
