# Deep mode

Quick mode covers what the deterministic checks automate. Deep mode lets Claude also run read-only `aws` CLI commands to work through the rest of the 282-entry catalog (`awshealth catalog` shows which entries are left). It is opt-in, because in deep mode the agent sees what those commands print.

## Before you turn it on

1. Deploy the audit role from `iam/audit-role.cfn.yaml` and create a CLI profile for it (see `iam/trust-policy-examples.md`). Never use deep mode with an admin profile.
2. Run a quick-mode audit first. Deep mode only fills the gaps.
3. Decide whether you accept billed reads. CloudWatch metric reads and Cost Explorer cost money; the role denies metric reads unless deployed with `AllowCostAndMetrics=true`, and Claude asks before any billed call.

## Turn it on

The guard reads two variables from Claude Code's own environment, so set them before starting Claude Code. Setting them inside a Bash command does nothing.

```bash
AWSHEALTH_GUARD=deep AWSHEALTH_PROFILE=aws-health-audit claude
```

Or put them in the `env` block of `.claude/settings.local.json` and restart Claude Code:

```json
{"env": {"AWSHEALTH_GUARD": "deep", "AWSHEALTH_PROFILE": "aws-health-audit"}}
```

Then ask for a deep audit. Claude confirms the account with `aws sts get-caller-identity --profile aws-health-audit` and reads the account id back to you before it runs anything else.

## What the guard allows

| | strict (`AWSHEALTH_GUARD=strict`, or any unknown value) | deep (`AWSHEALTH_GUARD=deep`) |
|---|---|---|
| `awshealth check`, `render`, `import`, `verify`, `catalog` | yes | yes |
| `awshealth collect` | yes, profile must be `AWSHEALTH_PROFILE` | same |
| `aws sts get-caller-identity`, `aws --version`, `aws help` | yes | yes |
| `aws <service> describe-*`, `list-*`, `get-*`, `lookup-*`, `search-*`, `batch-get-*`, `aws s3 ls` | no | yes, except the operations below |
| secret reads (`get-secret-value`, `ssm get-parameter*`, `--with-decryption`, `--include-values`) | no | no |
| data-plane reads (`s3 cp`, `get-object`, `dynamodb scan/query/get-item`, log events, query results) | no | no |
| credential minting (`get-session-token`, `assume-role`, `ecr get-login-password`, `eks get-token`, `configure export-credentials`) | no | no |
| calls that return environment variables or user data without a safe `--query` (`lambda list-functions`, `ecs describe-task-definition`, launch templates, Glue connections) | no | only with a `--query` that names safe fields |
| `--debug`, `--endpoint-url`, `--cli-input-json/yaml`, `--no-verify-ssl`, `--ca-bundle` | no | no |
| any `--profile` or `AWS_PROFILE` other than `AWSHEALTH_PROFILE` | no | no |
| WebFetch, Monitor WebSocket, `curl`, `wget`, `nc` | no while `AWSHEALTH_GUARD` is set | no |

In every mode, with or without the variables, the guard blocks reads of `~/.aws`, `.env` files, `*.tfstate*`, `*.tfvars`, SSH and TLS private keys, `/proc/*/environ`, environment dumps (`printenv`, `env`, `set`, `export -p`), instance metadata endpoints and boto3/botocore scripts.

Without `AWSHEALTH_PROFILE`, no `--profile` flag is accepted at all, and commands use whatever the default credentials are. Set it so every command is pinned to the audit role.

## What you get

Deep mode writes two files next to the quick-mode results:

- `<run>/deep/coverage.jsonl`: one line per catalog entry with `checked_ok`, `finding`, `not_applicable`, `no_access` or `already_covered`.
- `<run>/deep/observations.jsonl`: what it found, each with the command that shows it.

Observations are labeled as deep-mode results in the summary. They are not deterministic findings and are not written to `findings.json`.

## Turn it off

Start Claude Code without the variables, or remove them from the settings `env` block. The guard falls back to strict mode. Disabling the plugin removes the guard completely.
