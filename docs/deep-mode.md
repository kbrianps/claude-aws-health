# Deep mode

Quick mode covers what the deterministic checks automate. Deep mode lets Claude also run read-only `aws` CLI commands to work through the rest of the 282-entry catalog (`awshealth catalog` shows which entries are left). It is opt-in, because in deep mode the agent sees what those commands print.

## Before you turn it on

1. Deploy the audit role from `iam/audit-role.cfn.yaml` and create a CLI profile for it (see `iam/trust-policy-examples.md`). Never use deep mode with an admin profile.
2. Run a quick-mode audit first. Deep mode only fills the gaps.
3. Decide whether you accept billed reads. CloudWatch metric reads and Cost Explorer cost money; the role denies metric reads unless deployed with `AllowCostAndMetrics=true`, and Claude asks before any billed call.

## Turn it on

The guard reads two variables from Claude Code's own environment, so set them before starting Claude Code. Setting them inside a Bash command does nothing. Without `AWSHEALTH_GUARD` the guard does nothing at all, so deep mode must never run in a session started without it.

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
| bare `aws` with no service and operation, `aws` through `xargs` or `parallel` | no | no |
| `aws <service> describe-*`, `list-*`, `get-*`, `lookup-*`, `search-*`, `batch-get-*`, `aws s3 ls` | no | yes, except the operations below |
| secret reads (`get-secret-value`, `ssm get-parameter*`, `--with-decryption`, `--include-values`) | no | no |
| data-plane reads (`s3 cp`, `get-object`, `dynamodb scan/query/get-item`, log events, query results) | no | no |
| credential minting (`get-session-token`, `assume-role`, `ecr get-login-password`, `eks get-token`, `configure export-credentials`) | no | no |
| calls that return environment variables, user data, headers or command output without a safe `--query` (`lambda list-functions`, `ecs describe-task-definition`, `ecs describe-tasks`, `batch describe-jobs`, `codebuild batch-get-builds`, launch templates, spot requests, Glue connections, `cloudfront list-distributions`) | no | only with a `--query` that names safe fields, with no `"quoted"` identifiers, backslashes or `$` |
| `--debug`, `--endpoint-url`, `--cli-input-json/yaml`, `--no-verify-ssl`, `--ca-bundle`, and any abbreviation of them or of `--profile` (`--deb`, `--endpoint`, `--prof`) | no | no |
| `$VAR`, `$(...)` or backticks in `aws` or `awshealth` arguments | no | no |
| any `--profile` or `AWS_PROFILE` other than `AWSHEALTH_PROFILE` | no | no |
| WebFetch, Monitor WebSocket, `curl`, `wget`, `nc`, `socat`, `ssh`, `scp`, `sftp`, `rsync`, `ftp`, `telnet`, `dig`, `nslookup`, `host`, `/dev/tcp`, `git push/pull/fetch/clone/remote`, network libraries in inline Python or Node scripts | no | no |

While `AWSHEALTH_GUARD` is set, in both strict and deep mode, the guard also blocks reading or writing `~/.aws` (in any letter case), `.env` files, `*.tfstate*`, `*.tfvars`, SSH and TLS private keys and `/proc/*/environ`, through Bash and through the Read, Grep, Glob, Write, Edit, MultiEdit and NotebookEdit tools. It blocks environment dumps (`printenv` and `env` with options or without arguments, `set`, `export -p`, `${!PREFIX*}`, awk `ENVIRON`, `os.environ` or `process.env` in inline scripts), instance metadata endpoints, boto3/botocore scripts, and command names built from variables, globs, braces or `$'...'` quoting. Without `AWSHEALTH_GUARD` none of this applies: the hook exits at once and every call goes through.

In a JMESPath filter, write string literals as raw strings in single quotes, for example `--query "Reservations[].Instances[?State.Name=='running'].InstanceId"`. Backticks are rejected in every `aws` argument.

Without `AWSHEALTH_PROFILE`, no `--profile` flag is accepted at all, and commands use whatever the default credentials are. Set it so every command is pinned to the audit role.

## What you get

Deep mode writes two files next to the quick-mode results:

- `<run>/deep/coverage.jsonl`: one line per catalog entry with `checked_ok`, `finding`, `not_applicable`, `no_access` or `already_covered`.
- `<run>/deep/observations.jsonl`: what it found, each with the command that shows it.

Observations are labeled as deep-mode results in the chat summary. They are not deterministic findings, are not written to `findings.json`, and are not merged into `report.html` yet: the two `.jsonl` files and the summary are where they live.

## Turn it off

Restart Claude Code with `AWSHEALTH_GUARD=strict` to go back to quick mode with the guard on. Starting Claude Code without `AWSHEALTH_GUARD`, or removing it from the settings `env` block, turns the guard off completely: it does not fall back to strict mode, it does nothing. Disabling the plugin also removes it.
