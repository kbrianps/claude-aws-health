# AGENTS.md

Instructions for coding agents working on this repository. Read `DESIGN.md` first.

## Layout

| path | what it is |
|---|---|
| `awshealth/` | the deterministic CLI; the only code that touches AWS credentials |
| `awshealth/checks/` | one module per check; `eks_extended_support.py` is the reference |
| `awshealth/data/catalog.json` | the 282-entry health catalog |
| `.claude-plugin/` | `plugin.json` (plugin `aws-health`) and `marketplace.json` (marketplace `kbrianps`, source `./`) |
| `skills/aws-health/` | the skill and its one-level `references/` |
| `agents/aws-health-skeptic.md` | the read-only skeptic subagent |
| `commands/` | `/aws-health:audit` and `/aws-health:report` |
| `hooks/hooks.json`, `scripts/aws_guard.py` | the PreToolUse guard |
| `iam/` | the audit role template, the standalone deny policy and trust examples |
| `docs/` | threat model and deep mode |

## Commands

```bash
python -m pytest -q
python -m ruff check .
claude plugin validate .
```

## Rules

- Never call AWS from tests or while developing. Use fixtures, `awshealth.testing.snap_with` and botocore `Stubber`. Never read `~/.aws`.
- Never put real account ids, company names, people, domains or IPs anywhere. Use `111122223333` (and `444455556666` for an external account), `example.com` and the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.
- No comments in code. English identifiers, messages and docs. Brazilian Portuguese only in the `pt-BR` text of findings and report strings, with correct accents and no em dashes.
- Python 3.10 or newer, standard library plus boto3, jmespath and pyyaml. The guard script uses only the standard library.
- New checks follow "Writing a check" in `DESIGN.md`: a `keep` projection that keeps no secrets, claims for every number, prices only from `prices.py`, read-only `verify` commands, and tests with a positive, a false-positive and a quiet case.

## Guard invariants

`scripts/aws_guard.py` runs on every Bash, Monitor, Read, Grep, Glob, NotebookRead and WebFetch call in any session where the plugin is enabled. It does nothing unless `AWSHEALTH_GUARD` is set in Claude Code's environment, so the plugin never blocks unrelated work.

- It blocks with exit code 2 and a reason on stderr. Any other exit code lets the call through, so every error path must end in exit 2. Keep the top-level `except BaseException` that fails closed.
- It must stay fast and dependency-free: `python3 -I`, standard library only, no network, no file reads.
- Strict mode (`AWSHEALTH_GUARD=strict`, and any unknown value) allows no direct `aws` call except `aws sts get-caller-identity`, `aws --version` and `aws help`. Deep mode allows read-only verbs only.
- Every change to the guard comes with rows in `tests/test_guard.py`, both a blocked case and an allowed case that shows the change does not break normal work.

## Plugin constraints

- The plugin name stays `aws-health`; names starting with `claude-`, `anthropic-` or `cc-plugin-` are reserved.
- No `bin/` directory: claude.ai and Cowork refuse plugins that have one.
- Plugin subagents ignore `hooks` and `permissionMode` in their frontmatter. Session-wide protection lives in `hooks/hooks.json`.
- Keep `SKILL.md` under 500 lines and its references one level deep. Skill frontmatter uses only `name`, `description` (at most 1,024 characters), `license`, `compatibility`, `metadata` and `allowed-tools`.
- Use `${CLAUDE_PLUGIN_ROOT}` for files shipped with the plugin and `${CLAUDE_PLUGIN_DATA}` for state that must survive updates. Run output never goes inside the repository.

## IAM

`iam/deny-policy.json` holds the same deny statements as the inline policy in `iam/audit-role.cfn.yaml`, including `DenyBilledMetricReads`. Change both together and keep the JSON under 6,144 characters.
