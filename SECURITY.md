# Security policy

`awshealth` is meant to run against production AWS accounts, so security reports are welcome and taken seriously.

## Reporting

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/kbrianps/claude-aws-health/security/advisories/new). Do not open a public issue for them. You can expect a first answer within a week.

Especially interesting:

- A way to make the collector send an API call that is not in its allowlist, or a mutating call at all.
- A way for text from AWS (tags, names, descriptions) to change what the agent does or to run script in `report.html`.
- A way to read credentials, secrets or data-plane content past the guard hook while `AWSHEALTH_GUARD` is set.
- An IAM permission in `iam/` that is broader than documented.

## Scope and limits

The threat model and its known limits are in [docs/threat-model.md](docs/threat-model.md). The guard hook protects you from the agent and from injected text; it does not protect you from yourself, and it is off unless `AWSHEALTH_GUARD` is set.
