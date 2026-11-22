# adjustments.jsonl

`<run>/adjustments.jsonl` records what the review did to deterministic findings. `awshealth render` applies it and refuses the whole file if one line is invalid, listing every problem with its line number.

One JSON object per line:

| key | required | value |
|---|---|---|
| `uid` | yes | the finding's `uid` from `findings.json` or `imported/*.json` |
| `verdict` | yes | `confirmed`, `downgraded`, `killed` or `question` |
| `severity` | for `downgraded` | `critical`, `high`, `medium`, `low` or `info`; must be lower than the current severity; never higher |
| `reason` | yes | one or two plain sentences: what was checked and what it showed |
| `evidence` | for `killed` | a string or a list of strings pointing at the data: `snapshot:<call_key>@<region>:<resource id> <field>=<value>` or a file and a value |
| `question` | for `question` | `{"en": "...", "pt-BR": "..."}`, a question the owner can answer with one decision |

Rules:

- A `downgraded` line must change the severity; if it stays the same, use `confirmed`.
- Several lines for the same uid apply in order; each severity must be lower than the one before.
- Never put secret values in `reason` or `evidence`.
- The pt-BR text uses correct accents, plain words and no em dashes.

Examples:

```json
{"uid": "ebs-unattached:3f2a9c1d0b7e", "verdict": "confirmed", "reason": "Volume vol-0abc is available since 2025-08-02 and has no Kubernetes or DR tag."}
{"uid": "ec2-stopped-long:9b1c2d3e4f50", "verdict": "downgraded", "severity": "low", "reason": "Tagged env=staging; the cost is the EBS volume only, at list price."}
{"uid": "eip-unassociated:0a1b2c3d4e5f", "verdict": "killed", "reason": "The address is attached to a NAT gateway ENI owned by the service.", "evidence": ["snapshot:ec2:DescribeAddresses@us-east-1:eipalloc-0abc NetworkInterfaceOwnerId=amazon-elb"]}
{"uid": "iam-console-no-mfa:5e6f7a8b9c0d", "verdict": "question", "reason": "User name suggests a break-glass account.", "question": {"en": "Is break-glass-admin an emergency account kept on purpose, with its password in a safe?", "pt-BR": "O usuário break-glass-admin é uma conta de emergência mantida de propósito, com a senha guardada em cofre?"}}
```
