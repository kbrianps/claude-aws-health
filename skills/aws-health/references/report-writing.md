# Writing for the person who has to act

The reader is often not the person who built the account. Write so they can act without opening the AWS docs.

## Plain language

- Lead with the action and the consequence: "Upgrade cluster prod-eks before 2026-03-23 or it moves to extended support, about US$365 more per month at list price."
- One idea per sentence. Short words. No jargon without a one-line explanation the first time ("extended support: AWS keeps patching an old version, for a higher hourly price").
- Name the resource, the region and the account. "3 volumes" is less useful than "vol-0abc, vol-0def and vol-0123 in us-east-1".
- Dollars: always "per month", always "at list price" unless the figure came from Cost Explorer. Round to whole dollars.
- Dates: in the user's timezone, with the weekday for anything in the next 30 days.
- Say what you could not check, in the same tone as what you found. "Could not read RDS in sa-east-1 (access denied)" is a result, not an apology.
- No em dashes. No exclamation marks. No "simply" or "just".
- pt-BR text: Brazilian Portuguese with correct accents and plain words.

## Order

1. Deadlines, nearest first. A deadline with a dollar figure goes before one without.
2. High risk: public exposure, admin access without MFA, root usage, disabled detective controls.
3. Money: largest monthly figure first.
4. Everything else, grouped by where the user sees it.

## Group by where the user sees it

| the user sees it in | examples |
|---|---|
| a bill line | "Amazon Elastic Kubernetes Service", "EC2-Other" (EBS volumes, snapshots, NAT, idle Elastic IPs), "Amazon Virtual Private Cloud" (public IPv4) |
| a console page | IAM > Users, EC2 > Volumes, RDS > Databases, S3 > Block Public Access settings |
| a calendar | extended support dates, certificate expiry, runtime deprecation |
| an inbox | AWS Health notices, budget alerts, SNS topics with no subscribers |

Mention the check id only in the detailed report, never as the headline.

## Prowler check names

Prowler names state what should be true, for example `s3_bucket_default_encryption` or `iam_root_mfa_enabled`. A `FAIL` means that statement is not true for that resource. Translate the name into the problem: `iam_root_mfa_enabled: FAIL` becomes "the root user has no MFA". A `PASS` is not news; do not list passes. A `MANUAL` result means Prowler could not decide; say so.

## Verify commands

Every action in the summary carries one read-only command copied from the finding's `verify` list, so the reader can confirm it before acting. Never write a command that changes something, and never one that prints a secret.
