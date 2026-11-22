---
description: Run a read-only AWS health audit with the aws-health skill
argument-hint: "[profile] [regions]"
---

Use the aws-health skill to audit one AWS account, read-only. Follow its workflow from step 1: explain the trust model, ask for quick or deep mode, check that awshealth is installed, then check, challenge with the skeptic, render and summarize.

If the user passed arguments, treat them as the audit profile and the regions to collect: $ARGUMENTS
