---
description: Render the aws-health report for a run and summarize the actions that matter
argument-hint: "[run directory] [en|pt-BR]"
---

Render and summarize an existing aws-health run, following steps 5 and 6 of the aws-health skill.

1. Use the run directory from the arguments. Without one, use the newest directory under `${CLAUDE_PLUGIN_DATA}/runs` (or `~/.local/share/awshealth/runs`) that has a `findings.json`. If none exists, tell the user to run /aws-health:audit first.
2. Use the language from the arguments, otherwise the user's language (`en` or `pt-BR`).
3. Run `awshealth render --run <run> --lang <lang>`. If it rejects `adjustments.jsonl`, fix the lines it names and run it again.
4. Summarize: the 3 to 5 actions that matter (deadlines first, then high risk, then money), each with where the user sees it and one verify command; the open owner questions; the paths to `report.html` and `deadlines.ics`.

Arguments: $ARGUMENTS
