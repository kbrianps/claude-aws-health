# Contributing

Thanks for helping. The most useful contribution is a new check, or a false positive you hit on a real account.

## Setup

```bash
git clone https://github.com/kbrianps/claude-aws-health && cd claude-aws-health
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q && ruff check awshealth tests scripts tools
awshealth demo --out /tmp/awshealth-demo
```

No AWS account is needed to write or test a check.

## Adding a check

1. Pick an entry from the catalog (`awshealth catalog`) or open an issue describing the problem it catches and the false positives you expect.
2. Create `awshealth/checks/<id_with_underscores>.py` following "Writing a check" in [DESIGN.md](DESIGN.md). [`eks_extended_support.py`](awshealth/checks/eks_extended_support.py) is the reference.
3. Declare every API call with a `keep` projection that keeps only the fields you read. Never keep UserData, environment variables, policy secrets, tokens or object contents.
4. Write English and Brazilian Portuguese text. Plain words, name the resource, no em dashes.
5. Put dollar figures only through `awshealth/prices.py`, with the formula in `usd_calc`.
6. Add 1-3 read-only `verify` commands with `--region`, `--query` and `--output`.
7. Add `tests/test_<module>.py` with a positive case, a false-positive case and a quiet case.

The CI fails if a check declares a mutating or secret-reading API operation, so a check can never widen what the collector is allowed to call.

## Changes to the guard hook

Every change to `scripts/aws_guard.py` comes with rows in `tests/test_guard.py`: one blocked case and one allowed case that proves normal work still passes.

## Style

- No comments in code; names and small functions carry the meaning.
- Conventional Commits: `feat: add nat gateway idle check`, `fix: skip requester-managed interfaces`.
- Never commit real account ids, names, domains or IP addresses. Use `111122223333`, `example.com` and the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.
