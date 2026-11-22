from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .model import SEVERITIES, Finding

VERDICTS = ("confirmed", "downgraded", "killed", "question")


@dataclass
class Killed:
    finding: Finding
    reason: str
    evidence: list[str] = field(default_factory=list)


def _evidence(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    return [str(value)] if str(value).strip() else []


def _validate(n: int, adj: dict, current: dict[str, str]) -> str:
    uid = adj.get("uid")
    verdict = adj.get("verdict")
    if uid not in current:
        return f"line {n}: unknown uid {uid!r}"
    if verdict not in VERDICTS:
        return f"line {n}: verdict must be one of {', '.join(VERDICTS)}, got {verdict!r}"
    if not str(adj.get("reason") or "").strip():
        return f"line {n}: {uid} needs a reason"
    severity = adj.get("severity")
    if severity is not None:
        if severity not in SEVERITIES:
            return f"line {n}: bad severity {severity!r}"
        if SEVERITIES.index(severity) < SEVERITIES.index(current[uid]):
            return (f"line {n}: {uid} cannot be raised from {current[uid]} to {severity}; "
                    "the review may only lower severity")
    if verdict == "downgraded":
        if severity is None:
            return f"line {n}: downgraded {uid} needs a severity"
        if severity == current[uid]:
            return f"line {n}: downgraded {uid} keeps severity {severity}; use confirmed instead"
    if verdict == "killed" and not _evidence(adj.get("evidence")):
        return f"line {n}: killing {uid} needs evidence"
    if verdict == "question":
        q = adj.get("question") or {}
        if not isinstance(q, dict) or not str(q.get("en") or "").strip():
            return f"line {n}: question verdict for {uid} needs question.en"
    return ""


def load(adjustments_path: Path) -> list[tuple[int, dict]]:
    out = []
    for n, line in enumerate(Path(adjustments_path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append((n, json.loads(line)))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{adjustments_path} line {n}: not valid JSON ({exc.msg})") from exc
    return out


def apply(findings: list[Finding], adjustments_path: Path | None) -> tuple[list[Finding], list[Killed], list[Finding]]:
    by_uid = {f.uid: f for f in findings}
    killed: dict[str, Killed] = {}
    if adjustments_path and Path(adjustments_path).exists():
        entries = load(adjustments_path)
        current = {uid: f.severity for uid, f in by_uid.items()}
        errors = []
        for n, adj in entries:
            if not isinstance(adj, dict):
                errors.append(f"line {n}: expected a JSON object")
                continue
            problem = _validate(n, adj, current)
            if problem:
                errors.append(problem)
            elif adj.get("severity"):
                current[adj["uid"]] = adj["severity"]
        if errors:
            raise ValueError(f"invalid adjustments in {adjustments_path}:\n" + "\n".join(errors))
        for _, adj in entries:
            f = by_uid[adj["uid"]]
            verdict, reason = adj["verdict"], str(adj["reason"]).strip()
            if adj.get("severity") and adj["severity"] != f.severity:
                f.notes.append(f"{verdict}: severity {f.severity} -> {adj['severity']}. {reason}")
                f.severity = adj["severity"]
            else:
                f.notes.append(f"{verdict}: {reason}")
            if verdict == "killed":
                f.status = "killed"
                killed[f.uid] = Killed(f, reason, _evidence(adj.get("evidence")))
            elif verdict == "question":
                f.owner_question = {k: str(v) for k, v in adj["question"].items() if v}
                f.status = "question"
            elif verdict == "confirmed":
                f.status = "confirmed"
    kept = [f for f in findings if f.uid not in killed]
    questions = [f for f in kept if f.owner_question]
    return kept, list(killed.values()), questions
