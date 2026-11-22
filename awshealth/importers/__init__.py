from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding
from . import coh, prowler

KINDS = ("prowler", "coh")


def detect(data) -> str:
    if prowler.is_prowler(data):
        return "prowler"
    if coh.items(data) is not None:
        return "coh"
    raise ValueError("cannot detect the file kind; expected Prowler json-ocsf or Cost Optimization Hub "
                     "list-recommendations output, or pass --kind")


def load_any(path: Path, kind: str | None = None) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data == [] or data == {"items": []}:
        return []
    kind = kind or detect(data)
    if kind == "prowler":
        if not isinstance(data, list):
            raise ValueError(f"{path}: Prowler json-ocsf output must be a JSON array")
        return prowler.load(data)
    if kind == "coh":
        found = coh.items(data)
        if found is None:
            raise ValueError(f"{path}: no Cost Optimization Hub recommendations (items[].recommendationId) found")
        return coh.load(found)
    raise ValueError(f"unknown kind {kind!r}; expected one of {', '.join(KINDS)}")
