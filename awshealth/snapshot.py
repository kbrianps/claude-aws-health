from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .registry import Call

STATUSES = ("ok", "denied", "throttled", "error", "unsupported", "missing")


def call_dir(c: Call) -> str:
    if not c.params:
        return f"{c.service}/{c.operation}"
    digest = hashlib.sha256(c.key.encode()).hexdigest()[:8]
    return f"{c.service}/{c.operation}__{digest}"


@dataclass
class Snapshot:
    account_id: str
    regions: list[str]
    home_region: str = "us-east-1"
    collected_at: str = ""
    data: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)

    def _entry(self, c: Call, region: str) -> dict[str, Any] | None:
        r = "global" if c.scope == "global" else region
        return self.data.get(c.key, {}).get(r)

    def status(self, c: Call, region: str = "") -> str:
        e = self._entry(c, region or self.home_region)
        return e["status"] if e else "missing"

    def get(self, c: Call, region: str = "") -> Any:
        e = self._entry(c, region or self.home_region)
        if not e or e["status"] != "ok":
            return None
        return e.get("value")

    def items(self, c: Call, region: str = "") -> list[Any]:
        v = self.get(c, region)
        if v is None:
            return []
        return v if isinstance(v, list) else [v]

    def per_item(self, c: Call, region: str = "") -> dict[str, Any]:
        e = self._entry(c, region or self.home_region)
        if not e or e["status"] != "ok":
            return {}
        return e.get("by_id", {})

    def regions_for(self, c: Call) -> list[str]:
        if c.scope == "global":
            return ["global"]
        if c.scope == "home":
            return [self.home_region]
        return list(self.regions)

    def put(self, c: Call, region: str, status: str, value: Any = None, by_id: dict[str, Any] | None = None,
            error: str = "") -> None:
        if status not in STATUSES:
            raise ValueError(status)
        entry: dict[str, Any] = {"status": status}
        if value is not None:
            entry["value"] = value
        if by_id is not None:
            entry["by_id"] = by_id
        if error:
            entry["error"] = error
        self.data.setdefault(c.key, {})["global" if c.scope == "global" else region] = entry

    def save(self, run_dir: Path) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        meta = {"account_id": self.account_id, "regions": self.regions, "home_region": self.home_region,
                "collected_at": self.collected_at}
        (run_dir / "snapshot.json").write_text(json.dumps({"meta": meta, "data": self.data}, indent=1, sort_keys=True))

    @classmethod
    def load(cls, run_dir: Path) -> Snapshot:
        raw = json.loads((Path(run_dir) / "snapshot.json").read_text())
        m = raw["meta"]
        return cls(m["account_id"], m["regions"], m.get("home_region", "us-east-1"), m.get("collected_at", ""),
                   raw["data"])

    @classmethod
    def from_fixture(cls, fixture: dict[str, Any]) -> Snapshot:
        snap = cls(fixture.get("account_id", "111122223333"), fixture.get("regions", ["us-east-1"]),
                   fixture.get("home_region", "us-east-1"), fixture.get("collected_at", "2026-01-15T12:00:00+00:00"))
        for key, by_region in fixture.get("data", {}).items():
            for region, entry in by_region.items():
                if not isinstance(entry, dict) or "status" not in entry:
                    entry = {"status": "ok", "value": entry}
                snap.data.setdefault(key, {})[region] = entry
        return snap
