from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
CATEGORIES = ("cost", "security", "zombie", "outdated", "errors", "resilience", "governance", "quota")


@dataclass
class Claim:
    source: str
    path: str
    value: Any


@dataclass
class Finding:
    check_id: str
    resource: str
    severity: str
    category: str
    region: str
    text: dict[str, dict[str, str]]
    claims: list[Claim] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    monthly_usd: float | None = None
    usd_calc: str = ""
    deadline: str = ""
    owner_question: dict[str, str] = field(default_factory=dict)
    verify: list[str] = field(default_factory=list)
    confidence: str = "high"
    source: str = "awshealth"
    status: str = "open"
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r} in {self.check_id}")
        if self.category not in CATEGORIES:
            raise ValueError(f"bad category {self.category!r} in {self.check_id}")
        if "en" not in self.text or "title" not in self.text["en"]:
            raise ValueError(f"{self.check_id} needs text['en']['title']")
        if not self.resources:
            self.resources = [self.resource]

    @property
    def uid(self) -> str:
        digest = hashlib.sha256(f"{self.check_id}|{self.region}|{self.resource}".encode()).hexdigest()[:12]
        return f"{self.check_id}:{digest}"

    def t(self, key: str, lang: str = "en") -> str:
        return self.text.get(lang, {}).get(key) or self.text["en"].get(key, "")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["uid"] = self.uid
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        d = {k: v for k, v in d.items() if k != "uid"}
        d["claims"] = [Claim(**c) for c in d.get("claims", [])]
        return cls(**d)
