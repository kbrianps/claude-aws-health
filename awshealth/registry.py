from __future__ import annotations

import importlib
import json
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .model import CATEGORIES, SEVERITIES, Finding

SCOPES = ("regional", "global", "home")


@dataclass(frozen=True)
class Call:
    service: str
    operation: str
    params: tuple[tuple[str, Any], ...] = ()
    keep: str = ""
    result_key: str = ""
    scope: str = "regional"
    paginate: bool = True
    per_item: tuple[str, str, str, str] | None = None

    def __post_init__(self) -> None:
        if self.scope not in SCOPES:
            raise ValueError(f"bad scope {self.scope!r} for {self.service}:{self.operation}")
        if not self.keep:
            raise ValueError(f"{self.service}:{self.operation} must declare a keep projection")

    @property
    def kwargs(self) -> dict[str, Any]:
        return {k: json.loads(v) for k, v in self.params}

    @property
    def key(self) -> str:
        suffix = "" if not self.params else "?" + "&".join(f"{k}={v}" for k, v in self.params)
        return f"{self.service}:{self.operation}{suffix}"


def call(service: str, operation: str, keep: str, *, params: dict[str, Any] | None = None, result_key: str = "",
         scope: str = "regional", paginate: bool = True, per_item: tuple[str, str, str, str] | None = None) -> Call:
    frozen = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in (params or {}).items()))
    return Call(service, operation, frozen, keep, result_key, scope, paginate, per_item)


@dataclass
class CheckSpec:
    id: str
    category: str
    severity: str
    title: dict[str, str]
    requires: list[Call]
    fn: Callable[..., list[Finding]]
    catalog_ids: list[str] = field(default_factory=list)
    needs_metrics: bool = False


REGISTRY: dict[str, CheckSpec] = {}


def check(*, id: str, category: str, severity: str, title: dict[str, str], requires: list[Call],
          catalog_ids: list[str] | None = None, needs_metrics: bool = False):
    if category not in CATEGORIES or severity not in SEVERITIES:
        raise ValueError(f"bad category/severity on {id}")
    if "en" not in title or "pt-BR" not in title:
        raise ValueError(f"{id} needs en and pt-BR titles")

    def deco(fn):
        if id in REGISTRY:
            raise ValueError(f"duplicate check id {id}")
        REGISTRY[id] = CheckSpec(id, category, severity, title, list(requires), fn, catalog_ids or [], needs_metrics)
        return fn

    return deco


def load_checks() -> dict[str, CheckSpec]:
    from . import checks

    for mod in pkgutil.iter_modules(checks.__path__):
        importlib.import_module(f"{checks.__name__}.{mod.name}")
    return REGISTRY


def required_calls(specs: dict[str, CheckSpec] | None = None) -> list[Call]:
    specs = specs or load_checks()
    seen: dict[str, Call] = {}
    for spec in specs.values():
        for c in spec.requires:
            prev = seen.get(c.key)
            if prev and prev != c:
                raise ValueError(f"conflicting declarations for {c.key}: {prev} vs {c}")
            seen[c.key] = c
    return list(seen.values())
