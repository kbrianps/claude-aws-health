from __future__ import annotations

import ipaddress
import json
import logging
import os
import sys
import threading
import time
import urllib.request
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import jmespath
from botocore import xform_name
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, UnknownEndpointError

from .. import __version__
from ..calls_core import CALLER, ENABLED_REGIONS, IP_RANGES
from ..registry import Call, CheckSpec, load_checks, required_calls
from ..snapshot import Snapshot
from .guard import AllowlistViolation, Guard
from .ratelimit import RateLimiter

HOME_REGION = "us-east-1"
IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
IP_SERVICES = ("EC2", "AMAZON", "GLOBALACCELERATOR")
MAX_IDS = 500
MAX_WORKERS = 6
ACCOUNT_PLACEHOLDER = "{account}"
_END = object()

ClientFactory = Callable[[Any, str, str, Config], Any]


def default_client_factory(session: Any, service: str, region: str, config: Config) -> Any:
    return session.client(service, region_name=region, config=config)


def classify_code(code: str, regional: bool) -> str:
    if code.startswith(("AccessDenied", "AuthorizationError")) or code == "UnauthorizedOperation":
        return "denied"
    if code.startswith(("Throttling", "TooManyRequests")) or code == "RequestLimitExceeded":
        return "throttled"
    if code in ("OptInRequired", "SubscriptionRequiredException", "InvalidAction", "InvalidAccessException"):
        return "unsupported"
    if regional and code.startswith("UnrecognizedClient"):
        return "unsupported"
    return "error"


def classify(exc: BaseException, regional: bool) -> tuple[str, str]:
    if isinstance(exc, AllowlistViolation):
        return "error", "allowlist"
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code") or "ClientError"
        return classify_code(code, regional), code
    if isinstance(exc, (EndpointConnectionError, UnknownEndpointError)):
        return "unsupported", type(exc).__name__
    return "error", type(exc).__name__


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return None
    return value


def merge_pages(pages: list[dict[str, Any]], result_key: str) -> dict[str, Any]:
    if not pages:
        return {}
    merged = dict(pages[0])
    keys = [result_key] if result_key else [k for k, v in pages[0].items() if isinstance(v, list)]
    for k in keys:
        merged[k] = [item for page in pages for item in page.get(k) or []]
    return merged


def _ids(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return list(dict.fromkeys(str(v) for v in value if isinstance(v, (str, int)) and not isinstance(v, bool)))


def _param_sets(value: Any, param: str) -> list[tuple[str, dict[str, Any]]]:
    if param != "*":
        return [(i, {param: i}) for i in _ids(value)]
    if value is None:
        return []
    out: dict[str, dict[str, Any]] = {}
    for v in value if isinstance(value, list) else [value]:
        if isinstance(v, dict) and v and all(isinstance(x, (str, int)) for x in v.values()):
            out["|".join(str(v[k]) for k in sorted(v))] = dict(v)
    return list(out.items())


def fetch_ip_ranges() -> list[dict[str, str]]:
    with urllib.request.urlopen(IP_RANGES_URL, timeout=20) as resp:
        doc = json.load(resp)
    best: dict[str, dict[str, str]] = {}
    for p in doc.get("prefixes", []):
        if p.get("service") not in IP_SERVICES or not p.get("ip_prefix"):
            continue
        cidr = p["ip_prefix"]
        if cidr not in best or best[cidr]["service"] == "AMAZON":
            best[cidr] = {"cidr": cidr, "region": p.get("region", ""), "service": p["service"]}
    return sorted(best.values(), key=lambda r: ipaddress.ip_network(r["cidr"], strict=False))


METRIC_OPS = {"GetMetricData", "GetMetricStatistics", "GetMetricWidgetImage"}


def gather(specs: dict[str, CheckSpec], metrics: bool, cost: bool) -> tuple[list[Call], list[Call], dict[str, Call]]:
    calls = (required_calls(specs) if specs else []) + [IP_RANGES]
    active = {c.key for s in specs.values() if metrics or not s.needs_metrics for c in s.requires}
    active |= {IP_RANGES.key}
    by_op: dict[tuple[str, str], list[Call]] = {}
    for c in calls:
        by_op.setdefault((c.service, c.operation), []).append(c)
    parents: dict[str, Call] = {}
    for c in calls:
        if c.per_item:
            candidates = by_op.get((c.per_item[0], c.per_item[1]))
            if not candidates:
                raise ValueError(f"{c.key} needs parent {c.per_item[0]}:{c.per_item[1]}, which no check declares")
            parents[c.key] = sorted(candidates, key=lambda p: bool(p.params))[0]

    def skip(c: Call) -> bool:
        if c.key not in active:
            return True
        if c.service == "cloudwatch" and c.operation in METRIC_OPS and not metrics:
            return True
        if c.service == "ce" and not cost:
            return True
        return c.key in parents and skip(parents[c.key])

    run = [c for c in calls if not skip(c)]
    skipped = [c for c in calls if skip(c)]
    return run, skipped, parents


def phases(calls: list[Call], parents: dict[str, Call]) -> list[list[Call]]:
    def depth(c: Call) -> int:
        return depth(parents[c.key]) + 1 if c.key in parents else 0

    out: dict[int, list[Call]] = {}
    for c in calls:
        out.setdefault(depth(c), []).append(c)
    return [out[d] for d in sorted(out)]


class Collector:
    def __init__(self, session: Any, factory: ClientFactory, run_dir: Path, guard: Guard, limiter: RateLimiter):
        self.session = session
        self.factory = factory
        self.guard = guard
        self.limiter = limiter
        self.ledger = run_dir / "ledger.jsonl"
        self.config = Config(retries={"mode": "adaptive", "max_attempts": 5}, read_timeout=30,
                             user_agent_extra=f"awshealth/{__version__}")
        self.clients: dict[tuple[str, str], Any] = {}
        self.lock = threading.Lock()
        self.account = ""
        self.parents: dict[str, Call] = {}
        self.capped: list[dict[str, Any]] = []
        self.pending: Counter[str] = Counter()
        self.done: dict[str, Counter[str]] = {}
        self.requests = 0
        self.blocked = 0

    def client(self, service: str, region: str) -> Any:
        client_region = HOME_REGION if region == "global" else region
        with self.lock:
            c = self.clients.get((service, client_region))
            if c is None:
                c = self.factory(self.session, service, client_region, self.config)
                self.guard.install(c.meta.events)
                self.clients[(service, client_region)] = c
            return c

    def log(self, c: Call, region: str, status: str, ms: int) -> None:
        line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "service": c.service,
                           "operation": c.operation, "region": region, "status": status, "ms": ms,
                           "throttled": status == "throttled"})
        with self.lock:
            self.requests += 1
            with self.ledger.open("a") as f:
                f.write(line + "\n")

    def timed(self, c: Call, region: str, fn: Callable[[], Any], limited: bool = True) -> Any:
        if limited:
            self.limiter.acquire(region, c.service)
        t0 = time.monotonic()
        try:
            result = fn()
        except Exception as exc:
            status = "blocked" if isinstance(exc, AllowlistViolation) else classify(exc, c.scope == "regional")[0]
            if status == "blocked":
                with self.lock:
                    self.blocked += 1
            self.log(c, region, status, int((time.monotonic() - t0) * 1000))
            raise
        if result is not _END:
            self.log(c, region, "ok", int((time.monotonic() - t0) * 1000))
        return result

    def kwargs(self, c: Call) -> dict[str, Any]:
        return {k: self.account if v == ACCOUNT_PLACEHOLDER else v for k, v in c.kwargs.items()}

    def request(self, c: Call, region: str, kwargs: dict[str, Any]) -> Any:
        client = self.client(c.service, region)
        op = xform_name(c.operation)
        if c.paginate and client.can_paginate(op):
            it = iter(client.get_paginator(op).paginate(**kwargs))
            pages = []
            while (page := self.timed(c, region, lambda: next(it, _END))) is not _END:
                pages.append(page)
            response = merge_pages(pages, c.result_key)
        else:
            response = self.timed(c, region, lambda: getattr(client, op)(**kwargs))
        return jmespath.search(c.keep, _plain(response))

    def put(self, snap: Snapshot, c: Call, region: str, status: str, **kw: Any) -> None:
        with self.lock:
            snap.put(c, region, status, **kw)

    def run_per_item(self, snap: Snapshot, c: Call, region: str) -> None:
        parent = self.parents[c.key]
        parent_status = snap.status(parent, region)
        if parent_status != "ok":
            self.put(snap, c, region, "missing", error=f"parent {parent_status}")
            return
        _, _, id_path, param = c.per_item
        source = snap.per_item(parent, region) if parent.per_item else snap.get(parent, region)
        ids = _param_sets(jmespath.search(id_path, source), param)
        if len(ids) > MAX_IDS:
            with self.lock:
                self.capped.append({"call": c.key, "region": region, "ids": len(ids), "kept": MAX_IDS})
            ids = ids[:MAX_IDS]
        base = self.kwargs(c)
        by_id: dict[str, Any] = {}
        failed: list[tuple[str, str]] = []
        for i, extra in ids:
            try:
                by_id[i] = self.request(c, region, {**base, **extra})
            except ClientError as exc:
                status, code = classify(exc, c.scope == "regional")
                by_id[i] = {"__error__": code}
                failed.append((status, code))
        if ids and len(failed) == len(ids) and {s for s, _ in failed} == {"denied"}:
            self.put(snap, c, region, "denied", error=failed[0][1])
        else:
            self.put(snap, c, region, "ok", by_id=by_id)

    def run_unit(self, snap: Snapshot, c: Call, region: str) -> None:
        status = "ok"
        try:
            if (c.service, c.operation) == ("aws", "IpRanges"):
                value = self.timed(c, region, fetch_ip_ranges, limited=False)
                self.put(snap, c, region, "ok", value=jmespath.search(c.keep, value))
            elif c.per_item:
                self.run_per_item(snap, c, region)
            else:
                self.put(snap, c, region, "ok", value=self.request(c, region, self.kwargs(c)))
            status = snap.status(c, region)
        except Exception as exc:
            status, error = classify(exc, c.scope == "regional")
            self.put(snap, c, region, status, error=error)
        self.finish(c.service, status)

    def finish(self, service: str, status: str) -> None:
        with self.lock:
            self.done.setdefault(service, Counter())[status] += 1
            self.pending[service] -= 1
            if self.pending[service] == 0:
                counts = ", ".join(f"{k} {v}" for k, v in sorted(self.done[service].items()))
                print(f"awshealth: {service} done ({counts})", file=sys.stderr)


def collect(profile: str | None, regions: list[str] | None, run_dir: Path, metrics: bool = False, cost: bool = False,
            *, session: Any = None, client_factory: ClientFactory | None = None,
            specs: dict[str, CheckSpec] | None = None) -> Snapshot:
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o700)

    run, skipped, parents = gather(load_checks() if specs is None else specs, metrics, cost)
    allowed = {(c.service, c.operation) for c in run} | {(CALLER.service, CALLER.operation),
                                                         (ENABLED_REGIONS.service, ENABLED_REGIONS.operation)}
    guard = Guard(allowed)
    session = session or boto3.Session(profile_name=profile)
    guard.install(session.events)
    col = Collector(session, client_factory or default_client_factory, run_dir, guard, RateLimiter())
    col.parents = parents

    caller = col.request(CALLER, HOME_REGION, {})
    col.account = caller["account"]
    region_entry: tuple[str, Any, str] | None = None
    if regions:
        region_list = list(regions)
    else:
        try:
            region_list = sorted(col.request(ENABLED_REGIONS, HOME_REGION, {}) or [])
            region_entry = ("ok", region_list, "")
        except Exception as exc:
            status, error = classify(exc, False)
            region_entry = (status, None, error)
            region_list = []
        if not region_list:
            print(f"awshealth: could not list enabled regions, using {HOME_REGION} only", file=sys.stderr)
            region_list = [HOME_REGION]

    snap = Snapshot(col.account, region_list, HOME_REGION, collected_at)
    snap.put(CALLER, HOME_REGION, "ok", value=caller)
    if region_entry:
        snap.put(ENABLED_REGIONS, HOME_REGION, region_entry[0], value=region_entry[1], error=region_entry[2])
    for c in skipped:
        for r in snap.regions_for(c):
            snap.put(c, r, "missing", error="opt-in")

    for c in run:
        col.pending[c.service] += len(snap.regions_for(c))
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for group in phases(run, parents):
            list(pool.map(lambda unit: col.run_unit(snap, *unit), [(c, r) for c in group for r in snap.regions_for(c)]))

    snap.save(run_dir)
    counts = Counter(e["status"] for by_region in snap.data.values() for e in by_region.values())
    summary = {
        "account_id": snap.account_id,
        "regions": snap.regions,
        "home_region": snap.home_region,
        "collected_at": collected_at,
        "duration_s": round(time.monotonic() - started, 2),
        "requests": col.requests,
        "calls": col.requests,
        "blocked": col.blocked,
        "counts": dict(sorted(counts.items())),
        "capped": col.capped,
        "opt_in_skipped": sorted(c.key for c in skipped),
    }
    (run_dir / "collect.json").write_text(json.dumps(summary, indent=1))
    return snap
