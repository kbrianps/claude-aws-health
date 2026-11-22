from __future__ import annotations

import threading
import time

DEFAULT_RATE = 5.0
DEFAULT_BURST = 10
SERVICE_LIMITS = {"cloudtrail": (1.0, 1)}


class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rate
            time.sleep(wait)


class RateLimiter:
    def __init__(self, rate: float = DEFAULT_RATE, burst: int = DEFAULT_BURST,
                 service_limits: dict[str, tuple[float, int]] | None = None):
        self.rate = rate
        self.burst = burst
        self.service_limits = SERVICE_LIMITS if service_limits is None else service_limits
        self.buckets: dict[tuple[str, str], TokenBucket] = {}
        self.lock = threading.Lock()

    def bucket(self, region: str, service: str) -> TokenBucket:
        with self.lock:
            b = self.buckets.get((region, service))
            if b is None:
                rate, burst = self.service_limits.get(service, (self.rate, self.burst))
                b = self.buckets[(region, service)] = TokenBucket(rate, burst)
            return b

    def acquire(self, region: str, service: str) -> None:
        self.bucket(region, service).acquire()
