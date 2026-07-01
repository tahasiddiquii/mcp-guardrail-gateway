"""A small deterministic token-bucket rate limiter.

The clock is injectable so tests are deterministic and do not sleep.
"""

from __future__ import annotations

from collections.abc import Callable


class RateLimiter:
    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or __import__("time").monotonic
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)

    def allow(self, key: str, per_minute: int) -> bool:
        if per_minute <= 0:
            return False
        capacity = float(per_minute)
        refill_per_sec = capacity / 60.0
        now = self._clock()
        tokens, last = self._buckets.get(key, (capacity, now))
        tokens = min(capacity, tokens + (now - last) * refill_per_sec)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True
        self._buckets[key] = (tokens, now)
        return False
