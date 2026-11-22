"""HTTP 429 / rate-limit helpers shared by every outbound client. Stdlib only.

* ``parse_retry_after`` understands both forms of ``Retry-After`` (delta seconds
  and HTTP-date) and caps the wait, so a hostile target cannot stall a scan.
* ``backoff_delay`` is the wait to use for attempt ``n`` when no header is sent.
* ``RateLimitStats`` records what happened so reports can say that results may
  be incomplete because the target throttled the scanner.
"""
from __future__ import annotations

import datetime as dt
import email.utils
import threading
from dataclasses import dataclass, field

RETRY_STATUSES = frozenset({429, 503})  # 503 only retried when it carries Retry-After
DEFAULT_MAX_RETRIES = 3
DEFAULT_MAX_WAIT = 30.0


def parse_retry_after(value: str | None, *, cap: float = DEFAULT_MAX_WAIT,
                      now: dt.datetime | None = None) -> float | None:
    """Seconds to wait from a Retry-After header value, or None if absent/invalid."""
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        secs = float(value)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        secs = (when - (now or dt.datetime.now(dt.timezone.utc))).total_seconds()
    if secs != secs:  # NaN
        return None
    return max(0.0, min(secs, cap))


def backoff_delay(attempt: int, *, base: float = 1.0, cap: float = DEFAULT_MAX_WAIT) -> float:
    """Exponential backoff (1, 2, 4, ... seconds) for attempt 0, 1, 2, ..."""
    return min(cap, base * (2 ** max(0, attempt)))


def should_retry(status: int, retry_after: str | None) -> bool:
    return status == 429 or (status == 503 and retry_after is not None)


def wait_for(status: int, retry_after: str | None, attempt: int, *, cap: float = DEFAULT_MAX_WAIT) -> float:
    parsed = parse_retry_after(retry_after, cap=cap)
    return parsed if parsed is not None else backoff_delay(attempt, cap=cap)


@dataclass
class RateLimitStats:
    """Thread-safe counters of throttling seen during a scan."""

    throttled: int = 0           # 429/503 responses received (including retried ones)
    retries: int = 0             # retries performed
    gave_up: int = 0             # requests still throttled after the last retry
    waited_seconds: float = 0.0
    urls: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def record(self, url: str, *, retried: bool, waited: float = 0.0, gave_up: bool = False) -> None:
        with self._lock:
            self.throttled += 1
            self.retries += int(retried)
            self.gave_up += int(gave_up)
            self.waited_seconds += waited
            if gave_up and url not in self.urls and len(self.urls) < 50:
                self.urls.append(url)

    def as_dict(self) -> dict:
        return {"throttled": self.throttled, "retries": self.retries, "gave_up": self.gave_up,
                "waited_seconds": round(self.waited_seconds, 2), "urls": list(self.urls)}

    def red_flag(self) -> str | None:
        if self.gave_up:
            return (f"Target rate-limited the scanner (HTTP 429): {self.gave_up} request(s) were still "
                    f"throttled after {DEFAULT_MAX_RETRIES} retries; results for those URLs are incomplete.")
        if self.throttled:
            return (f"Target throttled {self.throttled} request(s) (HTTP 429/503); all succeeded after "
                    f"backing off for {self.waited_seconds:.1f}s in total.")
        return None
