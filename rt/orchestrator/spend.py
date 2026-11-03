"""Spend guard for judge mode: pause runs without the token when the account's pending charges reach a cap.

Reads `pending_charges` from GET /v2/account at most once per RT_SPEND_CACHE_S (default 600 s),
failures included, so the screen's polling never turns into API traffic. Fails closed: when the
API cannot be read or the value is not a finite non-negative number, judge runs are paused;
runs with the token are not affected (the caller decides that).
The cap is RT_SPEND_CAP_USD (default 150), read when the service starts; an unreadable cap
counts as 0, which pauses judge runs.
"""
from __future__ import annotations

import math
import threading
import time
from typing import Any, Callable

from rt.orchestrator.store import utc_now

DEFAULT_CAP_USD = 150.0
DEFAULT_CACHE_S = 600.0


def parse_pending(account: Any) -> float:
    """pending_charges as a finite non-negative float, or ValueError."""
    if not isinstance(account, dict):
        raise ValueError("no account object")
    raw = account.get("pending_charges")
    if isinstance(raw, bool) or raw is None:
        raise ValueError("pending_charges missing")
    value = float(raw)  # numbers or numeric strings; anything else raises ValueError/TypeError
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"pending_charges not usable: {raw!r}")
    return value


def read_pending(client) -> float:
    _, body = client.request("GET", "/account")
    try:
        return parse_pending((body or {}).get("account"))
    except TypeError:
        raise ValueError("pending_charges not a number") from None


class SpendGuard:
    def __init__(self, client, cap_usd: float, *, cache_s: float = DEFAULT_CACHE_S,
                 clock: Callable[[], float] = time.monotonic):
        self.client = client
        self.cap = cap_usd
        self.cache_s = cache_s
        self.clock = clock
        self._lock = threading.Lock()
        self._at: float | None = None
        self._state: dict = {}
        self.reads = 0

    def check(self) -> dict:
        """{spend_pending, spend_cap, checked_at, paused_reason}; paused_reason None means judge runs may start."""
        with self._lock:
            now = self.clock()
            if self._at is None or now - self._at >= self.cache_s:
                self._at = now
                self.reads += 1
                try:
                    pending = read_pending(self.client)
                    reason = (f"spend cap: pending ${pending:.2f} ≥ cap ${self.cap:.2f}"
                              if pending >= self.cap else None)
                    self._state = {"spend_pending": round(pending, 4), "paused_reason": reason}
                except Exception as e:  # fail closed: unknown spend pauses judge runs
                    self._state = {"spend_pending": None,
                                   "paused_reason": f"spend unknown: {type(e).__name__}"}
                self._state["checked_at"] = utc_now()
            return {**self._state, "spend_cap": self.cap}
