"""Warm pool of at most two ready twins made from one snapshot.

take() hands out the oldest ready twin and starts a refill in the background.
A pooled twin idle longer than max_idle_s is destroyed and replaced, so a
twin that is handed out still has most of the reaper TTL ahead of it
(reaper default 15 min, pool default 10 min idle).
"""
from __future__ import annotations

import sys
import threading
import time
from collections import deque
from typing import Callable

MAX_POOL = 2
DEFAULT_MAX_IDLE_S = 10 * 60


def _thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True).start()


class WarmPool:
    def __init__(self, factory: Callable[[], object], size: int = MAX_POOL, *,
                 max_idle_s: float = DEFAULT_MAX_IDLE_S, clock: Callable[[], float] = time.monotonic,
                 spawn: Callable[[Callable[[], None]], None] = _thread):
        if not 0 < size <= MAX_POOL:
            raise ValueError(f"pool size must be 1..{MAX_POOL}")
        self.factory = factory
        self.size = size
        self.max_idle_s = max_idle_s
        self.clock = clock
        self.spawn = spawn
        self._ready: deque[tuple[float, object]] = deque()
        self._pending = 0
        self._closed = False
        self._cv = threading.Condition()
        self.errors: list[str] = []

    def ready_count(self) -> int:
        with self._cv:
            return len(self._ready)

    def fill(self) -> None:
        with self._cv:
            if self._closed:
                return
            n = self.size - len(self._ready) - self._pending
            self._pending += max(0, n)
        for _ in range(max(0, n)):
            self.spawn(self._make_one)

    def _make_one(self) -> None:
        twin = None
        try:
            twin = self.factory()
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"
            self.errors.append(msg)
            print(f"rt.twin.pool: create failed: {msg}", file=sys.stderr)
        with self._cv:
            self._pending -= 1
            if twin is not None and not self._closed:
                self._ready.append((self.clock(), twin))
                self._cv.notify_all()
                return
        if twin is not None:  # pool closed while it was being made
            _destroy(twin)

    def _evict_expired(self) -> list[object]:
        now = self.clock()
        stale = []
        with self._cv:
            while self._ready and now - self._ready[0][0] > self.max_idle_s:
                stale.append(self._ready.popleft()[1])
        return stale

    def take(self, timeout: float = 900.0) -> object:
        for twin in self._evict_expired():
            _destroy(twin)
        self.fill()
        deadline = time.monotonic() + timeout
        with self._cv:
            while not self._ready:
                left = deadline - time.monotonic()
                if left <= 0 or self._closed:
                    raise TimeoutError("no ready twin in the pool")
                self._cv.wait(left)
            _, twin = self._ready.popleft()
        self.fill()
        return twin

    def close(self) -> None:
        with self._cv:
            self._closed = True
            twins = [t for _, t in self._ready]
            self._ready.clear()
            self._cv.notify_all()
        for twin in twins:
            _destroy(twin)


def _destroy(twin: object) -> None:
    try:
        twin.destroy()  # type: ignore[attr-defined]
    except Exception as e:
        print(f"rt.twin.pool: destroy {getattr(twin, 'id', '?')} failed: {type(e).__name__}: {e}", file=sys.stderr)


def twin_factory(snapshot_id: str, vpc_id: str, plan: str, *, client, ssh_factory: Callable[[], object],
                 ready_timeout_s: float = 900.0) -> Callable[[], object]:
    """Factory for WarmPool: create a twin from the snapshot and wait until it answers SSH.

    A twin that fails to become ready is destroyed before the error propagates.
    """
    from rt.twin.lifecycle import Twin, new_rid

    def make() -> object:
        twin = Twin.create(snapshot_id, new_rid(), vpc_id, plan, client=client, ssh=ssh_factory())
        try:
            return twin.wait_ready(timeout=ready_timeout_s)
        except Exception:
            _destroy(twin)
            raise
    return make
