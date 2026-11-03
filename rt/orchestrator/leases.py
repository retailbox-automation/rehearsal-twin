"""Leases on twins a rehearsal is using, and the reaper tick that honours them.

Why leases and not only a long TTL: a twin's life is not bounded tightly (live 03.11: 5.2 min to
ready plus 42 s to SSH; the orchestrator allows up to 15 min to ready plus up to ~18 min of
tracer phases), so a TTL long enough never to hit an active twin would leave crashed twins
alive for half an hour or more, and any shorter TTL can kill a slow but active rehearsal.
A lease names the twin before it exists (by its rt:<rid> tag), so even the instant between
create and the first id is covered, and a heartbeat thread renews every lease while the
orchestrator process lives. If the process dies, the heartbeat stops; after LEASE_STALE_S
the lease no longer protects and the normal TTL applies. The TTL stays as the floor: a twin
younger than the TTL is never reaped, lease or not.

    <data_dir>/twin-leases.json   {twin_rid: {rehearsal, instance_id, since, beat}}
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from rt.orchestrator.store import _atomic_write, utc_now

LEASE_FILE = "twin-leases.json"
LEASE_STALE_S = 300.0
HEARTBEAT_S = 60.0


def _ts(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return None


class Leases:
    def __init__(self, data_dir: Path | str, *, heartbeat_s: float = HEARTBEAT_S, start_heartbeat: bool = True):
        self.path = Path(data_dir) / LEASE_FILE
        self._lock = threading.Lock()
        self._held: set[str] = set()
        self._heartbeat_s = heartbeat_s
        self._start = start_heartbeat
        self._thread: threading.Thread | None = None

    # -- file ----------------------------------------------------------------
    def read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, data: dict) -> None:
        _atomic_write(self.path, json.dumps(data, sort_keys=True, indent=1).encode())

    # -- holder side (orchestrator) ------------------------------------------
    def take(self, twin_rid: str, rehearsal: str) -> None:
        with self._lock:
            data = self.read()
            now = utc_now()
            data[twin_rid] = {"rehearsal": rehearsal, "instance_id": None, "since": now, "beat": now}
            self._write(data)
            self._held.add(twin_rid)
        self._ensure_heartbeat()

    def bind(self, twin_rid: str, instance_id: str) -> None:
        with self._lock:
            data = self.read()
            if twin_rid in data:
                data[twin_rid].update(instance_id=instance_id, beat=utc_now())
                self._write(data)

    def drop(self, twin_rid: str) -> None:
        with self._lock:
            data = self.read()
            if data.pop(twin_rid, None) is not None:
                self._write(data)
            self._held.discard(twin_rid)

    def beat(self) -> None:
        with self._lock:
            if not self._held:
                return
            data = self.read()
            now = utc_now()
            for rid in self._held:
                if rid in data:
                    data[rid]["beat"] = now
            self._write(data)

    def held(self) -> set[str]:
        with self._lock:
            return set(self._held)

    def _ensure_heartbeat(self) -> None:
        if not self._start or (self._thread and self._thread.is_alive()):
            return

        def loop() -> None:
            while True:
                time.sleep(self._heartbeat_s)
                try:
                    self.beat()
                except OSError as e:  # a missed beat only shortens protection; say so
                    print(f"rt.orchestrator.leases: heartbeat failed: {type(e).__name__}", flush=True)

        self._thread = threading.Thread(target=loop, daemon=True, name="twin-lease-heartbeat")
        self._thread.start()

    # -- reaper side -----------------------------------------------------------
    def fresh(self, now: float | None = None, stale_s: float = LEASE_STALE_S) -> dict:
        now = time.time() if now is None else now
        out = {}
        for rid, lease in self.read().items():
            beat = _ts(lease.get("beat", ""))
            if beat is not None and now - beat <= stale_s:
                out[rid] = lease
        return out


def is_active(inst: dict, fresh: dict) -> bool:
    ids = {lease.get("instance_id") for lease in fresh.values() if lease.get("instance_id")}
    if inst.get("id") in ids:
        return True
    tags = set(inst.get("tags") or [])
    return any(f"rt:{rid}" in tags for rid in fresh)


def reap_tick(client, data_dir: Path | str, *, ttl_s: float, stale_s: float = LEASE_STALE_S,
              dry_run: bool = False, now: datetime | None = None) -> dict:
    """One reaper tick: delete rt-twin instances older than ttl_s that no fresh lease protects."""
    from rt.twin.reaper import reap

    now = now or datetime.now(timezone.utc)
    fresh = Leases(data_dir, start_heartbeat=False).fresh(now.timestamp(), stale_s)
    rows = reap(client, ttl_s, dry_run=dry_run, now=now, active=lambda inst: is_active(inst, fresh))
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["action"]] = counts.get(r["action"], 0) + 1
    return {"ts": utc_now(), "ttl_s": ttl_s, "dry_run": dry_run, "leases_fresh": len(fresh),
            "candidates": len(rows), "actions": counts,
            "deleted": [r["id"] for r in rows if r["action"] in ("deleted", "would-delete")]}


def append_log(data_dir: Path | str, line: dict) -> None:
    p = Path(data_dir) / "reaper.jsonl"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, sort_keys=True) + "\n")
