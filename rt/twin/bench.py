"""Lifecycle bench: create from snapshot -> ready -> ssh echo -> delete -> absent from the list.

Runs the cycles one after another (at most one live twin at a time) and writes
every observation plus p50/p95 to a JSON file.
"""
from __future__ import annotations

import json
import math
import time
from pathlib import Path

from rt.twin.lifecycle import DEFAULT_PLAN, DEFAULT_REGION, SSH, Twin, new_rid
from rt.twin.vultr import Vultr, utc_now

MAX_BENCH_N = 20
PHASES = ("create_s", "ready_s", "echo_s", "destroy_s", "total_s")


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return s[max(0, math.ceil(q * len(s)) - 1)]


def summarize(values: list[float]) -> dict:
    return {"p50": percentile(values, 0.50), "p95": percentile(values, 0.95),
            "min": min(values) if values else None, "max": max(values) if values else None}


def run_bench(n: int, snapshot_id: str, vpc_id: str, out_path: str, *, plan: str = DEFAULT_PLAN,
              region: str = DEFAULT_REGION, client: Vultr, ssh: SSH, ready_timeout_s: float = 900.0,
              poll_s: float = 5.0) -> dict:
    if not 1 <= n <= MAX_BENCH_N:
        raise ValueError(f"--n must be 1..{MAX_BENCH_N}")
    started = utc_now()
    observations = []
    calls: list[str] = []
    orig_timing = client.timing

    def tee(line: str) -> None:
        calls.append(line)
        orig_timing(line)

    client.timing = tee
    try:
        for i in range(n):
            observations.append(_one(i, snapshot_id, vpc_id, plan, region, client, ssh, ready_timeout_s, poll_s, calls))
    finally:
        client.timing = orig_timing
    ok = [o for o in observations if not o.get("error")]
    result = {
        "kind": "twin_lifecycle", "started_at": started, "finished_at": utc_now(),
        "n": n, "ok": len(ok), "plan": plan, "region": region, "snapshot_id": snapshot_id,
        "observations": observations,
        "summary": {k: summarize([o[k] for o in ok if o.get(k) is not None]) for k in PHASES},
    }
    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def _one(i, snapshot_id, vpc_id, plan, region, client, ssh, ready_timeout_s, poll_s, calls) -> dict:
    first_call = len(calls)
    obs: dict = {"i": i, "at": utc_now(), "instance_id": None, "echo_ok": False, "absent": False}
    t0 = time.monotonic()
    twin = Twin.create(snapshot_id, new_rid(), vpc_id, plan, region=region, client=client, ssh=ssh)
    obs["instance_id"] = twin.id
    obs["create_s"] = round(time.monotonic() - t0, 3)
    try:
        twin.wait_ready(timeout=ready_timeout_s, poll_s=poll_s)
        obs["ready_s"] = round(time.monotonic() - t0, 3)
        t1 = time.monotonic()
        rc, out, _ = twin.exec(["echo", "ok"], timeout=30)
        obs["echo_s"] = round(time.monotonic() - t1, 3)
        obs["echo_ok"] = rc == 0 and out.strip() == "ok"
    except Exception as e:
        obs["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            obs["destroy_s"] = twin.destroy(poll_s=min(poll_s, 3.0))
            obs["absent"] = True
        except Exception as e:
            obs["error"] = (obs.get("error", "") + f" | destroy: {type(e).__name__}: {e}").strip(" |")
    obs["total_s"] = round(time.monotonic() - t0, 3)
    obs["api_calls"] = len(calls) - first_call
    return obs
