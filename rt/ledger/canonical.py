"""Canonical JSON form of a ledger and its sha256.

Volatile values (timestamps, run ids, pids, measured wall time and memory) are
removed before hashing, so the same side effects always give the same hash and
the order of keys never matters.
"""
from __future__ import annotations

import hashlib
import json

VOLATILE_KEYS = frozenset({
    "ledger_sha256",
    "generated_at",
    "taken_at",
    "started_at",
    "ended_at",
    "ts",
    "time",
    "rid",
    "run_id",
    "unit_name",
    "pid",
    "wall_s",
    "peak_mem_mb",
    "duration_ms",
    "output",
})


def strip_volatile(obj):
    if isinstance(obj, dict):
        return {k: strip_volatile(v) for k, v in obj.items() if k not in VOLATILE_KEYS}
    if isinstance(obj, (list, tuple)):
        return [strip_volatile(v) for v in obj]
    return obj


def canonical_bytes(obj) -> bytes:
    return json.dumps(
        strip_volatile(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def ledger_sha256(ledger) -> str:
    return hashlib.sha256(canonical_bytes(ledger)).hexdigest()


def seal(ledger: dict) -> dict:
    """Return a copy of the ledger with `ledger_sha256` set."""
    out = dict(ledger)
    out["ledger_sha256"] = ledger_sha256(ledger)
    return out


def dumps(obj) -> str:
    """Human-readable, stable JSON for files on disk."""
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
