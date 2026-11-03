"""Compare the twin ledger (prediction) with the production ledger (what happened).

Normalization: paths (normalized, no mtime), row changes per table (+/-),
egress grouped by (method, host, path). Anything that differs is a surprise.
"""
from __future__ import annotations

import json
from collections import Counter

from .scope import DDL_FLAGS, FILE_OPS, DIR_OPS, ScopeError, norm_host, norm_path, norm_table

ROW_KEYS = ("inserted", "deleted", "updated")


def _np(p):
    try:
        return norm_path(p)
    except ScopeError:
        return str(p)


def _nh(h):
    try:
        return norm_host(h)
    except ScopeError:
        return str(h or "?")


def normalize(ledger: dict) -> dict:
    files = ledger.get("files") or {}
    dirs = ledger.get("dirs") or {}
    rows = {}
    for t, ch in (ledger.get("rows") or {}).items():
        entry = {k: int(ch.get(k) or 0) for k in ROW_KEYS}
        for flag in DDL_FLAGS:
            if ch.get(flag):
                entry[flag] = True
        if any(entry.values()):
            rows[norm_table(t)] = entry
    egress = Counter()
    for e in ledger.get("egress") or []:
        method = e.get("method") or (e.get("kind") or "tcp").upper()
        path = e.get("path") or ("" if not e.get("method") else "/")
        egress[(method, _nh(e.get("host")), path)] += 1
    limits = ledger.get("limits") or {}
    return {
        "files": {op: sorted({_np(p) for p in files.get(op) or []}) for op in FILE_OPS},
        "dirs": {op: sorted({_np(p) for p in dirs.get(op) or []}) for op in DIR_OPS},
        "rows": {k: rows[k] for k in sorted(rows)},
        "egress": [{"method": m, "host": h, "path": p, "count": n}
                   for (m, h, p), n in sorted(egress.items())],
        "canaries_touched": sorted(c.get("id") for c in ledger.get("canaries") or []
                                   if c.get("touched") or c.get("exfil_attempt")),
        "exit": ledger.get("exit"),
        "oom": bool(limits.get("oom")),
    }


def count_effects(norm: dict) -> int:
    n = sum(len(v) for v in norm["files"].values())
    n += sum(len(v) for v in norm["dirs"].values())
    n += sum(sum(ch.get(k, 0) for k in ROW_KEYS) for ch in norm["rows"].values())
    n += sum(e["count"] for e in norm["egress"])
    return n


def _surprise(kind, item, predicted, happened, reason):
    return {"kind": kind, "item": item, "predicted": predicted, "happened": happened, "reason": reason}


def compare(twin: dict, prod: dict) -> dict:
    p = normalize(twin)
    h = normalize(prod)
    surprises = []

    for group, ops in (("files", FILE_OPS), ("dirs", DIR_OPS)):
        kind = "file" if group == "files" else "dir"
        for op in ops:
            ps, hs = set(p[group][op]), set(h[group][op])
            for path in sorted(hs - ps):
                surprises.append(_surprise(kind, path, None, op,
                                           "happened on production, not predicted by the twin"))
            for path in sorted(ps - hs):
                surprises.append(_surprise(kind, path, op, None,
                                           "predicted by the twin, did not happen on production"))

    for t in sorted(set(p["rows"]) | set(h["rows"])):
        pv, hv = p["rows"].get(t), h["rows"].get(t)
        if pv != hv:
            surprises.append(_surprise("rows", t, pv, hv, "row changes differ"))

    pe = {(e["method"], e["host"], e["path"]): e["count"] for e in p["egress"]}
    he = {(e["method"], e["host"], e["path"]): e["count"] for e in h["egress"]}
    for key in sorted(set(pe) | set(he)):
        if pe.get(key, 0) != he.get(key, 0):
            m, host, path = key
            surprises.append(_surprise("egress", f"{m} {host}{path}", pe.get(key, 0), he.get(key, 0),
                                       "outbound call count differs"))

    if p["canaries_touched"] != h["canaries_touched"]:
        surprises.append(_surprise("canary", "canaries", p["canaries_touched"], h["canaries_touched"],
                                   "decoys touched differ"))
    if p["exit"] != h["exit"]:
        surprises.append(_surprise("exit", "exit", p["exit"], h["exit"], "exit code differs"))
    if p["oom"] != h["oom"]:
        surprises.append(_surprise("limits", "oom", p["oom"], h["oom"], "out-of-memory kill differs"))

    surprises.sort(key=lambda s: json.dumps(s, sort_keys=True))
    return {
        "predicted": p,
        "happened": h,
        "surprises": surprises,
        "counts": {
            "predicted": count_effects(p),
            "happened": count_effects(h),
            "surprises": len(surprises),
        },
        "match": not surprises,
        "twin_ledger_sha256": twin.get("ledger_sha256"),
        "prod_ledger_sha256": prod.get("ledger_sha256"),
    }
