"""Compare the twin ledger (prediction) with the production ledger (what happened).

Normalization: paths (normalized, no mtime), row changes per table (+/-),
egress grouped by (method, host, path, port). Anything that differs is a surprise.

Content, not only counts, when the tracer wrote it (fields added by the tracer, older
ledgers do not have them):
- rows[<table>].digests {inserted, deleted, updated}: one sha256 per operation over the keys
  (and, for updates, the new values) of the rows it touched. Same counts, other rows: a surprise.
- file_hashes {path: sha256 | "size:<n>:ctime:<ns>:ino:<n>" | null} for created and modified
  files. Same path, other content: a surprise. Files above the tracer's hash limit carry only
  their size here (ctime and inode never match across machines), so they compare by size.
- egress[].port: part of the key when every outbound entry on both sides has one.

`compare_basis` says what a match rests on: "content" when every compared item had its digest,
hash or port on both sides, "counts" when any part fell back to counts, paths or no port (an
older ledger). `compare_detail` gives the basis per part.
"""
from __future__ import annotations

import json
from collections import Counter

from .scope import DDL_FLAGS, FILE_OPS, DIR_OPS, ScopeError, norm_host, norm_path, norm_table

ROW_KEYS = ("inserted", "deleted", "updated")
DIR_COMPARE_OPS = DIR_OPS + ("modified",)  # dirs.modified: mode/owner changes, when the tracer lists them
CONTENT_FILE_OPS = ("created", "modified")


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


def _port(e: dict):
    p = e.get("port")
    return p if isinstance(p, int) and not isinstance(p, bool) else None


def _digests(ch: dict) -> dict:
    d = ch.get("digests")
    return {k: d[k] for k in ROW_KEYS if isinstance(d, dict) and isinstance(d.get(k), str)}


def _file_hashes(ledger: dict) -> dict | None:
    fh = ledger.get("file_hashes")
    if not isinstance(fh, dict):
        return None
    return {_np(p): (v if isinstance(v, str) else None) for p, v in fh.items()}


def normalize(ledger: dict) -> dict:
    files = ledger.get("files") or {}
    dirs = ledger.get("dirs") or {}
    rows, digests = {}, {}
    for t, ch in (ledger.get("rows") or {}).items():
        entry = {k: int(ch.get(k) or 0) for k in ROW_KEYS}
        for flag in DDL_FLAGS:
            if ch.get(flag):
                entry[flag] = True
        if any(entry.values()):
            rows[norm_table(t)] = entry
            d = _digests(ch)
            if d:
                digests[norm_table(t)] = d
    raw_egress = ledger.get("egress") or []
    with_port = all(_port(e) is not None for e in raw_egress)
    egress = Counter()
    for e in raw_egress:
        method = e.get("method") or (e.get("kind") or "tcp").upper()
        path = e.get("path") or ("" if not e.get("method") else "/")
        egress[(method, _nh(e.get("host")), path, _port(e))] += 1
    limits = ledger.get("limits") or {}
    return {
        "files": {op: sorted({_np(p) for p in files.get(op) or []}) for op in FILE_OPS},
        "dirs": {op: sorted({_np(p) for p in dirs.get(op) or []}) for op in DIR_COMPARE_OPS},
        "rows": {k: rows[k] for k in sorted(rows)},
        "row_digests": {k: digests[k] for k in sorted(digests)},
        "file_hashes": _file_hashes(ledger),
        "egress_with_port": with_port,
        "egress": [{"method": m, "host": h, "path": p, "port": port, "count": n}
                   for (m, h, p, port), n in sorted(egress.items(), key=lambda kv: str(kv[0]))],
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


def _content_id(v):
    if v is None:
        return None
    if v.startswith("size:"):
        return ("size", v.split(":")[1])
    return ("sha256", v)


def _short(v):
    return v[:16] if isinstance(v, str) else v


def compare(twin: dict, prod: dict) -> dict:
    p = normalize(twin)
    h = normalize(prod)
    surprises = []
    detail = {"rows": "digests", "files": "sha256", "egress": "port"}

    for group, ops in (("files", FILE_OPS), ("dirs", DIR_COMPARE_OPS)):
        kind = "file" if group == "files" else "dir"
        for op in ops:
            ps, hs = set(p[group][op]), set(h[group][op])
            for path in sorted(hs - ps):
                surprises.append(_surprise(kind, path, None, op,
                                           "happened on production, not predicted by the twin"))
            for path in sorted(ps - hs):
                surprises.append(_surprise(kind, path, op, None,
                                           "predicted by the twin, did not happen on production"))

    # Same paths created or modified on both sides: same content.
    pf, hf = p["file_hashes"], h["file_hashes"]
    both = sorted({x for op in CONTENT_FILE_OPS for x in set(p["files"][op]) & set(h["files"][op])})
    if both and (pf is None or hf is None):
        detail["files"] = "paths"
    elif both:
        weak = False
        for path in both:
            a, b = _content_id(pf.get(path)), _content_id(hf.get(path))
            if a is None and b is None:  # not hashed on either side: only the path is known
                weak = True
            elif a != b:
                surprises.append(_surprise("file_content", path, _short(pf.get(path)), _short(hf.get(path)),
                                           "same path, different content" if a and b
                                           else "content hashed on one side only"))
            elif a[0] == "size":  # above the hash limit on both sides: equal sizes only
                weak = True
        if weak:
            detail["files"] = "partial"

    for t in sorted(set(p["rows"]) | set(h["rows"])):
        pv, hv = p["rows"].get(t), h["rows"].get(t)
        if pv != hv:
            surprises.append(_surprise("rows", t, pv, hv, "row changes differ"))
            continue
        pd, hd = p["row_digests"].get(t, {}), h["row_digests"].get(t, {})
        for op in ROW_KEYS:
            if not pv.get(op):
                continue
            if op not in pd or op not in hd:
                detail["rows"] = "counts"
                continue
            if pd[op] != hd[op]:
                surprises.append(_surprise("rows", t, {op: pv[op], "digest": _short(pd[op])},
                                           {op: hv[op], "digest": _short(hd[op])},
                                           f"same number of {op} rows, different rows"))

    ports = p["egress_with_port"] and h["egress_with_port"]
    if not ports and (p["egress"] or h["egress"]):
        detail["egress"] = "no_port"

    def ekey(e):
        return (e["method"], e["host"], e["path"], e["port"] if ports else None)

    pe, he = Counter(), Counter()
    for e in p["egress"]:
        pe[ekey(e)] += e["count"]
    for e in h["egress"]:
        he[ekey(e)] += e["count"]
    for key in sorted(set(pe) | set(he), key=str):
        if pe.get(key, 0) != he.get(key, 0):
            m, host, path, port = key
            s = _surprise("egress", f"{m} {host}{path}", pe.get(key, 0), he.get(key, 0),
                          "outbound call count differs")
            if ports:
                s["port"] = port
            surprises.append(s)

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
        "compare_basis": "content" if detail == {"rows": "digests", "files": "sha256", "egress": "port"}
        else "counts",
        "compare_detail": detail,
        "twin_ledger_sha256": twin.get("ledger_sha256"),
        "prod_ledger_sha256": prod.get("ledger_sha256"),
    }
