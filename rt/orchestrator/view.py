"""What the screen shows, built from a real ledger and a rehearsal record.

ledger_view(ledger) groups the ledger's facts into a few rows (directory groups, tables,
outbound calls, decoys). A row is "out_of_scope" only when the ledger's own out_of_scope[]
lists one of its facts: the verdict is never recomputed here. Every out_of_scope entry is
claimed by exactly one row (out_of_scope_rows), so the screen cannot drop one silently.
"""
from __future__ import annotations

import posixpath
from collections import Counter, defaultdict
from datetime import datetime

from rt.ledger.scope import DIR_OPS, FILE_OPS, _egress_op, norm_table, path_in_scope

STEPS = ["rehearse", "review", "apply", "compare"]
MAX_PATH_ROWS = 4
TWIN_SUBTITLE = "Vultr VM from snapshot · VPC-only · no keys"
OP_SIGN = {"deleted": "-", "created": "+", "modified": "~", "dir_deleted": "-", "dir_created": "+"}
OP_ORDER = ("deleted", "created", "modified", "dir_deleted", "dir_created")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


class _Claims:
    """Out-of-scope entries of a ledger, handed out to view rows."""

    def __init__(self, out_of_scope: list[dict]):
        self.left: Counter = Counter()
        self.reason: dict = {}
        for e in out_of_scope or []:
            key = (e.get("kind"), e.get("op"), e.get("item"))
            self.left[key] += 1
            self.reason.setdefault(key, e.get("reason") or "")

    def has(self, kind, op, item) -> bool:
        return self.left[(kind, op, item)] > 0

    def take(self, kind, op, item, n: int = 1) -> tuple[int, str]:
        key = (kind, op, item)
        got = min(n, self.left[key])
        self.left[key] -= got
        return got, self.reason.get(key, "") if got else ""

    def take_item(self, kinds, item) -> tuple[int, str]:
        got, reason = 0, ""
        for key in list(self.left):
            if key[0] in kinds and key[2] == item and self.left[key] > 0:
                got += self.left[key]
                reason = reason or self.reason.get(key, "")
                self.left[key] = 0
        return got, reason

    def rest(self) -> list[tuple[tuple, int, str]]:
        return [(k, n, self.reason.get(k, "")) for k, n in sorted(self.left.items(), key=lambda kv: str(kv[0])) if n > 0]


def _row(target, out: bool, delta, reason, kind, count, claimed, **extra) -> dict:
    return {"target": target, "verdict": "out_of_scope" if out else "in_scope", "delta": delta,
            "reason": reason if out else "", "kind": kind, "count": count, "out_of_scope_rows": claimed, **extra}


def _path_rows(ledger: dict, claims: _Claims, max_rows: int) -> list[dict]:
    files, dirs = ledger.get("files") or {}, ledger.get("dirs") or {}
    facts = [(p, op) for op in FILE_OPS for p in files.get(op) or []]
    facts += [(p, "dir_" + op) for op in DIR_OPS for p in dirs.get(op) or []]
    if not facts:
        return []
    out_of = {(p, op): claims.has("path", op, p) for p, op in facts}
    groups: dict[str, list] = defaultdict(list)
    for p, op in facts:
        groups[p if op.startswith("dir_") else posixpath.dirname(p)].append((p, op))
    scope_paths = ((ledger.get("scope") or {}).get("paths")) or []

    def verdict(members) -> bool:
        return any(out_of[f] for f in members)

    def children(parent: str, out: bool) -> list[str]:
        return [k for k in groups if k != parent and posixpath.dirname(k) == parent and verdict(groups[k]) == out]

    def merge(parent: str, keys: list[str]) -> None:
        merged = [f for k in keys for f in groups.pop(k)]
        groups[parent] = merged

    # A group that is only its own deleted/created directory folds its same-verdict children in.
    folded = True
    while folded:
        folded = False
        for key in sorted(groups, key=lambda k: -k.count("/")):
            only = groups[key]
            if len(only) == 1 and only[0] == (key, only[0][1]) and only[0][1].startswith("dir_"):
                kids = children(key, verdict(only))
                if kids:
                    merge(key, [key, *kids])
                    folded = True
                    break

    # Still too many rows: merge siblings of one verdict into their parent. An in-scope group is
    # only ever labelled with a path that is itself in scope.
    while len(groups) > max_rows:
        best = None
        for parent in {posixpath.dirname(k) for k in groups if k != "/"}:
            for out in (True, False):
                if parent in groups and verdict(groups[parent]) != out:
                    continue
                if not out and parent not in groups and not path_in_scope(parent, scope_paths):
                    continue
                members = children(parent, out) + ([parent] if parent in groups else [])
                if len(members) < 2:
                    continue
                rank = (len(members), parent.count("/"), parent)
                if best is None or rank > best[0]:
                    best = (rank, parent, members)
        if best is None:
            break
        merge(best[1], best[2])

    rows = []
    for key, members in groups.items():
        is_out = verdict(members)
        ops = Counter(op for _, op in members)
        parts = []
        for op in OP_ORDER:
            if ops[op]:
                parts.append(OP_SIGN[op] + _plural(ops[op], "dir" if op.startswith("dir_") else "file"))
        claimed, reason = 0, ""
        for p, op in members:
            got, why = claims.take("path", op, p)
            claimed += got
            reason = reason or why
        target = members[0][0] if len(members) == 1 and not members[0][1].startswith("dir_") else key
        rows.append(_row(target, is_out, ", ".join(parts), reason, "path", len(members), claimed))
    rows.sort(key=lambda r: (r["verdict"] == "out_of_scope", -r["count"], r["target"]))
    return rows


def _table_rows(ledger: dict, claims: _Claims) -> list[dict]:
    rows = []
    for t_raw, ch in sorted((ledger.get("rows") or {}).items()):
        t = norm_table(t_raw)
        parts = [flag.replace("_", " ") for flag in ("dropped", "created", "schema_changed") if ch.get(flag)]
        for k, sign in (("deleted", "-"), ("inserted", "+"), ("updated", "~")):
            if int(ch.get(k) or 0):
                parts.append(f"{sign}{_plural(int(ch[k]), 'row')}")
        n = sum(int(ch.get(k) or 0) for k in ("inserted", "deleted", "updated"))
        claimed, reason = claims.take_item(("table", "rows_budget"), t)
        rows.append(_row(f"table {t}", claimed > 0, ", ".join(parts) or "no row changes", reason, "table", n,
                         claimed))
    return rows


def _egress_rows(ledger: dict, claims: _Claims) -> list[dict]:
    groups: dict[tuple, list] = defaultdict(list)
    for e in ledger.get("egress") or []:
        groups[(e.get("method") or "", e.get("host") or "?", e.get("path") or "", e.get("kind") or "tcp",
                e.get("port"))].append(e)
    dns = {d.get("qname"): int(d.get("count") or 0) for d in ledger.get("dns") or []}
    rows = []
    for (method, host, path, kind, port), es in sorted(groups.items(), key=lambda kv: str(kv[0])):
        claimed, reason = 0, ""
        for e in es:
            got, why = claims.take("host", _egress_op(e), e.get("host") or "?")
            claimed += got
            reason = reason or why
        if host in dns:
            got, _ = claims.take("dns", "lookup", host, n=10**9)
            claimed += got
        delivered = sum(int(e.get("delivered") or 0) for e in es)
        target = f"{method} {host}{path or '/'}" if method else f"{kind} {host}:{port}"
        rows.append(_row(target, claimed > 0, f"{_plural(len(es), 'call')}, {delivered} B delivered", reason,
                         "egress", len(es), claimed, method=method or kind, host=host, path=path,
                         delivered=delivered, sources=sorted({e.get("source") or "?" for e in es})))
    seen_hosts = {k[1] for k in groups}
    for q, n in sorted(dns.items()):
        if q in seen_hosts:
            continue
        claimed, reason = claims.take("dns", "lookup", q, n=10**9)
        rows.append(_row(f"dns {q}", claimed > 0, _plural(n, "lookup"), reason, "dns", n, claimed))
    denied = int((ledger.get("egress_denied") or {}).get("packets") or 0)
    if denied > 0:
        claimed, reason = claims.take("network", "denied", "outbound packets")
        rows.append(_row("denied by sandbox", claimed > 0, _plural(denied, "packet"), reason, "network", denied,
                         claimed))
    return rows


def _other_rows(ledger: dict, claims: _Claims) -> list[dict]:
    rows = []
    for c in ledger.get("canaries") or []:
        if not (c.get("touched") or c.get("exfil_attempt")):
            continue
        op = "+".join(c.get("evidence") or []) or "touched"
        claimed, reason = claims.take("canary", op, c.get("id") or "?")
        rows.append(_row(f"decoy {c.get('id')}", True, op.replace("+", ", "), reason or "decoy touched", "canary",
                         1, claimed))
    for issue in (ledger.get("integrity") or {}).get("issues") or []:
        claimed, reason = claims.take("integrity", "check", issue)
        rows.append(_row("tracer integrity", True, issue, reason or "tracer state changed", "integrity", 1, claimed))
    for (kind, op, item), n, reason in claims.rest():
        claims.take(kind, op, item, n)
        rows.append(_row(str(item), True, str(op), reason, str(kind), n, n))
    return rows


def ledger_view(ledger: dict, max_path_rows: int = MAX_PATH_ROWS) -> list[dict]:
    claims = _Claims(ledger.get("out_of_scope") or [])
    return (_path_rows(ledger, claims, max_path_rows) + _table_rows(ledger, claims)
            + _egress_rows(ledger, claims) + _other_rows(ledger, claims))


def headline(ledger: dict) -> str:
    files, rows = ledger.get("files") or {}, ledger.get("rows") or {}
    if files.get("deleted"):
        return f"deleted {_plural(len(files['deleted']), 'file')}"
    dropped = [t for t, ch in rows.items() if ch.get("dropped")]
    if dropped:
        return f"dropped {_plural(len(dropped), 'table')}"
    totals = Counter()
    for ch in rows.values():
        for k in ("updated", "deleted", "inserted"):
            totals[k] += int(ch.get(k) or 0)
    if any(totals.values()):
        k, n = max(totals.items(), key=lambda kv: (kv[1], kv[0]))
        return f"{k} {_plural(n, 'row')}"
    if files.get("created") or files.get("modified"):
        return f"changed {_plural(len(files.get('created') or []) + len(files.get('modified') or []), 'file')}"
    if ledger.get("egress"):
        return _plural(len(ledger["egress"]), "outbound call")
    return "no changes"


def screen_summary(ledger: dict, view_rows: list[dict]) -> dict:
    s = ledger.get("summary") or {}
    egress = [r for r in view_rows if r["kind"] == "egress"]
    egress.sort(key=lambda r: r["verdict"] != "out_of_scope")
    if egress:
        e = egress[0]
        state = "blocked" if e["delivered"] == 0 else "delivered"
        line = {"method": e["method"], "target": f"{e['host']}{e['path']}",
                "note": f"{state}, recorded, {e['delivered']} bytes delivered"}
    else:
        line = {"method": "egress", "target": "none", "note": "no outbound calls"}
    return {
        "headline": headline(ledger),
        "verdict": s.get("verdict"),
        "deleted_files": len((ledger.get("files") or {}).get("deleted") or []),
        "outside_count": int(s.get("files_out_of_scope") or 0),
        "outside_paths": [r["target"] for r in view_rows if r["kind"] == "path" and r["verdict"] == "out_of_scope"],
        "out_of_scope_total": int(s.get("out_of_scope_total") or 0),
        "rows_changed": int(s.get("rows_changed") or 0),
        "egress_line": line,
    }


def effect_counts(ledger: dict | None) -> dict:
    s = (ledger or {}).get("summary") or {}
    return {"files_changed": int(s.get("files_changed") or 0), "rows_changed": int(s.get("rows_changed") or 0),
            "egress_attempts": int(s.get("egress_attempts") or 0)}


def compare_view(cmp: dict, twin_ledger: dict, prod_ledger: dict) -> dict:
    return {"predicted": effect_counts(twin_ledger), "happened": effect_counts(prod_ledger),
            "match": bool(cmp.get("match")), "counts": cmp.get("counts") or {},
            "surprises": (cmp.get("surprises") or [])[:50]}


def _ms_between(a: str, b: str) -> int:
    try:
        ta = datetime.fromisoformat(a.replace("Z", "+00:00"))
        tb = datetime.fromisoformat(b.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return 0
    return max(0, int((tb - ta).total_seconds() * 1000))


def timeline(events: list[dict]) -> list[dict]:
    out, prev = [], None
    for ev in events:
        if ev.get("type") == "view":
            continue
        out.append({"delay_ms": _ms_between(prev, ev["ts"]) if prev else 0, "type": ev["type"], "data": ev["data"]})
        prev = ev["ts"]
    return out


def instances_view(record: dict) -> list[dict]:
    items = [{"id": record.get("prod_instance_id") or "prod", "label": record.get("prod_label") or "prod",
              "dot": "green", "meta": "public · rt-keep"}]
    for a in record.get("attempts") or []:
        t = a.get("twin") or {}
        if t.get("id"):
            items.append({"id": t["id"], "label": t.get("label") or "twin", "dot": "blue",
                          "meta": "rehearsal · no public IPv4", "destroyed": bool(t.get("destroyed"))})
    return items


def screen_view(record: dict, *, presets: list[str], ledger: dict | None, prod_ledger: dict | None = None,
                compare: dict | None = None, events: list[dict] | None = None) -> dict:
    attempts = record.get("attempts") or []
    shown = next((a for a in reversed(attempts) if a.get("ledger_sha256")), None)
    rows = ledger_view(ledger) if ledger else []
    script_src = (shown or (attempts[-1] if attempts else {})).get("script_text") or record.get("script_text") or ""
    twin = (shown or {}).get("twin") or {}
    view = {
        "id": record["id"],
        "mode": "live",
        "status": record.get("status"),
        "error": record.get("error"),
        "preset": record.get("name") or "script.sh",
        "presets": presets,
        "goal": record.get("goal"),
        "source": record.get("source"),
        "script": {"name": (shown or {}).get("script_name") or record.get("name") or "script.sh",
                   "lines": script_src.splitlines(), "attempt": (shown or {}).get("n")},
        "scope": record.get("scope") or {"paths": [], "tables": {}, "hosts": []},
        "steps": STEPS,
        "prod": {"name": record.get("prod_label") or "prod", "uptime_s": record.get("prod_uptime_s") or 0},
        "twin": {"label": twin.get("label") or "twin", "subtitle": TWIN_SUBTITLE},
        "twin_ledger": {"ledger_sha256": (ledger or {}).get("ledger_sha256") or "",
                        "summary": (ledger or {}).get("summary") or {}},
        "ledger_view": rows,
        "summary": screen_summary(ledger, rows) if ledger else screen_summary({}, []),
        "attempts": [{k: a.get(k) for k in ("n", "kind", "status", "verdict", "ledger_sha256", "script_sha256",
                                             "out_of_scope_total", "error")} | {"twin": (a.get("twin") or {}).get("label")}
                     for a in attempts],
        "instances": instances_view(record),
        "approval": record.get("approval") if record.get("status") == "awaiting_approval" else None,
        "prod_counters": effect_counts(prod_ledger) if prod_ledger else {"files_changed": 0, "rows_changed": 0,
                                                                         "egress_attempts": 0},
        "compare": compare_view(compare, ledger or {}, prod_ledger or {}) if compare and prod_ledger else None,
        "receipt_url": f"/api/rehearsals/{record['id']}/receipt" if record.get("receipt") else None,
        "view_key": f"{record['id']}:{(shown or {}).get('n') or 0}",
        "timeline": timeline(events or []),
    }
    return view
