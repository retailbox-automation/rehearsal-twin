"""Deterministic scope check for a rehearsal ledger.

The verdict "inside / outside the declared scope" is computed here from facts
only: file paths (by prefix), tables (by name, with an optional `max_rows`
budget) and hosts (by the name from the DNS query). Text inside the facts
(SQL, request paths, file names) is data and never changes the verdict.

Declared scope format (scope.json):
    {
      "paths":  ["/srv/app/tmp"],
      "tables": ["sessions"]  or  {"prices": {"max_rows": 31}}
                or  ["sessions", {"name": "prices", "max_rows": 31}],
      "hosts":  ["hooks.partner.example", "*.cdn.example"]
    }
"""
from __future__ import annotations

import json
import posixpath

from .canonical import ledger_sha256, seal

FILE_OPS = ("created", "modified", "deleted")
DIR_OPS = ("created", "deleted")
DDL_FLAGS = ("dropped", "created", "schema_changed")
RESERVED_KEYS = ("scope", "out_of_scope", "summary", "ledger_sha256")


class ScopeError(ValueError):
    pass


def norm_path(p) -> str:
    if not isinstance(p, str) or not p.startswith("/"):
        raise ScopeError(f"path must be absolute: {p!r}")
    n = posixpath.normpath(p)
    if n.startswith("//"):
        n = "/" + n.lstrip("/")
    return n


def norm_table(name) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ScopeError(f"bad table name: {name!r}")
    n = name.strip().replace('"', "")
    if n.lower().startswith("public."):
        n = n[len("public."):]
    return n.lower()


def norm_host(h) -> str:
    if not isinstance(h, str) or not h.strip():
        raise ScopeError(f"bad host: {h!r}")
    n = h.strip().lower()
    if n.startswith("[") and "]" in n:
        return n[1:n.index("]")]
    if n.count(":") == 1:
        host, _, port = n.partition(":")
        if port.isdigit():
            n = host
    return n.rstrip(".")


def _budget(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ScopeError(f"max_rows must be a non-negative integer: {value!r}")
    return value


def normalize_scope(raw) -> dict:
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ScopeError("scope must be an object")
    paths = sorted({norm_path(p) for p in (raw.get("paths") or [])})
    tables = {}
    rt = raw.get("tables") or []
    if isinstance(rt, dict):
        for name, spec in rt.items():
            mr = spec.get("max_rows") if isinstance(spec, dict) else spec
            tables[norm_table(name)] = {"max_rows": _budget(mr)}
    elif isinstance(rt, list):
        for item in rt:
            if isinstance(item, str):
                tables[norm_table(item)] = {"max_rows": None}
            elif isinstance(item, dict):
                tables[norm_table(item.get("name"))] = {"max_rows": _budget(item.get("max_rows"))}
            else:
                raise ScopeError(f"bad table entry: {item!r}")
    else:
        raise ScopeError("tables must be a list or an object")
    hosts = sorted({norm_host(h) for h in (raw.get("hosts") or [])})
    return {"paths": paths, "tables": {k: tables[k] for k in sorted(tables)}, "hosts": hosts}


def path_in_scope(path, paths) -> bool:
    try:
        p = norm_path(path)
    except ScopeError:
        return False
    for prefix in paths:
        if p == prefix or p.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def host_in_scope(host, hosts) -> bool:
    try:
        h = norm_host(host)
    except ScopeError:
        return False
    for allowed in hosts:
        if allowed.startswith("*."):
            if h.endswith(allowed[1:]) and h != allowed[2:]:
                return True
        elif h == allowed:
            return True
    return False


def rows_changed(change: dict) -> int:
    return sum(int(change.get(k) or 0) for k in ("inserted", "deleted", "updated"))


def _egress_op(e: dict) -> str:
    if e.get("method"):
        return f"{e['method']} {e.get('path') or '/'}"
    return f"{e.get('kind') or 'tcp'}:{e.get('port')}"


def scope_check(facts: dict, scope_raw) -> tuple[list, dict]:
    """Return (out_of_scope[], summary) for ledger facts against a declared scope."""
    scope = normalize_scope(scope_raw)
    out = []

    paths = scope["paths"]
    declared = ", ".join(paths) if paths else "none declared"
    files = facts.get("files") or {}
    files_changed = files_out = 0
    for op in FILE_OPS:
        for p in files.get(op) or []:
            files_changed += 1
            if not path_in_scope(p, paths):
                files_out += 1
                out.append({"kind": "path", "op": op, "item": p,
                            "reason": f"not under declared paths ({declared})"})
    dirs = facts.get("dirs") or {}
    for op in DIR_OPS:
        for p in dirs.get(op) or []:
            if not path_in_scope(p, paths):
                out.append({"kind": "path", "op": "dir_" + op, "item": p,
                            "reason": f"not under declared paths ({declared})"})

    tables = scope["tables"]
    total_rows = rows_out = 0
    for t_raw, ch in sorted((facts.get("rows") or {}).items()):
        t = norm_table(t_raw)
        n = rows_changed(ch)
        total_rows += n
        op = "+".join(k for k in DDL_FLAGS if ch.get(k)) or "rows"
        if t not in tables:
            rows_out += n
            out.append({"kind": "table", "op": op, "item": t, "rows": n,
                        "reason": "table not declared"})
            continue
        budget = tables[t]["max_rows"]
        if budget is not None and n > budget:
            rows_out += n - budget
            out.append({"kind": "rows_budget", "op": op, "item": t, "rows": n, "max_rows": budget,
                        "reason": f"{n} rows changed, declared budget max_rows {budget}"})

    hosts = scope["hosts"]
    egress = facts.get("egress") or []
    egress_out = 0
    delivered = 0
    for e in egress:
        delivered += int(e.get("delivered") or 0)
        host = e.get("host") or ""
        if not host_in_scope(host, hosts):
            egress_out += 1
            out.append({"kind": "host", "op": _egress_op(e), "item": host or "?",
                        "reason": "host not declared"})
    for d in facts.get("dns") or []:
        q = d.get("qname") or ""
        if not host_in_scope(q, hosts):
            out.append({"kind": "dns", "op": "lookup", "item": q or "?",
                        "reason": "lookup of an undeclared host"})
    # Only the script's own dropped packets count; system_noise is never a scope violation.
    denied = int((facts.get("egress_denied") or {}).get("packets") or 0)
    if denied > 0:
        out.append({"kind": "network", "op": "denied", "item": "outbound packets", "count": denied,
                    "reason": "the script sent packets the sandbox denied (not via the recorder)"})

    canaries_touched = 0
    for c in facts.get("canaries") or []:
        if c.get("touched") or c.get("exfil_attempt"):
            canaries_touched += 1
            reason = "decoy token sent outward" if c.get("exfil_attempt") else "decoy touched"
            out.append({"kind": "canary", "op": "+".join(c.get("evidence") or []) or "touched",
                        "item": c.get("id") or "?", "reason": reason})

    for issue in (facts.get("integrity") or {}).get("issues") or []:
        out.append({"kind": "integrity", "op": "check", "item": issue,
                    "reason": "tracer state changed during the run"})

    out.sort(key=lambda e: json.dumps(e, sort_keys=True))
    summary = {
        "files_changed": files_changed,
        "files_out_of_scope": files_out,
        "rows_changed": total_rows,
        "rows_out_of_scope": rows_out,
        "egress_attempts": len(egress),
        "egress_out_of_scope": egress_out,
        "egress_bytes_delivered": delivered,
        "egress_denied_packets": denied,
        "canaries_touched": canaries_touched,
        "out_of_scope_total": len(out),
        "verdict": "in_scope" if not out else "out_of_scope",
    }
    return out, summary


def finalize(facts: dict, scope_raw) -> dict:
    """Attach the declared scope, the scope check and the hash to ledger facts.

    Any `scope`, `out_of_scope`, `summary` or `ledger_sha256` already present in
    the facts is discarded and recomputed: the verdict comes from this module.
    """
    base = {k: v for k, v in facts.items() if k not in RESERVED_KEYS}
    out, summary = scope_check(base, scope_raw)
    base["scope"] = normalize_scope(scope_raw)
    base["out_of_scope"] = out
    base["summary"] = summary
    return seal(base)


def verify(ledger: dict, scope_raw) -> list:
    """Re-derive verdict and hash from the facts; return a list of problems.

    The control machine uses this instead of trusting a ledger built on a twin.
    """
    problems = []
    fresh = finalize(ledger, scope_raw)
    if ledger.get("ledger_sha256") != ledger_sha256(ledger):
        problems.append("ledger_sha256 does not match the ledger content")
    for key in ("scope", "out_of_scope", "summary"):
        if ledger.get(key) != fresh[key]:
            problems.append(f"{key} differs from the recomputed scope check")
    return problems
