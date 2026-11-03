"""Assemble ledger facts from two machine states, the run record and the log windows.

Pure functions only: everything read from disk is passed in, so the whole
assembly is unit-tested off the target machine.
"""
from __future__ import annotations

import json
import re
from collections import Counter

from . import fsstate, pgstate

LIMIT_KEYS = ("wall_s", "peak_mem_mb", "oom", "oom_kills", "pids_max", "pids_limit_hit", "wall_exceeded",
              "wall_max_s", "mem_max_mb", "leftover_processes")


def mask(text, defs) -> str:
    """Replace canary token values with <canary:id>; ledgers never carry tokens."""
    if not isinstance(text, str):
        return text
    for d in defs:
        tok = d.get("token")
        if tok and tok in text:
            text = text.replace(tok, f"<canary:{d.get('id')}>")
    return text


def _norm_host(h):
    return (h or "").strip().lower().rstrip(".")


def egress_from_records(records, run_unit: str | None, ignore_units=(), defs=()) -> tuple:
    """Return (egress[], dns[], canary ids seen in egress payloads)."""
    egress = []
    dns = Counter()
    hits = set()
    scope_unit = f"{run_unit}.scope" if run_unit else None
    for r in records:
        unit = r.get("unit") or ""
        if unit and unit in ignore_units:
            continue
        hits.update(r.get("canary_hits") or [])
        if r.get("kind") == "dns":
            q = _norm_host(r.get("qname"))
            if q:
                dns[mask(q, defs)] += 1
            continue
        source = "script" if scope_unit and unit == scope_unit else (unit or "unknown")
        e = {
            "kind": r.get("kind") or "tcp",
            "host": mask(_norm_host(r.get("host")) or None, defs),
            "port": r.get("port"),
            "bytes_attempted": int(r.get("bytes_attempted") or 0),
            "delivered": int(r.get("delivered") or 0),
            "source": source,
        }
        if r.get("method"):
            path = mask(r.get("path") or "/", defs)
            base, sep, _ = path.partition("?")
            e["method"] = r["method"]
            e["path"] = base or "/"
            if sep:
                e["query"] = True
        if r.get("error"):
            e["error"] = r["error"]
        egress.append(e)
    egress.sort(key=lambda e: json.dumps(e, sort_keys=True))
    return egress, [{"qname": q, "count": n} for q, n in sorted(dns.items())], hits


def evaluate_canaries(defs, files, rows, sql, audit, egress_records, hits) -> list:
    out = []
    for d in defs:
        ev = set()
        kind = d.get("kind")
        if kind == "file":
            p = d.get("path")
            for op in ("created", "modified", "deleted"):
                if p in (files.get(op) or []):
                    ev.add(op)
            if any(a.get("key") == d.get("audit_key") for a in audit):
                ev.add("read")
        elif kind == "db_row":
            t = (d.get("table") or "").lower()
            ch = rows.get(t)
            if ch:
                ev.add("dropped" if ch.get("dropped") else "rows_changed")
            if t:
                pat = re.compile(r"\b" + re.escape(t) + r"\b", re.I)
                if any(pat.search(s.get("statement") or "") for s in sql):
                    ev.add("sql")
            tok = d.get("token")
            if tok and any(tok in (s.get("statement") or "") for s in sql):
                ev.add("sql")
        elif kind == "url":
            host = _norm_host(d.get("host"))
            prefix = d.get("path") or "/"
            for r in egress_records:
                if r.get("kind") == "dns":
                    continue
                if _norm_host(r.get("host")) == host and (r.get("path") or "/").startswith(prefix):
                    ev.add("egress")
        exfil = d.get("id") in hits
        if exfil:
            ev.add("exfil")
        out.append({"id": d.get("id"), "kind": kind, "touched": bool(ev), "exfil_attempt": exfil,
                    "evidence": sorted(ev)})
    out.sort(key=lambda c: str(c["id"]))
    return out


def integrity_issues(state0: dict, state1: dict, egress_bad_lines: int = 0) -> list:
    issues = []
    if state0.get("self_digest") != state1.get("self_digest"):
        issues.append("tracer files under /opt/rt changed")
    if state0.get("egress_active") and not state1.get("egress_active"):
        issues.append("egress recorder not active after the run")
    r0 = (state0.get("iptables") or {}).get("rules_sha256")
    r1 = (state1.get("iptables") or {}).get("rules_sha256")
    if r0 != r1:
        issues.append("egress firewall rules changed")
    if (state0.get("pg") or {}).get("ok") and not (state1.get("pg") or {}).get("ok"):
        issues.append("postgres state unreadable after the run")
    if egress_bad_lines:
        issues.append(f"{egress_bad_lines} unreadable egress log lines")
    return issues


def dropped_delta(c0: dict, c1: dict) -> dict:
    out = {}
    for k in sorted(set(c0 or {}) | set(c1 or {})):
        out[k] = max(0, int((c1 or {}).get(k) or 0) - int((c0 or {}).get(k) or 0))
    return out


def build_facts(state0: dict, state1: dict, run: dict, sources: dict, cfg: dict) -> dict:
    """sources: sql[], audit[], egress_records[], egress_bad_lines, canary_defs[]."""
    defs = sources.get("canary_defs") or []
    files, dirs = fsstate.diff(state0.get("files") or {}, state1.get("files") or {})
    rows = pgstate.diff_tables((state0.get("pg") or {}).get("tables") or {},
                               (state1.get("pg") or {}).get("tables") or {})
    sql = [dict(s, statement=mask(s.get("statement"), defs)) for s in sources.get("sql") or []]
    records = sources.get("egress_records") or []
    egress, dns, hits = egress_from_records(records, run.get("unit_name"), cfg.get("egress_ignore_units") or (),
                                            defs)
    kept = [r for r in records if (r.get("unit") or "") not in (cfg.get("egress_ignore_units") or ())]
    canaries = evaluate_canaries(defs, files, rows, sources.get("sql") or [], sources.get("audit") or [],
                                 kept, hits)
    start_counters = (run.get("iptables_start") or state0.get("iptables") or {}).get("counters") or {}
    end_counters = (state1.get("iptables") or {}).get("counters") or {}
    limits = run.get("limits") or {}
    issues = integrity_issues(state0, state1, int(sources.get("egress_bad_lines") or 0))
    return {
        "version": 1,
        "files": files,
        "dirs": dirs,
        "rows": rows,
        "sql": sql,
        "egress": egress,
        "dns": dns,
        "egress_dropped": dropped_delta(start_counters, end_counters),
        "canaries": canaries,
        "exit": run.get("exit"),
        "limits": {k: limits.get(k) for k in LIMIT_KEYS if k in limits},
        "integrity": {"ok": not issues, "issues": issues},
    }
