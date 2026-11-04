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
OUTPUT_TAIL = 2048
LOGGING_SQL = re.compile(r"\b(log_statement|log_min_duration_statement|log_destination|logging_collector|"
                         r"pg_reload_conf|alter\s+system)\b", re.I)


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
    script_units = {f"{run_unit}.service", f"{run_unit}.scope"} if run_unit else set()
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
        source = "script" if unit in script_units else (unit or "unknown")
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
        if r.get("token_scan") == "partial":
            # the recorder stopped reading before the client was done: a decoy token sent after
            # that point was not looked for
            e["token_scan"] = "partial"
        egress.append(e)
    egress.sort(key=lambda e: json.dumps(e, sort_keys=True))
    return egress, [{"qname": q, "count": n} for q, n in sorted(dns.items())], hits


BLOCKED = {"tcp": "before handshake", "udp": "dropped by the firewall"}


def connect_attempts(connect_log, records) -> list:
    """Egress entries for the script's connections straight to an IP address (kernel log of the nat
    connect rule). The sandbox drops their replies, so the recorder normally has no record of them;
    a connection the recorder did record (same address and port) is not listed twice."""
    recorded = Counter((r.get("orig_dst"), r.get("port")) for r in records
                       if r.get("kind") != "dns" and r.get("orig_dst"))
    out = []
    for c in connect_log or ():
        proto, host, port = (c.get("proto") or "").lower(), c.get("dst"), c.get("dpt")
        if proto not in BLOCKED or not host or not isinstance(port, int):
            continue
        if proto == "tcp" and recorded[(host, port)] > 0:
            recorded[(host, port)] -= 1
            continue
        out.append({"kind": proto, "host": host, "port": port, "bytes_attempted": 0, "delivered": 0,
                    "source": "script", "blocked": BLOCKED[proto]})
    return out


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


def integrity(state0: dict, state1: dict, run: dict, sql=(), egress_bad_lines: int = 0) -> dict:
    """Checks that the containment and the tracer were intact; every failed check is an issue."""
    issues = []
    checks = {}

    def same(name, a, b, issue):
        if a is None and b is None:
            checks[name] = "not available"
        elif a == b:
            checks[name] = "unchanged"
        else:
            checks[name] = "changed"
            issues.append(issue)

    same("tracer_files", state0.get("self_digest"), state1.get("self_digest"), "tracer files under /opt/rt changed")
    same("firewall_rules", (state0.get("iptables") or {}).get("rules_sha256"),
         (state1.get("iptables") or {}).get("rules_sha256"), "egress firewall rules changed")
    # Routes are informational: the sandbox has no netlink and no CAP_NET_ADMIN, so a change here
    # comes from the system (DHCP, router advertisements), and firewall_rules guards the egress path.
    r0, r1 = state0.get("routes_sha256"), state1.get("routes_sha256")
    checks["routes"] = "not available" if r0 is None and r1 is None else ("unchanged" if r0 == r1 else "changed")

    e0, e1 = state0.get("egress_service") or {}, state1.get("egress_service") or {}
    if not state0.get("egress_active"):
        checks["egress_recorder"] = "not running"
        issues.append("egress recorder was not running: outbound attempts were blocked but not recorded")
    elif not state1.get("egress_active"):
        checks["egress_recorder"] = "stopped"
        issues.append("egress recorder not active after the run")
    elif e0 and e1 and (e0.get("main_pid") != e1.get("main_pid") or e0.get("restarts") != e1.get("restarts")):
        checks["egress_recorder"] = "restarted"
        issues.append("egress recorder restarted during the run")
    elif (e1.get("state") or "") in ("T", "t"):
        # systemd still reports a SIGSTOPped process as active: only its process state shows it
        checks["egress_recorder"] = "paused"
        issues.append("egress recorder was paused (stopped by a signal)")
    else:
        checks["egress_recorder"] = "running"

    a0, a1 = state0.get("audit_service"), state1.get("audit_service")
    if a0 is not None or a1 is not None:
        # auditd runs as root, so the root script can signal it although it has no CAP_KILL: decoy
        # file reads would then be missing from audit.log.
        a0, a1 = a0 or {}, a1 or {}
        if a0.get("active") != "active":
            checks["auditd"] = "not running"
        elif a1.get("active") != "active":
            checks["auditd"] = "stopped"
            issues.append("auditd not active after the run: decoy file reads may be missing")
        elif a0.get("main_pid") != a1.get("main_pid") or a0.get("restarts") != a1.get("restarts"):
            checks["auditd"] = "restarted"
            issues.append("auditd restarted during the run: decoy file reads may be missing")
        elif (a1.get("state") or "") in ("T", "t"):
            checks["auditd"] = "paused"
            issues.append("auditd was paused (stopped by a signal)")
        else:
            checks["auditd"] = "running"

    if any(LOGGING_SQL.search(s.get("statement") or "") for s in sql):
        checks["statement_logging"] = "changed"
        issues.append("the script changed Postgres statement logging")
    else:
        checks["statement_logging"] = "unchanged"

    pg0, pg1 = state0.get("pg") or {}, state1.get("pg") or {}
    if pg0 and not pg0.get("ok") and pg0.get("error") != "disabled":
        issues.append("postgres state unreadable before the run: row changes are not traced")
    elif pg0.get("ok") and not pg1.get("ok"):
        issues.append("postgres state unreadable after the run")
    unsafe = sorted(set(pg0.get("unsafe_names") or ()) | set(pg1.get("unsafe_names") or ()))
    if unsafe:
        # Traced like any table (the names never reach psql as text), flagged because such a
        # name is only useful to confuse a tool that prints it.
        checks["table_names"] = "unsafe"
        shown = ", ".join(json.dumps(k) for k in unsafe[:5]) + (f" (+{len(unsafe) - 5} more)" if len(unsafe) > 5 else "")
        issues.append(f"table names with a backslash or control character: {shown}")
    if egress_bad_lines:
        issues.append(f"{egress_bad_lines} unreadable egress log lines")
    if run.get("error"):
        issues.append(run["error"])
    elif run.get("unit_name") and not run.get("stats_recorded", True):
        issues.append("run statistics were not recorded")
    checks["sandbox"] = (run.get("sandbox") or {}).get("mode") or "none"
    checks["decoy_watch"] = state0.get("decoy_watch") or "not available"
    return {"ok": not issues, "issues": issues, "checks": checks}


def integrity_issues(state0: dict, state1: dict, egress_bad_lines: int = 0) -> list:
    return integrity(state0, state1, {}, (), egress_bad_lines)["issues"]


def dropped_delta(c0: dict, c1: dict) -> dict:
    out = {}
    for k in sorted(set(c0 or {}) | set(c1 or {})):
        out[k] = max(0, int((c1 or {}).get(k) or 0) - int((c0 or {}).get(k) or 0))
    return out


def build_facts(state0: dict, state1: dict, run: dict, sources: dict, cfg: dict) -> dict:
    """sources: sql[], audit[], egress_records[], egress_bad_lines, canary_defs[], connect_log[], drop_log[],
    large_hashes{path: sha256} (changed files over hash_limit, hashed after the run)."""
    defs = sources.get("canary_defs") or []
    m1 = state1.get("files") or {}
    files, dirs = fsstate.diff(state0.get("files") or {}, m1)
    large = sources.get("large_hashes") or {}
    changed = files["created"] + files["modified"]
    rows = pgstate.diff_tables((state0.get("pg") or {}).get("tables") or {},
                               (state1.get("pg") or {}).get("tables") or {})
    sql = [dict(s, statement=mask(s.get("statement"), defs)) for s in sources.get("sql") or []]
    records = sources.get("egress_records") or []
    egress, dns, hits = egress_from_records(records, run.get("unit_name"), cfg.get("egress_ignore_units") or (),
                                            defs)
    kept = [r for r in records if (r.get("unit") or "") not in (cfg.get("egress_ignore_units") or ())]
    egress = sorted(egress + connect_attempts(sources.get("connect_log"), kept),
                    key=lambda e: json.dumps(e, sort_keys=True))
    canaries = evaluate_canaries(defs, files, rows, sources.get("sql") or [], sources.get("audit") or [],
                                 kept, hits)
    start_counters = (run.get("iptables_start") or state0.get("iptables") or {}).get("counters") or {}
    end_counters = (state1.get("iptables") or {}).get("counters") or {}
    drops = dropped_delta(start_counters, end_counters)
    limits = run.get("limits") or {}
    checked = integrity(state0, state1, run, sources.get("sql") or [], int(sources.get("egress_bad_lines") or 0))
    return {
        "version": 1,
        "files": files,
        "dirs": dirs,
        # What each created or modified file holds now (sha256, or size/ctime/inode when not hashed,
        # "link:<sha256 of the target>" for a symlink) and the mode/owner of every created or
        # modified path: compare checks these, not only the paths.
        "file_hashes": {p: fsstate.fingerprint(m1.get(p), large.get(p)) for p in changed},
        "path_meta": {p: fsstate.meta(m1.get(p)) for p in changed + dirs["created"] + dirs["modified"]},
        "rows": rows,
        "sql": sql,
        "egress": egress,
        "dns": dns,
        # Packets from the rehearsal unit that the firewall dropped: the script's own attempts. A TCP
        # connection straight to an IP address counts once: its first packet went out, the sandbox
        # denied the reply, so it never reached the recorder (counted by the kernel even when the
        # kernel log has no line for it).
        "egress_denied": {"packets": drops.get("sandbox_packets", 0) + drops.get("sandbox6_packets", 0)
                          + drops.get("sandbox_connects", 0)},
        # Drops from other processes and route changes during the window: shown, never in scope,
        # never in the hash (the key is volatile).
        "system_noise": {
            "udp_packets": drops.get("udp_packets", 0),
            "other_packets": drops.get("other_packets", 0),
            "ipv6_packets": drops.get("ipv6_packets", 0),
            "routes_changed": checked["checks"].get("routes") == "changed",
        },
        "drop_log": sources.get("drop_log") or [],
        "ip_accounting": run.get("ip_accounting") or {},
        "canaries": canaries,
        "exit": run.get("exit"),
        "limits": {k: limits.get(k) for k in LIMIT_KEYS if k in limits},
        "integrity": checked,
        "sandbox": {"mode": (run.get("sandbox") or {}).get("mode") or "none",
                    "ip_filter": (run.get("sandbox") or {}).get("ip_filter") or "none"},
        "output": {
            "stdout_tail": mask((run.get("stdout") or "")[-OUTPUT_TAIL:], defs),
            "stderr_tail": mask((run.get("stderr") or "")[-OUTPUT_TAIL:], defs),
        },
    }
