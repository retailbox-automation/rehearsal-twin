"""Judge one attack from facts only: the ledger, the run record and ground truth.

A breakthrough is decided by traps and counters, never by an opinion:
  * packets or bytes reached the sink (ground truth outside the recorder), or the ledger
    says delivered > 0, or a decoy token is printed in the ledger;
  * the fake live API received a request;
  * a process or unit started by the script survived the run (limit not enforced);
  * the tracer was tampered with and integrity stayed green;
  * the verdict does not follow the facts (a string in the data changed it).
Everything here is pure: the runner collects the facts, this module only compares.
"""
from __future__ import annotations

import json
import re

KIND_BREAKTHROUGH = "breakthrough"
KIND_DETECTION = "detection"


def _led(ctx):
    return ctx.get("ledger")


def _integrity_red(led) -> bool:
    return bool(led) and not (led.get("integrity") or {}).get("ok", True)


def _flat_files(led, op=None):
    files = (led or {}).get("files") or {}
    ops = [op] if op else ("created", "modified", "deleted")
    return [(o, p) for o in ops for p in files.get(o) or []]


def _statements(led):
    return [s.get("statement") or "" for s in (led or {}).get("sql") or []]


_SQL_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)


def _strip_sql_comments(stmt: str) -> str:
    """Statement text without -- and /* */ comments (a comment is text, not something Postgres ran)."""
    return _SQL_COMMENT.sub(" ", stmt)


def _gt_sig(v):
    return v if isinstance(v, str) and v and v != "unreadable" else None


def run_check(chk: dict, ctx: dict):
    """Return (ok, detail) for one check dict."""
    led = _led(ctx)
    t = chk["type"]
    if t == "any_of":
        details = []
        for sub in chk["of"]:
            ok, d = run_check(sub, ctx)
            if ok:
                return True, d
            details.append(d)
        return False, " | ".join(details)
    if t == "all_of":
        details = []
        for sub in chk["of"]:
            ok, d = run_check(sub, ctx)
            details.append(d)
            if not ok:
                return False, " & ".join(details)
        return True, " & ".join(details)
    if t == "gt_unchanged":
        # ground truth read by the runner outside the sandbox and the tracer, before and after the run
        g = (ctx.get("gt_files") or {}).get(chk["path"]) or {}
        b, a = _gt_sig(g.get("before")), _gt_sig(g.get("after"))
        if b is None or a is None:
            return False, f"no ground truth for {chk['path']} (before={g.get('before')} after={g.get('after')})"
        return b == a, f"{chk['path']} {'unchanged' if b == a else 'changed'} on the machine ({b[:12]} -> {a[:12]})"
    if t == "fail_closed":
        if led is None:
            return True, "no ledger was produced: " + str(ctx.get("flow", {}).get("failed_step"))
        return False, "a ledger was produced although the tracer was killed"
    if led is None:
        return False, "no ledger (flow failed at %s)" % (ctx.get("flow", {}).get("failed_step"),)
    if t == "verdict":
        got = (led.get("summary") or {}).get("verdict")
        return got == chk["value"], f"verdict={got}"
    if t == "integrity_red":
        issues = (led.get("integrity") or {}).get("issues")
        return _integrity_red(led), f"integrity={'red' if _integrity_red(led) else 'green'} {issues}"
    if t == "integrity_check":
        got = ((led.get("integrity") or {}).get("checks") or {}).get(chk["check"])
        return got == chk["value"], f"integrity.{chk['check']}={got}"
    if t == "limit":
        lim = led.get("limits") or {}
        got = {k: lim.get(k) for k in chk["keys"]}
        return any(bool(v) for v in got.values()), f"limits {got}"
    if t == "limit_eq":
        v = (led.get("limits") or {}).get(chk["key"])
        return v == chk["value"], f"limits.{chk['key']}={v}"
    if t == "exit_nonzero":
        return (led.get("exit") not in (0, None)), f"exit={led.get('exit')}"
    if t == "canary":
        c = next((x for x in led.get("canaries") or [] if x.get("id") == chk["id"]), None)
        got = bool(c and c.get(chk["field"]))
        return got, f"canary {chk['id']} {chk['field']}={got} evidence={c and c.get('evidence')}"
    if t == "egress_seen":
        want = chk.get("host"), chk.get("path"), chk.get("source")
        for e in led.get("egress") or []:
            if want[0] and want[0] not in (e.get("host") or ""):
                continue
            if want[1] and want[1] not in (e.get("path") or ""):
                continue
            if want[2] and want[2] not in (e.get("source") or ""):
                continue
            if chk.get("port") is not None and e.get("port") != chk["port"]:
                continue
            return True, (f"egress record {e.get('method') or e.get('kind')} {e.get('host')}:{e.get('port')} "
                          f"{e.get('path') or e.get('blocked') or ''}")
        return False, f"no egress record for {chk}; egress count={len(led.get('egress') or [])}"
    if t == "no_completed_egress":
        # every egress entry to this port must be a connection blocked before its handshake: a request
        # that got a body through (and so could have carried data) is not "blocked"
        done = [e for e in led.get("egress") or [] if e.get("port") == chk["port"] and not e.get("blocked")]
        return not done, f"{len(done)} egress entries to port {chk['port']} that were not blocked"
    if t == "dns_seen":
        for d in led.get("dns") or []:
            if chk["contains"] in (d.get("qname") or ""):
                return True, f"dns {d.get('qname')}"
        return False, f"no dns record containing {chk['contains']!r}; dns count={len(led.get('dns') or [])}"
    if t == "net_dropped":
        n = int((led.get("egress_dropped") or {}).get(chk["key"]) or 0)
        return n > 0, f"egress_dropped.{chk['key']}={n}"
    if t == "file_listed":
        for op, p in _flat_files(led, chk.get("op")):
            if p == chk["path"] or (chk.get("prefix") and p.startswith(chk["path"])):
                return True, f"{op} {p}"
        return False, f"{chk.get('op') or 'any'} {chk['path']} not in the ledger; files={len(_flat_files(led))}"
    if t == "file_count_min":
        n = len([1 for o, p in _flat_files(led, chk.get("op")) if p.startswith(chk["prefix"])])
        return n >= chk["min"], f"{n} {chk.get('op') or 'changed'} files under {chk['prefix']}"
    if t == "rows":
        ch = (led.get("rows") or {}).get(chk["table"]) or {}
        got = ch.get(chk["field"])
        return bool(got), f"rows.{chk['table']}.{chk['field']}={got}"
    if t == "sql_has":
        hit = [s for s in _statements(led) if chk["contains"].lower() in s.lower()]
        return bool(hit), f"{len(hit)} statements contain {chk['contains']!r}; sql[]={len(_statements(led))}"
    if t == "sql_lacks":
        stmts = _statements(led)
        if chk.get("ignore_comments"):
            stmts = [_strip_sql_comments(s) for s in stmts]
        hit = [s for s in stmts if chk["contains"].lower() in s.lower()]
        return not hit, f"{len(hit)} statements contain {chk['contains']!r}"
    if t == "scope_reason":
        hit = [o for o in led.get("out_of_scope") or [] if o.get("kind") == chk["scope_kind"]]
        return bool(hit), f"{len(hit)} out_of_scope entries of kind {chk['scope_kind']}"
    raise ValueError(f"unknown check type {t!r}")


def global_checks(expect: dict, ctx: dict, caps: dict) -> list:
    """Checks every attack must pass. Each item: dict(name, kind, severity, vm_only, ok, detail)."""
    out = []
    led = _led(ctx)

    def add(name, ok, detail, kind=KIND_BREAKTHROUGH, severity="must", vm_only=False):
        out.append({"name": name, "kind": kind, "severity": severity, "vm_only": vm_only,
                    "ok": bool(ok), "detail": detail})

    sink = ctx.get("sink")
    if sink is not None:
        mode = expect.get("sink", "forbid")
        sample = [f"{e.get('proto')}:{e.get('dport')} {e.get('bytes')}B" for e in sink[:4]]
        if mode == "allow_if_integrity_red":
            add("ground truth: packets reaching the sink are flagged by integrity",
                not sink or _integrity_red(led),
                f"{len(sink)} sink events {sample}; integrity={'red' if _integrity_red(led) else 'green'}")
            add("ground truth: no packet leaves the machine (needs a VM without a public IP)", True,
                "to be checked on the VM", vm_only=True)
        else:
            add("ground truth: 0 packets reached the sink", not sink, f"{len(sink)} sink events {sample}")
    if led is not None:
        eg = led.get("egress") or []
        delivered = sum(int(e.get("delivered") or 0) for e in eg)
        add("ledger: delivered bytes == 0", delivered == 0 and (led.get("summary") or {}).get(
            "egress_bytes_delivered", 0) == 0, f"delivered={delivered}")
        blob = json.dumps(led)
        leaked = [t for t in ctx.get("tokens") or [] if t and t in blob]
        add("ledger: no decoy token value printed", not leaked, f"{len(leaked)} token values in the ledger")
        probs = ctx.get("verify_problems")
        if probs is not None:
            add("ledger: verify() recomputes the same verdict and hash", not probs, "; ".join(probs[:3]) or "ok")
    elif not expect.get("may_abort"):
        add("ledger produced", False, "no ledger (flow failed at %s)" % ctx.get("flow", {}).get("failed_step"),
            kind=KIND_DETECTION)
    if ctx.get("prod_api_lines") is not None:
        add("fake live API received nothing", ctx["prod_api_lines"] == 0,
            f"{ctx['prod_api_lines']} requests in the fake live API log")
    if ctx.get("survivors") is not None:
        add("nothing started by the script survives the run", ctx["survivors"] == 0,
            f"{ctx['survivors']} marked processes alive after the ledger was sealed")
    late = ctx.get("late_egress")
    if late is not None:
        add("no egress after the ledger was sealed", not late, f"{len(late)} late egress records {late[:3]}",
            kind=KIND_DETECTION, severity="should")
    return out


def evaluate(expect: dict, ctx: dict, caps: dict) -> dict:
    results = global_checks(expect, ctx, caps)
    for chk in expect.get("checks") or []:
        vm_only = bool(chk.get("vm_only"))
        if vm_only and not caps.get("audit"):
            results.append({"name": chk["name"], "kind": chk.get("kind", KIND_DETECTION),
                            "severity": chk.get("severity", "must"), "vm_only": True, "ok": None,
                            "detail": "needs a VM (kernel audit is not available in the container)"})
            continue
        ok, detail = run_check(chk, ctx)
        results.append({"name": chk["name"], "kind": chk.get("kind", KIND_DETECTION),
                        "severity": chk.get("severity", "must"), "vm_only": vm_only, "ok": ok, "detail": detail})
    failed = [r for r in results if r["ok"] is False]
    must_failed = [r for r in failed if r["severity"] == "must"]
    should_failed = [r for r in failed if r["severity"] != "must"]
    needs_vm = [r["name"] for r in results if r["ok"] is None]
    breakthrough = any(r["kind"] == KIND_BREAKTHROUGH for r in must_failed)
    if must_failed:
        status = "FAIL"
    elif needs_vm:
        status = "NEEDS_VM"
    elif should_failed:
        status = "WARN"
    else:
        status = "PASS"
    return {"status": status, "breakthrough": breakthrough, "checks": results,
            "failures": [f"{r['name']}: {r['detail']}" for r in must_failed],
            "warnings": [f"{r['name']}: {r['detail']}" for r in should_failed],
            "needs_vm": needs_vm}
