"""rtrace: before / run / after / diff on the target machine (Python 3 stdlib + psql).

    rtrace before --scope scope.json > state0.json
    rtrace run --script s.sh --wall 60 --mem 512M --pids 256 > run.json
    rtrace after --scope scope.json > state1.json
    rtrace diff state0.json state1.json run.json --scope scope.json > ledger.json

Keep the script, scope.json and every state/run/ledger file in /opt/rt/work: files written
under a tracked root (/srv, /etc, /root, ...) during the run show up in the ledger.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import time

from ..ledger.canonical import dumps
from ..ledger.scope import finalize, normalize_scope
from . import config, diff, egress, fsstate, logs, pgstate, runner


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def log_offsets(cfg: dict) -> dict:
    return {
        "pg_log": logs.size_of((cfg.get("pg") or {}).get("log_path", "")),
        "audit_log": logs.size_of(cfg.get("audit_log", "")),
        "egress_log": logs.size_of(cfg.get("egress_log", "")),
    }


def egress_active() -> bool:
    try:
        p = subprocess.run(["systemctl", "is-active", "--quiet", "rt-egress.service"], timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0


def iptables_state() -> dict:
    return {"rules_sha256": egress.rules_digest(), "counters": egress.counters()}


_EXPIRES = re.compile(r"\s+expires\s+-?\d+sec")


def normalize_routes(text: str) -> str:
    """Route listing without the lifetimes that count down on their own (router advertisements)."""
    return "\n".join(_EXPIRES.sub("", line).rstrip() for line in text.splitlines())


def routes_digest() -> str | None:
    """Digest of every routing table (IPv4 and IPv6); None when it cannot be read."""
    import hashlib
    h = hashlib.sha256()
    ok = False
    for argv in (["ip", "-4", "route", "show", "table", "all"], ["ip", "-6", "route", "show", "table", "all"]):
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode == 0:
            ok = True
            h.update(normalize_routes(p.stdout).encode())
    if not ok:
        try:
            with open("/proc/net/route", encoding="utf-8") as f:
                h.update(f.read().encode())
        except OSError:
            return None
    return h.hexdigest()


def egress_service() -> dict:
    info = runner.show("rt-egress.service", "ActiveState", "MainPID", "NRestarts")
    return {"active": info.get("ActiveState"), "main_pid": info.get("MainPID"), "restarts": info.get("NRestarts")}


def tracked_roots(cfg: dict, scope_raw) -> list:
    roots = list(cfg.get("track_roots") or [])
    if scope_raw:
        for p in normalize_scope(scope_raw)["paths"]:
            if not any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots):
                roots.append(p)
    return roots


def self_digest(cfg: dict) -> str:
    root = cfg.get("self_root") or config.RT_HOME
    m = fsstate.scan([root], exclude=[root + "/state", root + "/work", root + "/egress/certs"],
                     hash_limit=cfg.get("hash_limit", 4 << 20))
    m = {p: e for p, e in m.items() if "/__pycache__" not in p}
    return fsstate.tree_digest(m)


def capture(cfg: dict, scope_raw=None, settle_max: float = 0.0) -> dict:
    if settle_max > 0:
        settle(cfg, settle_max)
    offsets = log_offsets(cfg)
    taken = _now_iso()
    roots = tracked_roots(cfg, scope_raw)
    return {
        "kind": "rt-state",
        "taken_at": taken,
        "roots": roots,
        "offsets": offsets,
        "files": fsstate.scan(roots, cfg.get("exclude") or (), cfg.get("hash_limit", 4 << 20)),
        "pg": pgstate.snapshot(cfg),
        "iptables": iptables_state(),
        "egress_active": egress_active(),
        "egress_service": egress_service(),
        "routes_sha256": routes_digest(),
        "self_digest": self_digest(cfg),
    }


def settle(cfg: dict, settle_max: float, quiet_s: float = 2.0, step: float = 0.5):
    """Wait until the egress log stops growing (asynchronous webhooks after a commit)."""
    path = cfg.get("egress_log", "")
    deadline = time.monotonic() + settle_max
    last = logs.size_of(path)
    quiet_since = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(step)
        size = logs.size_of(path)
        if size != last:
            last = size
            quiet_since = time.monotonic()
        elif time.monotonic() - quiet_since >= quiet_s:
            return


def cmd_run(args, cfg) -> dict:
    start_offsets = log_offsets(cfg)
    start_ipt = iptables_state()
    res = runner.run_script(args.script, wall=args.wall, mem=args.mem, pids=args.pids, cwd=args.cwd,
                            slice_name=cfg.get("run_slice", "rt.slice"),
                            stats_dir=(cfg.get("self_root") or config.RT_HOME) + "/state",
                            allow=tuple(cfg.get("sandbox_allow") or ()))
    res["kind"] = "rt-run"
    res["offsets_start"] = start_offsets
    res["offsets_end"] = log_offsets(cfg)
    res["iptables_start"] = start_ipt
    return res


def read_sources(cfg: dict, state0: dict, state1: dict, run: dict) -> dict:
    start = run.get("offsets_start") or state0.get("offsets") or {}
    end = state1.get("offsets") or {}
    pg = cfg.get("pg") or {}
    sql = logs.parse_pg_log(logs.read_window(pg.get("log_path", ""), start.get("pg_log", 0), end.get("pg_log")),
                            exclude_apps=tuple(pg.get("exclude_apps") or ()))
    defs = config.load_canaries(cfg.get("canaries_path", ""))
    keys = {d["audit_key"] for d in defs if d.get("audit_key")}
    audit = logs.parse_audit_log(logs.read_window(cfg.get("audit_log", ""), start.get("audit_log", 0),
                                                  end.get("audit_log")), keys or None)
    records, bad = logs.parse_jsonl(logs.read_window(cfg.get("egress_log", ""), start.get("egress_log", 0),
                                                     end.get("egress_log")))
    return {"sql": sql, "audit": audit, "egress_records": records, "egress_bad_lines": bad,
            "canary_defs": defs}


def cmd_diff(args, cfg) -> dict:
    state0, state1, run = _load_json(args.state0), _load_json(args.state1), _load_json(args.run)
    scope_raw = _load_json(args.scope) if args.scope else {}
    facts = diff.build_facts(state0, state1, run, read_sources(cfg, state0, state1, run), cfg)
    facts["generated_at"] = _now_iso()
    return finalize(facts, scope_raw)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="rtrace")
    ap.add_argument("--config", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("before")
    b.add_argument("--scope")
    r = sub.add_parser("run")
    r.add_argument("--script", required=True)
    r.add_argument("--wall", type=float, default=60)
    r.add_argument("--mem", default="512M")
    r.add_argument("--pids", type=int, default=256)
    r.add_argument("--cwd")
    a = sub.add_parser("after")
    a.add_argument("--scope")
    a.add_argument("--settle-max", type=float, default=20.0)
    d = sub.add_parser("diff")
    d.add_argument("state0")
    d.add_argument("state1")
    d.add_argument("run")
    d.add_argument("--scope")
    args = ap.parse_args(argv)
    cfg = config.load(args.config)
    if os.geteuid() != 0 and args.cmd in ("before", "after", "run"):
        print("rtrace: must run as root", file=sys.stderr)
        return 2

    if args.cmd == "before":
        out = capture(cfg, _load_json(args.scope) if args.scope else None)
    elif args.cmd == "after":
        out = capture(cfg, _load_json(args.scope) if args.scope else None, settle_max=args.settle_max)
    elif args.cmd == "run":
        out = cmd_run(args, cfg)
    else:
        out = cmd_diff(args, cfg)
    sys.stdout.write(dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
