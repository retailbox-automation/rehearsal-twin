"""python -m rt.orchestrator {presets,run,show,approve,reap,restore-tick}

Live: reads the same environment as the API (see rt/orchestrator/settings.py). Events go to
stdout as JSON lines; the record lives in RT_DATA_DIR, so the web screen shows CLI runs too.
`approve` takes the fields explicitly (files and drift override too): it is the human step.
`reap` and `restore-tick` are the systemd timer jobs: one JSON line per tick on stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from rt.orchestrator.core import Busy, Conflict, NotConfigured, build_live
from rt.orchestrator.presets import load_presets
from rt.orchestrator.settings import Settings
from rt.orchestrator.store import utc_now


def _print(obj) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m rt.orchestrator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("presets", help="list presets")
    r = sub.add_parser("run", help="rehearse a preset, a script or a goal until it awaits approval")
    r.add_argument("--preset")
    r.add_argument("--script", help="path to a script file")
    r.add_argument("--goal")
    r.add_argument("--scope", help="path to a scope.json (required with --script or --goal)")
    s = sub.add_parser("show", help="print the record view")
    s.add_argument("id")
    a = sub.add_parser("approve", help="approve by the exact ledger, script, snapshot and production state")
    a.add_argument("id")
    for f in ("ledger-sha256", "script-sha256", "snapshot-id", "prod-state-version"):
        a.add_argument(f"--{f}", required=True)
    a.add_argument("--files-sha256", help="required when the rehearsal has companion files")
    a.add_argument("--override-drift", action="store_true",
                   help="approve although the twin did not start from production's current data")
    rp = sub.add_parser("reap", help="one reaper tick: delete rt-twin older than the TTL unless a live lease holds it")
    rp.add_argument("--ttl", type=float, default=None, help="seconds (default RT_REAPER_TTL_S, 900)")
    rp.add_argument("--dry-run", action="store_true")
    sub.add_parser("restore-tick", help="ask the API to restore production when nothing is open")
    args = ap.parse_args(argv)

    settings = Settings.from_env()
    if args.cmd == "presets":
        for p in load_presets(settings.presets_dir).values():
            _print(p.public())
        return 0
    if args.cmd == "reap":
        return reap_tick_cli(settings, args.ttl, args.dry_run)
    if args.cmd == "restore-tick":
        return restore_tick_cli(settings)
    try:
        orch = build_live(settings)
        if args.cmd == "run":
            scope = None
            if args.scope:
                with open(args.scope, encoding="utf-8") as f:
                    scope = json.load(f)
            script = None
            if args.script:
                with open(args.script, encoding="utf-8") as f:
                    script = f.read()
            rec = orch.create(preset=args.preset, script=script, goal=args.goal, scope=scope)
            rec = orch.run(rec["id"])
        elif args.cmd == "show":
            _print(orch.view(args.id))
            return 0
        else:
            req = {"ledger_sha256": args.ledger_sha256, "script_sha256": args.script_sha256,
                   "snapshot_id": args.snapshot_id, "prod_state_version": args.prod_state_version,
                   "files_sha256": args.files_sha256, "override_drift": args.override_drift}
            rec = orch.approve_and_apply(args.id, req)
        for ev in orch.store.events(rec["id"]):
            if ev["type"] != "view":
                _print(ev)
        _print({"id": rec["id"], "status": rec["status"], "error": rec.get("error"), "approval": rec.get("approval")})
        return 0 if rec["status"] in ("awaiting_approval", "applied") else 1
    except Conflict as e:
        _print({"conflict": e.reasons})
        return 4
    except (Busy, NotConfigured, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def reap_tick_cli(settings: Settings, ttl: float | None, dry_run: bool, vultr_factory=None) -> int:
    from rt.orchestrator.leases import append_log, reap_tick
    from rt.twin.vultr import Vultr

    if vultr_factory is not None:
        Vultr = vultr_factory  # noqa: N806 (tests pass a client bound to the fake API)

    from rt.orchestrator.spend import read_pending

    client = None
    try:
        client = Vultr(timing=lambda _line: None)
        line = reap_tick(client, settings.data_dir,
                         ttl_s=settings.reaper_ttl_s if ttl is None else ttl, stale_s=settings.lease_stale_s,
                         dry_run=dry_run)
        code = 0
    except Exception as e:  # one line per tick, failures included
        line = {"ts": utc_now(), "error": f"{type(e).__name__}: {e}"[:300]}
        code = 1
    if client is not None:  # the same line leaves a trace of the account's pending charges
        try:
            line["spend_pending"] = read_pending(client)
        except Exception as e:
            line["spend_error"] = type(e).__name__
        line["spend_cap"] = settings.spend_cap_usd
    line["tick"] = "reap"
    _print(line)
    try:
        append_log(settings.data_dir, line)
    except OSError:
        pass
    return code


def restore_tick_cli(settings: Settings, opener=urllib.request.urlopen) -> int:
    base = (os.environ.get("RT_API_URL") or "http://127.0.0.1:8000").rstrip("/")
    line: dict = {"ts": utc_now(), "tick": "restore"}
    if not settings.api_token:
        line["error"] = "RT_API_TOKEN is not set; the restore endpoint needs it"
        _print(line)
        return 2
    req = urllib.request.Request(base + "/api/prod/restore", data=json.dumps({"when": "idle"}).encode(),
                                 method="POST", headers={"Content-Type": "application/json",
                                                         "Authorization": "Bearer " + settings.api_token})
    try:
        with opener(req, timeout=30) as resp:
            line["http"] = resp.status
            line["result"] = json.loads(resp.read() or b"{}")
        code = 0
    except urllib.error.HTTPError as e:
        line["http"] = e.code
        line["error"] = e.read().decode("utf-8", "replace")[:300]
        code = 1
    except (urllib.error.URLError, OSError, ValueError) as e:
        line["error"] = f"{type(e).__name__}: {e}"[:300]
        code = 1
    _print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
