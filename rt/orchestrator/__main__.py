"""python -m rt.orchestrator {presets,run,show,approve}

Live: reads the same environment as the API (see rt/orchestrator/settings.py). Events go to
stdout as JSON lines; the record lives in RT_DATA_DIR, so the web screen shows CLI runs too.
`approve` takes the four fields explicitly: it is the human step.
"""
from __future__ import annotations

import argparse
import json
import sys

from rt.orchestrator.core import Busy, Conflict, NotConfigured, build_live
from rt.orchestrator.presets import load_presets
from rt.orchestrator.settings import Settings


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
    args = ap.parse_args(argv)

    settings = Settings.from_env()
    if args.cmd == "presets":
        for p in load_presets(settings.presets_dir).values():
            _print(p.public())
        return 0
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
                   "snapshot_id": args.snapshot_id, "prod_state_version": args.prod_state_version}
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


if __name__ == "__main__":
    sys.exit(main())
