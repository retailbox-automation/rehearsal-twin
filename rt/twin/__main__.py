"""python -m rt.twin {create,exec,destroy,reap,bench}

Vultr timing lines go to stderr (or RT_VULTR_TIMING_LOG); results go to stdout as JSON.
Exit codes: 0 ok, 2 error, 3 account blocker (balance/credit/quota: a human decides).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import TextIO

from rt.twin.bench import MAX_BENCH_N, run_bench
from rt.twin.lifecycle import ALLOWED_PLANS, DEFAULT_PLAN, DEFAULT_REGION, SSH, Twin, TwinError, new_rid
from rt.twin.reaper import DEFAULT_TTL_S, reap
from rt.twin.vultr import AccountBlocked, Vultr, VultrError


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m rt.twin", description="Disposable twins on Vultr.")
    p.add_argument("--jump", default=os.environ.get("RT_JUMP_HOST") or None,
                   help="jump host (control VM) for SSH into the VPC; default $RT_JUMP_HOST")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="create a twin from a snapshot and wait until SSH answers")
    c.add_argument("--snapshot", required=True)
    c.add_argument("--vpc", required=True)
    c.add_argument("--rid", default=None)
    c.add_argument("--plan", default=DEFAULT_PLAN, choices=ALLOWED_PLANS)
    c.add_argument("--region", default=DEFAULT_REGION)
    c.add_argument("--timeout", type=float, default=900.0)
    c.add_argument("--no-wait", action="store_true")

    e = sub.add_parser("exec", help="run a command on a twin")
    e.add_argument("--id", required=True)
    e.add_argument("--timeout", type=float, default=60.0)
    e.add_argument("argv", nargs=argparse.REMAINDER)

    d = sub.add_parser("destroy", help="delete a twin and wait until it is gone from the list")
    d.add_argument("--id", required=True)
    d.add_argument("--timeout", type=float, default=300.0)

    r = sub.add_parser("reap", help="delete rt-twin instances older than the TTL")
    r.add_argument("--ttl", type=float, default=DEFAULT_TTL_S, help="seconds (default 900)")
    r.add_argument("--dry-run", action="store_true")

    b = sub.add_parser("bench", help="measure create -> ready -> ssh echo -> delete -> absent")
    b.add_argument("--n", type=int, required=True, help=f"cycles, 1..{MAX_BENCH_N}, one live twin at a time")
    b.add_argument("--snapshot", required=True)
    b.add_argument("--vpc", required=True)
    b.add_argument("--plan", default=DEFAULT_PLAN, choices=ALLOWED_PLANS)
    b.add_argument("--region", default=DEFAULT_REGION)
    b.add_argument("--timeout", type=float, default=900.0)
    b.add_argument("--out", default="bench/twin_lifecycle.json")
    return p


def main(argv: list[str] | None = None, *, client: Vultr | None = None, ssh: SSH | None = None,
         out: TextIO = sys.stdout) -> int:
    args = _parser().parse_args(argv)

    def emit(row: dict) -> None:
        out.write(json.dumps(row) + "\n")

    try:
        client = client or Vultr()
        need_ssh = args.cmd in ("exec", "bench") or (args.cmd == "create" and not args.no_wait)
        if ssh is None and need_ssh:
            ssh = SSH(jump=args.jump)

        if args.cmd == "create":
            rid = args.rid or new_rid()
            twin = Twin.create(args.snapshot, rid, args.vpc, args.plan, region=args.region, client=client, ssh=ssh)
            row = {"id": twin.id, "rid": rid, "label": twin.label, "host": None}
            if not args.no_wait:
                try:
                    twin.wait_ready(timeout=args.timeout)
                except Exception:
                    twin.destroy()
                    raise
                row["host"] = twin.host
            emit(row)
            return 0

        if args.cmd == "exec":
            cmd = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
            if not cmd:
                raise TwinError("exec: no command given")
            twin = Twin.attach(args.id, client=client, ssh=ssh)
            if not twin.host:
                raise TwinError(f"{args.id} is not ready yet")
            rc, so, se = twin.exec(cmd, timeout=args.timeout)
            out.write(so)
            sys.stderr.write(se)
            return rc

        if args.cmd == "destroy":
            twin = Twin.attach(args.id, client=client, ssh=ssh)
            secs = twin.destroy(timeout=args.timeout)
            emit({"id": args.id, "absent": True, "seconds": secs})
            return 0

        if args.cmd == "reap":
            for row in reap(client, args.ttl, dry_run=args.dry_run):
                emit(row)
            return 0

        if args.cmd == "bench":
            res = run_bench(args.n, args.snapshot, args.vpc, args.out, plan=args.plan, region=args.region,
                            client=client, ssh=ssh, ready_timeout_s=args.timeout)
            emit({"out": args.out, "n": res["n"], "ok": res["ok"], "summary": res["summary"]})
            return 0 if res["ok"] == res["n"] else 1

    except AccountBlocked as e:
        print(f"BLOCKER (account): {e}", file=sys.stderr)
        raise SystemExit(3) from None
    except (TwinError, VultrError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2) from None
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
