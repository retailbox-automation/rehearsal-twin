"""python -m rt.ledger {compare,verify,hash} ..."""
from __future__ import annotations

import argparse
import json
import sys

from .canonical import dumps, ledger_sha256
from .compare import compare
from .scope import verify


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m rt.ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compare", help="twin ledger vs production ledger -> compare.json")
    c.add_argument("twin")
    c.add_argument("prod")
    v = sub.add_parser("verify", help="recompute scope check and hash; exit 1 on mismatch")
    v.add_argument("ledger")
    v.add_argument("--scope", required=True)
    h = sub.add_parser("hash", help="print the canonical ledger_sha256")
    h.add_argument("ledger")
    args = ap.parse_args(argv)

    if args.cmd == "compare":
        sys.stdout.write(dumps(compare(_load(args.twin), _load(args.prod))))
        return 0
    if args.cmd == "verify":
        problems = verify(_load(args.ledger), _load(args.scope))
        sys.stdout.write(dumps({"ok": not problems, "problems": problems}))
        return 0 if not problems else 1
    print(ledger_sha256(_load(args.ledger)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
