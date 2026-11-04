"""Check a Rehearsal Twin receipt.

    python -m rt.receipts.verify_receipt receipt.json [--pubkey KEY] [--twin-ledger twin.json] [--prod-ledger prod.json]

Checks the ed25519 signature over the receipt; with --pubkey (base64, hex or a
PEM file path) also that the receipt was signed by that key; with ledgers, that
their canonical sha256 matches the hashes the receipt names. Prints OK or the
problems; exit 0 when everything holds, 1 otherwise.

Without --pubkey the signature is only checked against the key embedded in the
receipt itself, which anyone can replace: that proves nothing about who signed.
It prints "signer NOT checked" and exits 2 (NO_SIGNER).

The receipt's `outcome` is printed too: "diverged" means production did not do
what was rehearsed (a valid signature on such a receipt is not a success).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from rt.ledger.canonical import ledger_sha256
from rt.receipts.sign import ReceiptError, load_public, verify_receipt

NO_SIGNER = 2


def _load(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check(receipt: dict, pubkey: bytes | None = None, twin_ledger: dict | None = None,
          prod_ledger: dict | None = None) -> list[str]:
    problems = verify_receipt(receipt, pubkey)
    if twin_ledger is not None and ledger_sha256(twin_ledger) != receipt.get("twin_ledger_sha256"):
        problems.append("twin ledger does not match twin_ledger_sha256")
    if prod_ledger is not None and ledger_sha256(prod_ledger) != receipt.get("prod_ledger_sha256"):
        problems.append("production ledger does not match prod_ledger_sha256")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="verify_receipt")
    ap.add_argument("receipt")
    ap.add_argument("--pubkey", help="expected public key: base64, hex, or a path to a PEM file")
    ap.add_argument("--twin-ledger")
    ap.add_argument("--prod-ledger")
    args = ap.parse_args(argv)
    try:
        pub = None
        if args.pubkey:
            text = args.pubkey
            if os.path.isfile(text):
                with open(text, encoding="utf-8") as f:
                    text = f.read()
            pub = load_public(text)
        receipt = _load(args.receipt)
        problems = check(receipt, pub,
                         _load(args.twin_ledger) if args.twin_ledger else None,
                         _load(args.prod_ledger) if args.prod_ledger else None)
    except (OSError, json.JSONDecodeError, ReceiptError, ValueError) as e:
        print(f"FAIL  {type(e).__name__}: {e}")
        return 1
    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        return 1
    ledgers = ", ledgers match" if args.twin_ledger or args.prod_ledger else ""
    outcome = receipt.get("outcome") if isinstance(receipt, dict) else None
    tail = f"; outcome {outcome}" if outcome else ""
    if pub is None:
        print("UNVERIFIED  signature matches the key embedded in the receipt, but the signer NOT checked "
              f"(anyone can embed a key; pass --pubkey){ledgers}{tail}")
        return NO_SIGNER
    print(f"OK  signature valid, signed by the given key{ledgers}{tail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
