"""Ed25519 signatures over a receipt.

The signed bytes are the canonical JSON of the receipt without its `signature`
field: keys sorted, no whitespace, UTF-8. Unlike the ledger hash nothing is
stripped, so timestamps are covered by the signature too.

Key: env RT_RECEIPT_SIGNING_KEY, the 32-byte private seed as base64 or hex,
or a PEM (PKCS#8) private key. The value is never printed or written anywhere
by this module; only the public key and its id leave it.

    python -m rt.receipts.sign keygen --env-file /etc/rt/env   # appends a new key, prints the public key
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ENV_NAME = "RT_RECEIPT_SIGNING_KEY"
ALG = "ed25519"


class ReceiptError(Exception):
    pass


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _raw_public(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


def _decode_seed(value: str) -> bytes:
    v = value.strip()
    if len(v) == 64:
        try:
            return bytes.fromhex(v)
        except ValueError:
            pass
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decode(v + "=" * (-len(v) % 4))
        except (binascii.Error, ValueError):
            continue
        if len(raw) == 32:
            return raw
    raise ReceiptError(f"{ENV_NAME} is not a 32-byte seed (base64 or hex) or a PEM private key")


def load_private(value: str) -> Ed25519PrivateKey:
    if not value or not value.strip():
        raise ReceiptError(f"{ENV_NAME} is not set")
    if "-----BEGIN" in value:
        try:
            key = serialization.load_pem_private_key(value.encode(), password=None)
        except (ValueError, TypeError):
            raise ReceiptError(f"{ENV_NAME} is not a readable PEM private key") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise ReceiptError(f"{ENV_NAME} is not an Ed25519 key")
        return key
    return Ed25519PrivateKey.from_private_bytes(_decode_seed(value))


def load_public(value: str) -> bytes:
    """Raw 32-byte public key from base64, hex or a PEM public key."""
    v = value.strip()
    if "-----BEGIN" in v:
        key = serialization.load_pem_public_key(v.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ReceiptError("not an Ed25519 public key")
        return _raw_public(key)
    try:
        return _decode_seed(v)
    except ReceiptError:
        raise ReceiptError("public key is not 32 bytes of base64 or hex") from None


class Signer:
    def __init__(self, private: Ed25519PrivateKey):
        self._key = private
        self.public_raw = _raw_public(private.public_key())
        self.key_id = key_id(self.public_raw)

    def __repr__(self) -> str:  # never show key material
        return f"Signer(key_id={self.key_id!r})"

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Signer":
        env = os.environ if env is None else env
        return cls(load_private(env.get(ENV_NAME, "")))

    def public_info(self) -> dict:
        return {"alg": ALG, "key_id": self.key_id,
                "public_key": base64.b64encode(self.public_raw).decode()}

    def sign(self, receipt: dict) -> dict:
        body = {k: v for k, v in receipt.items() if k != "signature"}
        sig = self._key.sign(canonical(body))
        return {**body, "signature": {**self.public_info(), "value": base64.b64encode(sig).decode()}}


def verify_receipt(receipt: dict, public_key: bytes | None = None) -> list[str]:
    """Return a list of problems; empty means the signature is valid.

    With public_key given, the key embedded in the receipt must be that key.
    """
    problems: list[str] = []
    sig = receipt.get("signature")
    if not isinstance(sig, dict):
        return ["receipt has no signature"]
    if sig.get("alg") != ALG:
        return [f"unsupported signature algorithm {sig.get('alg')!r}"]
    try:
        embedded = base64.b64decode(sig.get("public_key") or "", validate=True)
        value = base64.b64decode(sig.get("value") or "", validate=True)
    except (binascii.Error, ValueError):
        return ["signature fields are not base64"]
    if len(embedded) != 32:
        return ["embedded public key is not 32 bytes"]
    if sig.get("key_id") != key_id(embedded):
        problems.append("key_id does not match the embedded public key")
    if public_key is not None and public_key != embedded:
        problems.append("receipt was signed by a different key than the one given")
    body = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(embedded).verify(value, canonical(body))
    except InvalidSignature:
        problems.append("signature does not match the receipt content")
    return problems


def _keygen(env_file: str) -> int:
    lines = []
    if os.path.exists(env_file):
        with open(env_file, encoding="utf-8") as f:
            lines = f.read().splitlines()
        if any(line.startswith(ENV_NAME + "=") for line in lines):
            print(f"{env_file} already has {ENV_NAME}; not replacing it", file=sys.stderr)
            return 1
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(f"{ENV_NAME}={base64.b64encode(seed).decode()}\n")
    os.chmod(env_file, 0o600)
    print(json.dumps(Signer(key).public_info()))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m rt.receipts.sign")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="append a new signing key to an env file (mode 600); print the public key")
    k.add_argument("--env-file", required=True)
    sub.add_parser("pubkey", help=f"print the public key of ${ENV_NAME}")
    args = ap.parse_args(argv)
    if args.cmd == "keygen":
        return _keygen(args.env_file)
    try:
        print(json.dumps(Signer.from_env().public_info()))
    except ReceiptError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
