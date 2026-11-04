"""verify_receipt without --pubkey must not print OK (review finding 19)."""
from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rt.receipts.sign import Signer
from rt.receipts.verify_receipt import NO_SIGNER, main as verify_main


def _receipt(tmp_path, signer, **extra):
    r = signer.sign({"kind": "rehearsal-twin/receipt", "issued_at": "2026-11-04T17:00:00Z",
                     "twin_ledger_sha256": "a" * 64, "prod_ledger_sha256": "a" * 64, **extra})
    path = tmp_path / "r.json"
    path.write_text(json.dumps(r))
    return path


def test_without_pubkey_the_signer_is_not_checked(tmp_path, capsys):
    path = _receipt(tmp_path, Signer(Ed25519PrivateKey.generate()))
    assert verify_main([str(path)]) == NO_SIGNER != 0
    out = capsys.readouterr().out
    assert "signer NOT checked" in out and not out.startswith("OK")


def test_a_receipt_signed_by_anyone_is_not_ok_without_pubkey(tmp_path, capsys):
    stranger = Signer(Ed25519PrivateKey.generate())  # self-consistent, but not our key
    path = _receipt(tmp_path, stranger, outcome="applied")
    assert verify_main([str(path)]) != 0
    assert "OK" not in capsys.readouterr().out.split()[0]


def test_with_pubkey_ok_and_outcome_shown(tmp_path, capsys):
    signer = Signer(Ed25519PrivateKey.generate())
    path = _receipt(tmp_path, signer, outcome="diverged")
    assert verify_main([str(path), "--pubkey", signer.public_info()["public_key"]]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK  signature valid") and "outcome diverged" in out
    other = Signer(Ed25519PrivateKey.generate())
    assert verify_main([str(path), "--pubkey", other.public_info()["public_key"]]) == 1
