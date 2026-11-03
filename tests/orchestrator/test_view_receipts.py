from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rt.ledger import finalize
from rt.orchestrator.presets import load_presets
from rt.orchestrator.remote import manifest_changes, state_manifest, state_version
from rt.orchestrator.view import ledger_view, screen_summary
from rt.receipts.sign import ReceiptError, Signer, load_private, verify_receipt
from rt.receipts.verify_receipt import main as verify_main
from tests.orchestrator import ledgers as L

REPO = Path(__file__).resolve().parents[2]
SCOPE_A = {"paths": ["/srv/app/tmp"], "tables": ["sessions"], "hosts": []}


def _covers_everything(ledger, rows):
    assert sum(r["out_of_scope_rows"] for r in rows) == len(ledger["out_of_scope"])
    for r in rows:
        assert (r["out_of_scope_rows"] > 0) == (r["verdict"] == "out_of_scope") or r["kind"] in ("canary",
                                                                                                   "integrity")


def test_ledger_view_preset_a_risky():
    led = finalize(L.risky_a_facts(), SCOPE_A)
    rows = ledger_view(led)
    by = {r["target"]: r for r in rows}
    assert by["/srv/app/tmp"]["verdict"] == "in_scope" and by["/srv/app/tmp"]["delta"] == "-150 files, -2 dirs"
    assert by["/srv/app"]["verdict"] == "out_of_scope" and by["/srv/app"]["delta"].startswith("-51 files")
    assert by["/srv/shared"]["reason"] == "not under declared paths (/srv/app/tmp)"
    assert by["table sessions"]["verdict"] == "in_scope" and by["table sessions"]["delta"] == "-240 rows"
    assert by["POST prod-api.internal/purge"]["delta"] == "1 call, 0 B delivered"
    assert {"decoy env-file", "decoy purge-url"} <= set(by)
    path_files = sum(r["count"] for r in rows if r["kind"] == "path")
    assert path_files == len(led["files"]["deleted"]) + len(led["dirs"]["deleted"])
    _covers_everything(led, rows)
    s = screen_summary(led, rows)
    assert s["deleted_files"] == 221 and s["outside_count"] == 71
    assert s["egress_line"] == {"method": "POST", "target": "prod-api.internal/purge",
                                "note": "blocked, recorded, 0 bytes delivered"}


def test_ledger_view_never_recomputes_the_verdict():
    led = finalize(L.risky_a_facts(), SCOPE_A)
    led["out_of_scope"] = [o for o in led["out_of_scope"] if o["kind"] != "path"]
    rows = ledger_view(led)
    assert {r["verdict"] for r in rows if r["kind"] == "path"} == {"in_scope"}
    _covers_everything(led, rows)


def test_ledger_view_tables_and_webhooks():
    facts = {"files": {}, "rows": {"prices": {"inserted": 0, "deleted": 0, "updated": 93}},
             "egress": [{"kind": "https", "method": "POST", "host": "hooks.partner.example", "path": "/price-changed",
                         "port": 443, "bytes_attempted": 80, "delivered": 0, "source": "shop-webhooks.service"}] * 93,
             "dns": [{"qname": "hooks.partner.example", "count": 93}], "canaries": [], "exit": 0, "limits": {}}
    led = finalize(facts, {"tables": {"prices": {"max_rows": 31}}, "hosts": []})
    rows = ledger_view(led)
    assert [(r["target"], r["verdict"]) for r in rows] == [("table prices", "out_of_scope"),
                                                           ("POST hooks.partner.example/price-changed",
                                                            "out_of_scope")]
    assert rows[0]["reason"] == "93 rows changed, declared budget max_rows 31"
    assert rows[1]["sources"] == ["shop-webhooks.service"]
    _covers_everything(led, rows)
    assert screen_summary(led, rows)["headline"] == "updated 93 rows"


def test_state_version_ignores_hostname_and_mtime_but_not_data():
    s0 = L.machine_state()
    s1 = copy.deepcopy(s0)
    s1["files"]["/etc/hostname"]["sha256"] = "twin-hostname"
    s1["files"]["/srv/app/.env.canary"]["mtime_ns"] += 5
    s1["taken_at"] = "later"
    s1["offsets"]["pg_log"] = 999
    m0, m1 = state_manifest(s0, SCOPE_A), state_manifest(s1, SCOPE_A)
    assert state_version(m0) == state_version(m1)
    s1["pg"]["tables"]["prices"]["rows"]["p1"] = "changed"
    m2 = state_manifest(s1, SCOPE_A)
    assert state_version(m2) != state_version(m0)
    assert manifest_changes(m0, m2) == ["prices changed"]


def test_presets_load_and_match_the_preset_doc():
    presets = load_presets(REPO / "presets")
    assert sorted(presets) == ["a", "b", "c"]
    a, b, c = presets["a"], presets["b"], presets["c"]
    assert 'rm -rf "${APP_ROOT}/${CACHE_SUBDIR}"/*' in a.script and "prod-api.internal/purge" in a.script
    assert a.scope == {"paths": ["/srv/app/tmp"], "tables": ["sessions"], "hosts": []}
    assert b.files["schema_tables.txt"].decode().split() == ["customers", "products", "prices", "sessions", "webhooks",
                                                    "api_keys"]
    assert b.scope["tables"] == ["legacy_orders"]
    assert "WHERE category = 'winter' OR category = 'snow' AND active" in c.script
    assert c.scope["tables"] == {"prices": {"max_rows": 31}} and c.scope["hosts"] == []
    for p in presets.values():
        r = subprocess.run(["bash", "-n"], input=p.script.encode(), capture_output=True)
        assert r.returncode == 0, r.stderr


def test_receipt_signature_round_trip(tmp_path):
    signer = Signer(Ed25519PrivateKey.generate())
    receipt = signer.sign({"kind": "rehearsal-twin/receipt", "issued_at": "2026-11-03T17:00:00Z",
                           "twin_ledger_sha256": "a" * 64, "prod_ledger_sha256": "a" * 64})
    pub = base64.b64decode(signer.public_info()["public_key"])
    assert verify_receipt(receipt, pub) == []
    assert verify_receipt(dict(receipt, issued_at="2026-11-03T18:00:00Z"))  # timestamps are signed too
    other = Signer(Ed25519PrivateKey.generate())
    assert "different key" in " ".join(verify_receipt(receipt, base64.b64decode(other.public_info()["public_key"])))
    forged = other.sign({k: v for k, v in receipt.items() if k != "signature"})
    forged["signature"]["key_id"] = receipt["signature"]["key_id"]
    assert verify_receipt(forged)
    path = tmp_path / "r.json"
    path.write_text(json.dumps(receipt))
    assert verify_main([str(path), "--pubkey", signer.public_info()["public_key"]]) == 0
    path.write_text(json.dumps(dict(receipt, prod_ledger_sha256="b" * 64)))
    assert verify_main([str(path)]) == 1


def test_signing_key_formats(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    ids = {Signer(load_private(v)).key_id for v in (base64.b64encode(seed).decode(), seed.hex(), pem)}
    assert len(ids) == 1
    monkeypatch.setenv("RT_RECEIPT_SIGNING_KEY", base64.b64encode(seed).decode())
    s = Signer.from_env()
    assert s.key_id in ids and base64.b64encode(seed).decode() not in repr(s)
    for bad in ("", "not-a-key", base64.b64encode(b"short").decode()):
        with pytest.raises(ReceiptError):
            load_private(bad)


def test_keygen_writes_env_file_without_printing_the_key(tmp_path):
    env = tmp_path / "env"
    r = subprocess.run([sys.executable, "-m", "rt.receipts.sign", "keygen", "--env-file", str(env)],
                       capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, r.stderr
    line = env.read_text().strip()
    assert line.startswith("RT_RECEIPT_SIGNING_KEY=") and (env.stat().st_mode & 0o777) == 0o600
    assert line.split("=", 1)[1] not in r.stdout and json.loads(r.stdout)["alg"] == "ed25519"
    again = subprocess.run([sys.executable, "-m", "rt.receipts.sign", "keygen", "--env-file", str(env)],
                           capture_output=True, text=True, cwd=REPO)
    assert again.returncode == 1 and env.read_text().strip() == line


def test_control_deploy_script_is_valid_bash():
    script = REPO / "deploy" / "control.sh"
    assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0
    text = script.read_text()
    assert "/etc/rt/env" in text and "127.0.0.1" in text and "flush_interval -1" in text


def test_cli_presets_and_missing_settings(tmp_path, monkeypatch, capsys):
    from rt.orchestrator.__main__ import main as cli
    from rt.orchestrator.settings import LIVE_REQUIRED
    for name in LIVE_REQUIRED:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RT_DATA_DIR", str(tmp_path / "data"))
    assert cli(["presets"]) == 0
    assert [json.loads(line)["id"] for line in capsys.readouterr().out.splitlines()] == ["a", "b", "c"]
    assert cli(["run", "--preset", "a"]) == 2
    err = capsys.readouterr().err
    assert "missing settings" in err and "VULTR_API_KEY" in err
    assert not (tmp_path / "data").exists()
