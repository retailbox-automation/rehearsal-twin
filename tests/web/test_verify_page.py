"""The /verify page: web/verify.js must rebuild Python's canonical bytes exactly and say PASS only
for a receipt signed by the published key.

verify.js runs under node through tests/web/harness.js. RT_VERIFY_JS points these tests at another
copy of verify.js; it exists only to prove that the tests fail on a wrong canonicalizer.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from rt.api.app import WEB_DIR, create_app
from rt.receipts.sign import Signer, canonical, load_public, verify_receipt
from tests.orchestrator.conftest import API_TOKEN, harness  # noqa: F401  (harness is a fixture)

HERE = Path(__file__).resolve().parent
RECEIPTS = HERE / "receipts"
REPO = HERE.parents[1]
PUBLISHED_KEY = "rYyVzKw04aG8Y278Q1QsS1xeqBLAwX4NOHt4FWpryy4="
REAL_IDS = ["92b8c5f42e86", "fb6a2121c9a2", "1c41e4d75dec", "2cf9f3d5e536", "d1b6a7e00ee6"]
BAD_SIGNATURE = "signature does not match the receipt content"
OTHER_KEY = "receipt was signed by a different key than the published one"
NODE = shutil.which("node") or next((p for p in ("/opt/homebrew/bin/node", "/usr/local/bin/node")
                                     if Path(p).is_file()), None)
VERIFY_JS = Path(os.environ.get("RT_VERIFY_JS") or WEB_DIR / "verify.js")

needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed: the page's verifier is run under node")


def js(*ops: dict) -> list[dict]:
    r = subprocess.run([NODE, str(HERE / "harness.js"), str(VERIFY_JS)], input=json.dumps(list(ops)),
                       capture_output=True, text=True, encoding="utf-8", timeout=60, check=False)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert len(out) == len(ops)
    return out


def raw(rid: str) -> str:
    return (RECEIPTS / f"receipt-{rid}.json").read_text(encoding="utf-8")


def body_of(text: str) -> dict:
    return {k: v for k, v in json.loads(text).items() if k != "signature"}


def python_problems(text: str, key: bytes | None = None) -> list[str]:
    return verify_receipt(json.loads(text), key or load_public(PUBLISHED_KEY))


def one_char_diff(a: str, b: str) -> int:
    assert len(a) == len(b)
    diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    assert len(diffs) == 1, diffs
    return diffs[0]


# ------------------------------------------------------------------------------------- real receipts

@needs_node
@pytest.mark.parametrize("rid", REAL_IDS)
def test_real_receipt_canonical_bytes_match_python(rid):
    text = raw(rid)
    [out] = js({"op": "canonical", "text": text})
    assert "hex" in out, out
    assert bytes.fromhex(out["hex"]) == canonical(body_of(text))


@needs_node
@pytest.mark.parametrize("rid", REAL_IDS)
def test_real_receipt_passes_in_js(rid):
    text = raw(rid)
    d = json.loads(text)
    [r] = js({"op": "verify", "text": text})
    assert r["status"] == "pass", r["problems"]
    assert r["problems"] == []
    info = r["info"]
    assert info["key_matches_published"] is True
    assert info["key_id"] == info["key_id_computed"] == d["signature"]["key_id"]
    assert info["rehearsal_id"] == rid and info["outcome"] == d["outcome"]
    assert info["counts"] == {k: str(v) for k, v in d["compare"]["counts"].items()}
    assert info["twin_ledger_sha256"] == d["twin_ledger_sha256"]
    assert info["prod_ledger_sha256"] == d["prod_ledger_sha256"]


@pytest.mark.parametrize("rid", REAL_IDS)
def test_real_receipt_passes_in_python(rid):
    assert python_problems(raw(rid)) == []


@needs_node
def test_published_key_is_the_readme_key():
    [out] = js({"op": "published_key"})
    assert out["key"] == PUBLISHED_KEY
    assert PUBLISHED_KEY in (REPO / "README.md").read_text(encoding="utf-8")
    assert all(json.loads(raw(rid))["signature"]["public_key"] == PUBLISHED_KEY for rid in REAL_IDS)


# --------------------------------------------------------------------------------------- tampering

@needs_node
def test_changed_number_fails():
    text = raw("d1b6a7e00ee6")
    assert text.count('"wall_max_s":60.0') == 1
    bad = text.replace('"wall_max_s":60.0', '"wall_max_s":61.0')
    [r] = js({"op": "verify", "text": bad})
    assert r["status"] == "fail" and r["problems"] == [BAD_SIGNATURE]
    assert python_problems(bad) == [BAD_SIGNATURE]


@needs_node
def test_same_value_written_differently_fails():
    text = raw("d1b6a7e00ee6")
    bad = text.replace('"wall_max_s":60.0', '"wall_max_s":60')
    assert bad != text and json.loads(bad)["result"]["limits"]["wall_max_s"] == 60.0
    canon, r = js({"op": "canonical", "text": bad}, {"op": "verify", "text": bad})
    assert bytes.fromhex(canon["hex"]) != canonical(body_of(text))
    assert r["status"] == "fail" and r["problems"] == [BAD_SIGNATURE]
    assert python_problems(bad) == [BAD_SIGNATURE]


@needs_node
@pytest.mark.parametrize("rid", REAL_IDS)
def test_change_one_byte_button_makes_it_fail(rid):
    text = raw(rid)
    before = json.loads(text)
    [t] = js({"op": "tamper", "text": text})
    assert t["path"] == "compare.counts.happened"
    assert t["old"] == str(before["compare"]["counts"]["happened"]) and t["new"] != t["old"]
    one_char_diff(text, t["text"])
    after = json.loads(t["text"])
    assert after["signature"] == before["signature"]
    assert after["compare"]["counts"]["happened"] == int(t["new"])
    [r] = js({"op": "verify", "text": t["text"]})
    assert r["status"] == "fail" and r["problems"] == [BAD_SIGNATURE]
    assert python_problems(t["text"]) == [BAD_SIGNATURE]


@needs_node
def test_change_one_byte_without_counts_skips_the_signature():
    text = '{"signature":{"alg":"ed25519","n":5},"version":-19,"later":3}'
    [t] = js({"op": "tamper", "text": text})
    assert (t["path"], t["old"], t["new"]) == ("version", "-19", "-29")
    assert t["text"] == '{"signature":{"alg":"ed25519","n":5},"version":-29,"later":3}'
    [t9] = js({"op": "tamper", "text": '{"a":{"b":[97]}}'})
    assert (t9["path"], t9["new"]) == ("a.b[0]", "87")
    [none] = js({"op": "tamper", "text": '{"signature":{"n":1},"a":"x"}'})
    assert "no number" in none["error"]


@needs_node
@pytest.mark.parametrize("rid", REAL_IDS)
def test_forge_button_makes_it_fail(rid):
    text = raw(rid)
    [f] = js({"op": "forge", "text": text})
    assert f["path"] == "signature.value" and f["position"] == 1 and f["old"] != f["new"]
    one_char_diff(text, f["text"])
    old_value = json.loads(text)["signature"]["value"]
    new_value = json.loads(f["text"])["signature"]["value"]
    assert len(new_value) == len(old_value) and new_value[1:] == old_value[1:]
    forged = base64.b64decode(new_value, validate=True)
    assert len(forged) == 64 and forged != base64.b64decode(old_value)
    assert body_of(f["text"]) == body_of(text)
    [r] = js({"op": "verify", "text": f["text"]})
    assert r["status"] == "fail" and r["problems"] == [BAD_SIGNATURE]
    assert python_problems(f["text"]) == [BAD_SIGNATURE]


# --------------------------------------------------------------------------- synthetic, fresh key

def synthetic_receipt(signer: Signer) -> dict:
    return signer.sign({
        "kind": "rehearsal-twin/receipt", "version": 1, "rehearsal_id": "s1nthet1c", "outcome": "applied",
        "compare": {"counts": {"predicted": 3, "happened": 3, "surprises": 0}},
        "ключ": "значение", "café": "crème brûlée", "日本": "東京", "😀": "🎉 party",
        "｡": "sorts before the emoji by code point, after it by UTF-16 unit",
        "": "empty key", "__proto__": {"polluted": True},
        "text": {"separators": "a b c", "delete": "x\x7fy", "controls": "".join(map(chr, range(32))),
                 "quotes": 'say "hi" \\ back\\slash / done', "tab_newline": "a\tb\nc\u0001"},
        "floats": [512.0, 0.1, 1e-05, 1e16, -0.0, 1.5e300, 2.5e-300, 60.0, 123.456, -1.0],
        "ints": [0, -7, 2**63, 10**30, -(10**25)],
        "flags": [True, False, None],
        "empty": {"object": {}, "array": []},
        "nested": [[{"z": [[{"b": 1, "a": [None, {}]}]], "a": []}], []],
    })


VARIANTS = {
    "fastapi": lambda d: json.dumps(d, separators=(",", ":"), ensure_ascii=False),
    "pretty": lambda d: json.dumps(d, indent=2, ensure_ascii=False),
    "ascii-escaped": lambda d: json.dumps(d, indent=2),
}


def test_synthetic_data_tells_a_wrong_canonicalizer_apart():
    text = VARIANTS["fastapi"](synthetic_receipt(Signer(Ed25519PrivateKey.generate())))
    for lexeme in ("512.0", "1e-05", "1e+16", "-0.0", "60.0", "9223372036854775808", " ", "\x7f"):
        assert lexeme in text
    keys = ["｡", "😀"]
    assert sorted(keys) != sorted(keys, key=lambda s: s.encode("utf-16-be"))


@needs_node
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_synthetic_receipt_matches_python(variant):
    signer = Signer(Ed25519PrivateKey.generate())
    signed = synthetic_receipt(signer)
    text = VARIANTS[variant](signed)
    fresh = base64.b64encode(signer.public_raw).decode()
    canon, ok, other = js({"op": "canonical", "text": text}, {"op": "verify", "text": text, "key": fresh},
                          {"op": "verify", "text": text})
    assert bytes.fromhex(canon["hex"]) == canonical({k: v for k, v in signed.items() if k != "signature"})
    assert ok["status"] == "pass", ok["problems"]
    assert other["status"] == "fail" and other["problems"] == [OTHER_KEY]
    assert other["info"]["key_matches_published"] is False
    assert verify_receipt(json.loads(text), signer.public_raw) == []


# ------------------------------------------------------------------------------ no Ed25519 in browser

@needs_node
@pytest.mark.parametrize("stub", ["importKey", "verify", "no-subtle", "no-crypto-global"])
def test_without_ed25519_it_is_unsupported_never_pass(stub):
    text = raw("92b8c5f42e86")
    control, r = js({"op": "verify", "text": text}, {"op": "verify_stubbed", "text": text, "stub": stub})
    assert control["status"] == "pass"
    assert r["status"] == "unsupported", r
    assert r["problems"] == [] and r["signature_checked"] is False
    [tampered] = js({"op": "verify_stubbed", "text": text.replace('"happened":391', '"happened":491'), "stub": stub})
    assert tampered["status"] == "unsupported"


@needs_node
def test_without_ed25519_a_foreign_key_still_fails():
    text = VARIANTS["fastapi"](synthetic_receipt(Signer(Ed25519PrivateKey.generate())))
    [r] = js({"op": "verify_stubbed", "text": text, "stub": "importKey"})
    assert r["status"] == "fail"
    assert r["problems"][0] == OTHER_KEY and "not checked" in r["problems"][-1]


# ------------------------------------------------------------------------------------ broken input

def _swap(rid: str, old: str, new: str) -> str:
    text = raw(rid)
    assert text.count(old) == 1, old
    return text.replace(old, new)


BROKEN = {
    "duplicate key": (lambda: _swap("92b8c5f42e86", '"outcome":"applied"', '"outcome":"diverged","outcome":"applied"'),
                      'the key "outcome" appears twice'),
    "NaN": (lambda: _swap("92b8c5f42e86", '"wall_max_s":60.0', '"wall_max_s":NaN'), "not valid JSON"),
    "Infinity": (lambda: _swap("92b8c5f42e86", '"wall_max_s":60.0', '"wall_max_s":Infinity'), "not valid JSON"),
    "huge number": (lambda: _swap("92b8c5f42e86", '"wall_max_s":60.0', '"wall_max_s":1e400'), "number out of range"),
    "extra text": (lambda: raw("92b8c5f42e86") + "x", "extra text"),
    "lone surrogate": (lambda: _swap("92b8c5f42e86", '"outcome":"applied"', '"outcome":"applied\\ud800"'),
                       "lone surrogate"),
    "raw newline in a string": (lambda: _swap("92b8c5f42e86", '"outcome":"applied"', '"outcome":"app\nlied"'),
                                "not valid JSON"),
    "empty": (lambda: "", "not valid JSON"),
    "not an object": (lambda: "[1, 2]", "receipt is not a JSON object"),
    "no signature": (lambda: json.dumps(body_of(raw("92b8c5f42e86"))), "receipt has no signature"),
    "other algorithm": (lambda: _swap("92b8c5f42e86", '"alg":"ed25519"', '"alg":"rsa"'),
                        'unsupported signature algorithm "rsa"'),
    "not base64": (lambda: _swap("92b8c5f42e86", '"public_key":"rYyV', '"public_key":"!YyV'),
                   "signature fields are not base64"),
    "short key": (lambda: _swap("92b8c5f42e86", '"public_key":"rYyVzKw04aG8Y278Q1QsS1xeqBLAwX4NOHt4FWpryy4="',
                                '"public_key":"rYyVzKw04aG8Y278Q1QsS1xeqBLAwX4NOHt4FWpr"'),
                  "embedded public key is not 32 bytes"),
}


@needs_node
@pytest.mark.parametrize("case", sorted(BROKEN))
def test_broken_receipt_fails(case):
    make, problem = BROKEN[case]
    [r] = js({"op": "verify", "text": make()})
    assert r["status"] == "fail"
    assert any(problem in p for p in r["problems"]), r["problems"]


@needs_node
def test_wrong_key_id_fails_like_python():
    text = raw("92b8c5f42e86")
    kid = json.loads(text)["signature"]["key_id"]
    bad = _swap("92b8c5f42e86", f'"key_id":"{kid}"', '"key_id":"0000000000000000"')
    [r] = js({"op": "verify", "text": bad})
    assert r["status"] == "fail" and r["problems"] == ["key_id does not match the embedded public key"]
    assert python_problems(bad) == ["key_id does not match the embedded public key"]


# ------------------------------------------------------------------------------------ page and API

def test_verify_route_serves_the_page_in_fixture_mode():
    client = TestClient(create_app(mode="fixture"))
    page = client.get("/verify")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert '<script src="/verify.js"></script>' in page.text
    assert "<title>Verify a receipt · Rehearsal Twin</title>" in page.text
    script = client.get("/verify.js")
    assert script.status_code == 200 and "javascript" in script.headers["content-type"]
    assert script.text == (WEB_DIR / "verify.js").read_text(encoding="utf-8")
    assert client.get("/").status_code == 200 and "verify.js" not in client.get("/").text
    assert client.get("/style.css").status_code == 200
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/api/rehearsals/a").json()["_demo"].startswith("Every number")


def test_verify_route_serves_the_page_in_live_mode(tmp_path, monkeypatch):
    for name in ("VULTR_API_KEY", "VULTR_INFERENCE_API_KEY", "RT_RECEIPT_SIGNING_KEY", "RT_SSH_KEY_FILE",
                 "RT_GOLDEN_SNAPSHOT_ID", "RT_VPC_ID", "RT_PROD_INSTANCE_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RT_DATA_DIR", str(tmp_path))
    client = TestClient(create_app(mode="live"))
    page = client.get("/verify")
    assert page.status_code == 200 and "verify.js" in page.text
    assert client.get("/verify.js").status_code == 200


@needs_node
def test_live_api_receipt_text_verifies_in_js(harness):  # noqa: F811
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()),
                     headers={"Authorization": f"Bearer {API_TOKEN}"})
    r = api.post("/api/rehearsals", json={"preset": "a"})
    assert r.status_code == 202, r.text
    rid = r.json()["id"]
    view = api.get(f"/api/rehearsals/{rid}").json()
    assert api.post(f"/api/rehearsals/{rid}/approve", json=view["approval"]).status_code == 202
    text = api.get(f"/api/rehearsals/{rid}/receipt").text
    assert re.search(r":\d+\.0[,}]", text), "expected a float like 60.0 in the served text"
    key = base64.b64encode(harness.signer.public_raw).decode()
    ok, other = js({"op": "verify", "text": text, "key": key}, {"op": "verify", "text": text})
    assert ok["status"] == "pass", ok["problems"]
    assert ok["info"]["rehearsal_id"] == rid
    assert other["status"] == "fail" and other["problems"] == [OTHER_KEY]
    assert api.get("/verify").status_code == 200


def test_page_loads_no_outside_code():
    html = (WEB_DIR / "verify.html").read_text(encoding="utf-8")
    code = (WEB_DIR / "verify.js").read_text(encoding="utf-8")
    assert re.findall(r"<script[^>]*\bsrc=\"([^\"]+)\"", html) == ["/verify.js"]
    assert "<link" not in html and "@import" not in html
    assert re.search(r"https?://", code) is None
    assert code.count("fetch(") == 1 and ".text()" in code and ".json()" not in code


def test_every_element_the_script_uses_is_on_the_page():
    html = (WEB_DIR / "verify.html").read_text(encoding="utf-8")
    code = (WEB_DIR / "verify.js").read_text(encoding="utf-8")
    used = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', code))
    assert len(used) >= 10
    assert used <= set(re.findall(r'\bid="([^"]+)"', html))
