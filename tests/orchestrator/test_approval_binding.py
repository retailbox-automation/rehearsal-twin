"""What an approval binds: companion files (review finding 10) and the twin's starting state (finding 11)."""
from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from rt.api.app import create_app
from rt.orchestrator import Conflict
from rt.orchestrator.core import files_digest
from rt.receipts.verify_receipt import check as check_receipt
from tests.orchestrator import ledgers as L
from tests.orchestrator.conftest import API_TOKEN, REPO
from tests.orchestrator.fakes import sha

B_SCRIPT = (REPO / "presets" / "b-migrate" / "migrate_0042.sh").read_bytes()
B_FILE = (REPO / "presets" / "b-migrate" / "schema_tables.txt").read_bytes()


def b_facts() -> dict:
    return {"version": 1, "files": {"created": [], "modified": [], "deleted": []},
            "dirs": {"created": [], "deleted": []},
            "rows": {"legacy_orders": {"inserted": 0, "deleted": 800, "updated": 0, "dropped": True}},
            "sql": [], "egress": [], "dns": [], "canaries": [], "exit": 0, "limits": {"oom": False},
            "integrity": {"ok": True, "issues": []}}


@pytest.fixture
def hb(harness):
    harness.fleet.twin_ledgers[sha(B_SCRIPT)] = b_facts()
    harness.prod.ledgers[sha(B_SCRIPT)] = b_facts()
    sent: dict = {}

    def on_phase(phase):
        if phase == "run":
            sent.update(harness.prod.files)
    harness.prod.on_phase = on_phase
    harness.sent = sent
    return harness


def run_b(h):
    rec = h.run_preset("b")
    assert rec["status"] == "awaiting_approval", rec.get("error")
    return rec


def sent_file(h, name):
    return next(v for k, v in h.sent.items() if k.endswith("/" + name))


# ---------------------------------------------------------------- finding 10: companion files

def test_approval_carries_the_companion_files_hash(hb):
    rec = run_b(hb)
    want = files_digest({"schema_tables.txt": hashlib.sha256(B_FILE).hexdigest()})
    assert rec["approval"]["files_sha256"] == want
    done = hb.orch.approve_and_apply(rec["id"], dict(rec["approval"]))
    assert done["status"] == "applied", done.get("error")
    assert sent_file(hb, "schema_tables.txt") == B_FILE
    receipt = hb.orch.receipt(rec["id"])
    assert receipt["script"]["files"] == {"schema_tables.txt": hashlib.sha256(B_FILE).hexdigest()}
    assert receipt["script"]["files_sha256"] == want == receipt["approval"]["files_sha256"]
    assert check_receipt(receipt, base64.b64decode(hb.signer.public_info()["public_key"])) == []


def test_approval_without_the_files_hash_is_refused_when_there_are_files(hb):
    rec = run_b(hb)
    req = {k: v for k, v in rec["approval"].items() if k != "files_sha256"}
    with pytest.raises(Conflict) as e:
        hb.orch.approve(rec["id"], req)
    assert e.value.reasons == ["files_sha256 does not match the rehearsal"]
    assert "run" not in hb.prod.phases


def test_changed_companion_file_is_refused_at_approval(hb):
    rec = run_b(hb)
    hb.orch.store.write_file(rec["id"], "file-schema_tables.txt", b"customers\n")  # someone with data-dir access
    with pytest.raises(Conflict) as e:
        hb.orch.approve(rec["id"], dict(rec["approval"]))
    assert any(r.startswith("files_sha256") and "schema_tables.txt" in r for r in e.value.reasons)
    assert "run" not in hb.prod.phases
    assert hb.orch.load(rec["id"])["status"] == "awaiting_approval"


def test_changed_companion_file_between_approval_and_apply_never_reaches_production(hb):
    rec = run_b(hb)
    hb.orch.approve(rec["id"], dict(rec["approval"]))
    hb.orch.store.write_file(rec["id"], "file-schema_tables.txt", b"customers\n")
    done = hb.orch.apply(rec["id"])
    assert done["status"] == "apply_failed" and "schema_tables.txt" in done["error"]
    assert "before the script ran" in done["error"]
    assert "run" not in hb.prod.phases and hb.sent == {}


def test_apply_sends_the_bytes_it_checked_not_a_second_read(hb, monkeypatch):
    # A file swapped right after apply() checked it must not be what production receives.
    rec = run_b(hb)
    hb.orch.approve(rec["id"], dict(rec["approval"]))
    store, real, reads = hb.orch.store, hb.orch.store.read_file, []

    def read_file(rid, name):
        if name == "file-schema_tables.txt":
            reads.append(name)
            if len(reads) > 1:
                return b"customers\n"
        return real(rid, name)
    monkeypatch.setattr(store, "read_file", read_file)
    done = hb.orch.apply(rec["id"])
    assert done["status"] == "applied", done.get("error")
    assert sent_file(hb, "schema_tables.txt") == B_FILE


def test_changed_companion_file_never_reaches_a_twin(hb):
    rec = hb.orch.create(preset="b")
    hb.orch.store.write_file(rec["id"], "file-schema_tables.txt", b"customers\n")
    done = hb.orch.run(rec["id"])
    assert done["status"] == "failed" and "schema_tables.txt" in done["error"]
    assert all("run" not in t.phases for t in hb.twins())


def test_no_companion_files_keeps_the_four_field_approval(harness):
    rec = harness.run_preset("a")
    req = {k: v for k, v in rec["approval"].items() if k != "files_sha256"}
    assert harness.orch.approve_and_apply(rec["id"], req)["status"] == "applied"
    assert harness.orch.receipt(rec["id"])["script"]["files"] == {}


def test_record_from_before_files_sha256_still_approves(harness):
    rec = harness.run_preset("a")
    old = harness.orch.load(rec["id"])
    old["approval"].pop("files_sha256")
    harness.orch.store.save(old)
    assert harness.orch.approve_and_apply(rec["id"], dict(old["approval"]))["status"] == "applied"


# ---------------------------------------------------------------- finding 11: snapshot drift

def drifted(h):
    st = L.machine_state()
    st["files"]["/srv/app/tmp/cache/stray.bin"] = {"t": "f", "size": 1, "mode": 420, "uid": 0, "gid": 0,
                                                   "sha256": "s", "mtime_ns": 1}
    h.prod.state = st


def test_drift_refuses_approval_without_override(harness):
    h = harness
    drifted(h)
    rec = h.run_preset("a")
    assert rec["snapshot_drift"] and rec["snapshot_matches_prod"] is False
    with pytest.raises(Conflict) as e:
        h.orch.approve(rec["id"], dict(rec["approval"]))
    assert any(r.startswith("snapshot_drift") for r in e.value.reasons)
    assert "run" not in h.prod.phases
    with pytest.raises(Conflict):
        h.orch.approve(rec["id"], {**rec["approval"], "override_drift": "yes"})  # only a real true


def test_drift_override_is_written_into_the_receipt(harness):
    h = harness
    drifted(h)
    rec = h.run_preset("a")
    done = h.orch.approve_and_apply(rec["id"], {**rec["approval"], "override_drift": True})
    assert done["status"] in ("applied", "diverged"), done.get("error")
    receipt = h.orch.receipt(rec["id"])
    assert receipt["approval"]["override_drift"] is True
    assert receipt["approval"]["snapshot_drift"] == rec["snapshot_drift"]
    assert receipt["snapshot_drift"] == {"changes": rec["snapshot_drift"], "overridden": True}


def test_no_drift_no_override_in_the_receipt(harness):
    rec = harness.run_preset("a")
    harness.orch.approve_and_apply(rec["id"], dict(rec["approval"]))
    receipt = harness.orch.receipt(rec["id"])
    assert "override_drift" not in receipt["approval"]
    assert receipt["snapshot_drift"] == {"changes": [], "overridden": False}


def test_api_drift_409_then_override(harness):
    h = harness
    drifted(h)
    rec = h.run_preset("a")
    c = TestClient(create_app("live", orchestrator=h.orch, run_in_background=lambda fn: fn()),
                   headers={"Authorization": f"Bearer {API_TOKEN}"})
    r = c.post(f"/api/rehearsals/{rec['id']}/approve", json=dict(rec["approval"]))
    assert r.status_code == 409 and any(x.startswith("snapshot_drift") for x in r.json()["detail"]["reasons"])
    r = c.post(f"/api/rehearsals/{rec['id']}/approve", json={**rec["approval"], "override_drift": True})
    assert r.status_code == 202, r.text
    assert c.get(f"/api/rehearsals/{rec['id']}/receipt").json()["approval"]["override_drift"] is True


def test_api_files_hash_round_trip(hb):
    rec = run_b(hb)
    c = TestClient(create_app("live", orchestrator=hb.orch, run_in_background=lambda fn: fn()),
                   headers={"Authorization": f"Bearer {API_TOKEN}"})
    view = c.get(f"/api/rehearsals/{rec['id']}").json()
    assert view["approval"]["files_sha256"] == rec["approval"]["files_sha256"]
    r = c.post(f"/api/rehearsals/{rec['id']}/approve", json=view["approval"])  # what the screen sends
    assert r.status_code == 202, r.text
    assert c.get(f"/api/rehearsals/{rec['id']}").json()["status"] == "applied"
