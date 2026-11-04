"""Production that does not do what was rehearsed must never read as `applied` (review finding 1)."""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from rt.api.app import create_app
from rt.receipts.verify_receipt import check as check_receipt
from tests.orchestrator import ledgers as L
from tests.orchestrator.conftest import API_TOKEN
from tests.orchestrator.fakes import sha


def _prod_facts(h, facts: dict) -> None:
    h.prod.ledgers[sha(L.SAFE_A.encode())] = facts


def _apply(h):
    rec = h.run_preset("a")
    assert rec["status"] == "awaiting_approval", rec.get("error")
    return h.orch.approve_and_apply(rec["id"], dict(rec["approval"]))


def test_matching_in_scope_production_is_applied(harness):
    done = _apply(harness)
    assert done["status"] == "applied", done.get("error")
    assert done["apply"]["outcome"] == "applied" and done["apply"]["divergence"] == []
    assert done["apply"]["prod_verdict"] == "in_scope"
    receipt = harness.orch.receipt(done["id"])
    assert receipt["outcome"] == "applied" and receipt["divergence"] == []
    assert receipt["prod_verdict"] == {"verdict": "in_scope", "out_of_scope_total": 0, "computed_on": "control"}
    assert harness.orch.stats()["diverged"] == 0


def test_production_that_differs_from_the_twin_is_diverged(harness):
    h = harness
    facts = L.safe_a_facts(wall=1.7)
    facts["files"]["deleted"] = facts["files"]["deleted"][:-1]  # production deleted one file fewer
    _prod_facts(h, facts)
    done = _apply(h)
    rid = done["id"]
    assert done["status"] == "diverged"
    assert done["apply"]["match"] is False and done["apply"]["outcome"] == "diverged"
    assert any("differs from the rehearsal" in r for r in done["apply"]["divergence"])
    assert "diverged" in done["error"]

    receipt = h.orch.receipt(rid)
    pub = base64.b64decode(h.signer.public_info()["public_key"])
    assert check_receipt(receipt, pub) == []  # signed, and the signature covers the outcome
    assert receipt["outcome"] == "diverged" and receipt["compare"]["match"] is False
    assert receipt["divergence"] == done["apply"]["divergence"]

    ev = h.events(rid)
    assert ev[-1]["type"] == "done" and ev[-1]["data"]["status"] == "diverged"
    assert any(e["type"] == "diverged" for e in ev)
    view = h.orch.view(rid)
    assert view["status"] == "diverged" and view["outcome"] == "diverged"
    assert view["compare"]["outcome"] == "diverged" and view["divergence"]
    st = h.orch.stats()
    assert st["diverged"] == 1 and st["statuses"].get("applied") is None


def test_out_of_scope_production_is_diverged_even_when_compare_matches(harness):
    # compare does not look at the tracer's integrity checks; the production verdict does.
    h = harness
    facts = L.safe_a_facts(wall=1.7)
    facts["integrity"] = {"ok": False, "issues": ["egress recorder was paused (stopped by a signal)"]}
    _prod_facts(h, facts)
    done = _apply(h)
    assert done["apply"]["match"] is True
    assert done["apply"]["prod_verdict"] == "out_of_scope"
    assert done["status"] == "diverged"
    receipt = h.orch.receipt(done["id"])
    assert receipt["prod_verdict"]["verdict"] == "out_of_scope"
    assert receipt["prod_verdict"]["out_of_scope_total"] == 1
    assert receipt["outcome"] == "diverged"


def test_production_verdict_is_computed_on_control_not_read_from_the_ledger(harness):
    # A production ledger whose own summary claims in_scope over out-of-scope facts: verify flags it
    # and the verdict used is the recomputed one.
    h = harness
    facts = L.safe_a_facts(wall=1.7)
    facts["integrity"] = {"ok": False, "issues": ["the script changed Postgres statement logging"]}

    def lie(ledger):
        ledger["summary"] = dict(ledger["summary"], verdict="in_scope", out_of_scope_total=0)
        ledger["out_of_scope"] = []
        return ledger
    _prod_facts(h, facts)
    h.prod.tamper = lie
    done = _apply(h)
    assert done["status"] == "diverged"
    assert done["apply"]["prod_verdict"] == "out_of_scope"
    assert done["apply"]["verify"]["ok"] is False
    assert any("failed verification" in r for r in done["apply"]["divergence"])


def test_api_shows_diverged(harness):
    h = harness
    facts = L.safe_a_facts(wall=1.7)
    facts["rows"]["sessions"]["deleted"] = 239
    _prod_facts(h, facts)
    rec = h.run_preset("a")
    app = create_app("live", orchestrator=h.orch, run_in_background=lambda fn: fn())
    c = TestClient(app)
    r = c.post(f"/api/rehearsals/{rec['id']}/approve", json=dict(rec["approval"]),
               headers={"Authorization": f"Bearer {API_TOKEN}"})
    assert r.status_code == 202, r.text
    v = c.get(f"/api/rehearsals/{rec['id']}").json()
    assert v["status"] == "diverged" and v["outcome"] == "diverged"
    assert v["compare"]["match"] is False and v["divergence"]
    listing = c.get("/api/rehearsals").json()["rehearsals"]
    assert listing[0]["status"] == "diverged"
    assert c.get(f"/api/rehearsals/{rec['id']}/receipt").json()["outcome"] == "diverged"
    assert c.get("/api/stats").json()["diverged"] == 1
