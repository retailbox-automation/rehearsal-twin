import json

import pytest
from fastapi.testclient import TestClient

from rt.api.app import app

client = TestClient(app)


def parse_sse(text: str) -> list[tuple[str, dict]]:
    frames = []
    for block in text.strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines())
        frames.append((fields["event"], json.loads(fields["data"])))
    return frames


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_rehearsal_follows_ledger_contract():
    body = client.get("/api/rehearsals/a").json()
    assert body["_demo"].startswith("Every number")
    ledger = body["twin_ledger"]
    for key in ("files", "rows", "sql", "egress", "canaries", "exit", "limits",
                "out_of_scope", "ledger_sha256"):
        assert key in ledger
    assert all(e["delivered"] == 0 for e in ledger["egress"])
    assert body["compare"]["predicted"] == body["compare"]["happened"]


def test_screen_rows_match_ledger():
    body = client.get("/api/rehearsals/a").json()
    deleted = len(body["twin_ledger"]["files"]["deleted"])
    assert deleted == body["summary"]["deleted_files"]
    outside = sum(o["count"] for o in body["twin_ledger"]["out_of_scope"] if o["kind"] == "path")
    assert outside == body["summary"]["outside_count"]
    shown = sum(int(r["delta"].split()[0].lstrip("-")) for r in body["ledger_view"])
    assert shown == deleted


def test_unknown_rehearsal_is_404():
    assert client.get("/api/rehearsals/zzz").status_code == 404
    assert client.get("/api/rehearsals/zzz/events").status_code == 404
    assert client.get("/api/rehearsals/..%2Fx").status_code == 404


def test_instances_lists_twin_without_public_ip():
    items = client.get("/api/instances").json()["instances"]
    twin = [i for i in items if i["label"].startswith("twin-")]
    assert len(twin) == 1 and "no public IPv4" in twin[0]["meta"]


def test_sse_plays_steps_in_order():
    r = client.get("/api/rehearsals/a/events?pace=0")
    assert r.headers["content-type"].startswith("text/event-stream")
    frames = parse_sse(r.text)
    steps = [d["step"] for e, d in frames if e == "step"]
    assert steps == ["rehearse", "review", "apply", "compare"]
    assert frames[-1][0] == "done"
    kinds = [e for e, _ in frames]
    # the twin summary lands before review, prod counters only after apply starts
    assert kinds.index("twin_summary") < kinds.index("step", 1)
    apply_at = [i for i, (e, d) in enumerate(frames) if e == "step" and d["step"] == "apply"][0]
    assert kinds.index("prod_counters") > apply_at
    ids = [int(line.split(": ")[1]) for line in r.text.splitlines() if line.startswith("id: ")]
    assert ids == sorted(ids)


def test_static_screen_served():
    r = client.get("/")
    assert r.status_code == 200 and "Rehearsal Twin" in r.text
    assert client.get("/app.js").status_code == 200
