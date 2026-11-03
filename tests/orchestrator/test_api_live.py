from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from rt.api.app import create_app
from rt.receipts.verify_receipt import check as check_receipt


def parse_sse(text: str) -> list[tuple[int, str, dict]]:
    frames = []
    for block in text.strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if not line.startswith(":"))
        if fields:
            frames.append((int(fields["id"]), fields["event"], json.loads(fields["data"])))
    return frames


@pytest.fixture
def api(harness):
    app = create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn())
    return TestClient(app)


def start(api, **body):
    r = api.post("/api/rehearsals", json=body or {"preset": "a"})
    assert r.status_code == 202, r.text
    return r.json()["id"]


def test_live_cycle_over_http(api, harness):
    rid = start(api, preset="a")
    view = api.get(f"/api/rehearsals/{rid}").json()
    assert view["status"] == "awaiting_approval" and view["mode"] == "live"
    assert api.get("/api/rehearsals/latest").json()["id"] == rid

    r = api.post(f"/api/rehearsals/{rid}/approve", json=view["approval"])
    assert r.status_code == 202, r.text
    view = api.get(f"/api/rehearsals/{rid}").json()
    assert view["status"] == "applied"
    assert view["compare"]["match"] is True
    assert view["compare"]["predicted"] == view["compare"]["happened"] == {
        "files_changed": 150, "rows_changed": 240, "egress_attempts": 0}
    assert view["prod_counters"]["files_changed"] == 150

    receipt = api.get(f"/api/rehearsals/{rid}/receipt").json()
    pub = api.get("/api/receipts/pubkey").json()
    led = api.get(f"/api/rehearsals/{rid}/ledgers").json()
    import base64
    assert check_receipt(receipt, base64.b64decode(pub["public_key"]), led["attempts"]["2"], led["prod"]) == []

    frames = parse_sse(api.get(f"/api/rehearsals/{rid}/events").text)
    kinds = [e for _, e, _ in frames]
    assert kinds[-1] == "done" and "view" in kinds and "ledger_row" in kinds
    assert [d["step"] for _, e, d in frames if e == "step"][-2:] == ["apply", "compare"]
    # resume after an id: only later frames
    r = api.get(f"/api/rehearsals/{rid}/events", headers={"Last-Event-ID": str(frames[-3][0])})
    assert [i for i, _, _ in parse_sse(r.text)] == [i for i, _, _ in frames[-2:]]

    stats = api.get("/api/stats").json()
    assert stats["runs"] == 1 and stats["applied"] == 1 and stats["match_rate"] == 1.0
    assert stats["twins_alive"] == 0


def test_approve_409_over_http(api, harness):
    rid = start(api, preset="a")
    view = api.get(f"/api/rehearsals/{rid}").json()
    bad = dict(view["approval"], ledger_sha256="0" * 64)
    r = api.post(f"/api/rehearsals/{rid}/approve", json=bad)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "shift"
    harness.prod.state["files"]["/srv/app/tmp/cache/new.bin"] = {"t": "f", "size": 1, "mode": 420, "uid": 0,
                                                                 "gid": 0, "sha256": "y", "mtime_ns": 1}
    r = api.post(f"/api/rehearsals/{rid}/approve", json=view["approval"])
    assert r.status_code == 409
    assert "/srv/app/tmp/cache/new.bin added" in r.json()["detail"]["reasons"]
    assert api.post(f"/api/rehearsals/{rid}/approve", json={"ledger_sha256": "x"}).status_code == 422
    assert api.post("/api/rehearsals/ffffffffffff/approve", json=view["approval"]).status_code == 404
    assert "run" not in harness.prod.phases


def test_sse_waiting_for_approval_replays_without_follow(api):
    rid = start(api, preset="a")
    frames = parse_sse(api.get(f"/api/rehearsals/{rid}/events?follow=0").text)
    kinds = [e for _, e, _ in frames]
    assert "approval" in kinds and "done" not in kinds


def test_bad_requests(api):
    assert api.post("/api/rehearsals", json={}).status_code == 400
    assert api.post("/api/rehearsals", json={"preset": "zz"}).status_code == 400
    assert api.post("/api/rehearsals", json={"script": "echo hi"}).status_code == 400  # no scope
    assert api.post("/api/rehearsals", json={"script": "echo", "scope": {"paths": ["relative"]}}).status_code == 400
    assert api.get("/api/rehearsals/..%2Fetc").status_code == 404
    assert api.get("/api/rehearsals/zzz/events").status_code == 404
    assert api.get("/api/rehearsals/ffffffffffff/receipt").status_code == 404


def test_presets_listed(api):
    presets = {p["id"]: p for p in api.get("/api/presets").json()["presets"]}
    assert sorted(presets) == ["a", "b", "c"]
    assert presets["a"]["scope"] == {"paths": ["/srv/app/tmp"], "tables": {"sessions": {"max_rows": None}},
                                     "hosts": []}
    assert presets["b"]["files"] == ["schema_tables.txt"]
    assert presets["c"]["scope"]["tables"] == {"prices": {"max_rows": 31}}


def test_instances_live_from_vultr(api, harness):
    now = datetime.now(timezone.utc)
    harness.vultr_fake.add_instance(tags=["rehearsal", "rt-twin", "rt:abc"], created=now, label="twin-abc")
    harness.vultr_fake.add_instance(tags=["probe"], created=now, label="p2-probe", main_ip="203.0.113.50")
    items = {i["label"]: i for i in api.get("/api/instances").json()["instances"]}
    assert set(items) == {"prod-shop-01", "twin-abc"}
    assert items["twin-abc"]["dot"] == "blue" and items["twin-abc"]["vpc_only"] is True
    assert items["prod-shop-01"]["dot"] == "green"
    assert "main_ip" not in items["twin-abc"]
    assert api.get("/api/stats").json()["twins_alive"] == 1


def test_token_guards_post(harness):
    harness.settings.api_token = "t" * 24
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()))
    assert api.post("/api/rehearsals", json={"preset": "a"}).status_code == 401
    r = api.post("/api/rehearsals", json={"preset": "a"}, headers={"Authorization": "Bearer " + "t" * 24})
    assert r.status_code == 202
    assert api.get(f"/api/rehearsals/{r.json()['id']}").status_code == 200  # reads stay open


def test_busy_while_running(harness):
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: None))
    assert api.post("/api/rehearsals", json={"preset": "a"}).status_code == 202
    r = api.post("/api/rehearsals", json={"preset": "b"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "busy"


def test_live_without_settings_is_503(tmp_path, monkeypatch):
    for name in ("VULTR_API_KEY", "VULTR_INFERENCE_API_KEY", "RT_RECEIPT_SIGNING_KEY", "RT_SSH_KEY_FILE",
                 "RT_GOLDEN_SNAPSHOT_ID", "RT_VPC_ID", "RT_PROD_INSTANCE_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RT_DATA_DIR", str(tmp_path))
    api = TestClient(create_app(mode="live"))
    assert api.get("/api/health").json() == {"status": "ok"}
    r = api.post("/api/rehearsals", json={"preset": "a"})
    assert r.status_code == 503 and "VULTR_API_KEY" in r.json()["detail"]["detail"]
    assert api.get("/").status_code == 200


def test_fixture_mode_is_default(monkeypatch):
    monkeypatch.delenv("RT_MODE", raising=False)
    api = TestClient(create_app())
    assert api.get("/api/rehearsals/a").json()["_demo"].startswith("Every number")
    assert api.get("/api/stats").json()["runs"] == 1
    with pytest.raises(ValueError):
        create_app(mode="prod")
