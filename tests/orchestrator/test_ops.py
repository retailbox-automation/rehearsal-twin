"""Reaper with leases, production reset, judge mode and the run queue."""
from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from rt.api.app import create_app
from rt.orchestrator import Busy, Conflict
from rt.orchestrator.leases import LEASE_FILE, Leases, reap_tick
from tests.orchestrator import ledgers as L
from tests.orchestrator.conftest import API_TOKEN

OPERATOR = {"Authorization": f"Bearer {API_TOKEN}"}
NOW = datetime(2026, 11, 3, 18, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def deleted_ids(fake) -> set[str]:
    return {c["path"].rsplit("/", 1)[-1] for c in fake.calls("DELETE", "/v2/instances/")}


# ---------------------------------------------------------------- reaper and leases

def test_reaper_skips_twins_a_live_lease_holds(harness, tmp_path):
    h = harness
    old = NOW - timedelta(minutes=40)
    held = h.vultr_fake.add_instance(tags=["rehearsal", "rt-twin", "rt:1held"], created=old)
    by_id = h.vultr_fake.add_instance(tags=["rehearsal", "rt-twin", "rt:2byid"], created=old)
    stale = h.vultr_fake.add_instance(tags=["rehearsal", "rt-twin", "rt:3stale"], created=old)
    orphan = h.vultr_fake.add_instance(tags=["rehearsal", "rt-twin", "rt:4orphan"], created=old)
    young = h.vultr_fake.add_instance(tags=["rehearsal", "rt-twin", "rt:5young"], created=NOW - timedelta(minutes=3))
    probe = h.vultr_fake.add_instance(tags=["probe", "rt-twin"], created=old)
    keep = h.vultr_fake.add_instance(tags=["rt-keep", "rt-twin"], created=old)
    (tmp_path / LEASE_FILE).write_text(json.dumps({
        "1held": {"rehearsal": "r1", "instance_id": None, "since": iso(old), "beat": iso(NOW - timedelta(minutes=1))},
        "x": {"rehearsal": "r2", "instance_id": by_id, "since": iso(old), "beat": iso(NOW - timedelta(minutes=2))},
        "3stale": {"rehearsal": "r3", "instance_id": stale, "since": iso(old), "beat": iso(NOW - timedelta(minutes=10))},
    }))
    line = reap_tick(h.orch.vultr, tmp_path, ttl_s=900, now=NOW)
    assert deleted_ids(h.vultr_fake) == {stale, orphan}
    assert line["actions"] == {"kept:active": 2, "deleted": 2, "kept:young": 1, "kept:protected": 2}
    assert line["leases_fresh"] == 2 and sorted(line["deleted"]) == sorted([stale, orphan])
    assert {held, by_id, young, probe, keep}.isdisjoint(deleted_ids(h.vultr_fake))


def test_reaper_never_takes_the_twin_of_a_running_rehearsal(harness):
    h = harness
    seen = {}

    def during_run(t):
        def hook(phase):
            if phase == "run":
                seen["leases"] = h.orch.leases.read()
                # a reaper tick in the middle of the rehearsal, with a TTL that makes every twin "old"
                seen["tick"] = reap_tick(h.orch.vultr, h.settings.data_dir, ttl_s=0)
        t.on_phase = hook
    h.fleet.twin_setup = during_run
    rec = h.run_preset("a")
    assert rec["status"] == "awaiting_approval"
    (lease,) = [v for v in seen["leases"].values() if v["rehearsal"] == rec["id"]]
    assert lease["instance_id"] == rec["attempts"][-1]["twin"]["id"]  # the hook saw the last twin last
    assert seen["tick"]["actions"] == {"kept:active": 1} and seen["tick"]["deleted"] == []
    assert h.orch.leases.read() == {}  # released after each destroy
    assert len(h.vultr_fake.calls("DELETE", "/v2/instances/")) == 2  # only the orchestrator's own destroys


def test_lease_released_when_the_rehearsal_fails(harness):
    h = harness
    h.fleet.twin_setup = lambda t: t.fail.__setitem__("run", (1, "", "boom"))
    rec = h.run_preset("a")
    assert rec["status"] == "failed" and h.orch.leases.read() == {}


def test_lease_heartbeat_renews_beat(tmp_path):
    leases = Leases(tmp_path, start_heartbeat=False)
    leases.take("1abc", "rid")
    first = leases.read()["1abc"]["beat"]
    (tmp_path / LEASE_FILE).write_text(json.dumps({"1abc": {**leases.read()["1abc"], "beat": "2026-01-01T00:00:00.000000Z"}}))
    assert leases.fresh() == {}
    leases.beat()
    assert leases.read()["1abc"]["beat"] >= first and "1abc" in leases.fresh()


def test_twin_slot_wait_lets_the_rehearsal_start_when_one_frees(harness):
    h = harness
    leaked = [h.vultr_fake.add_instance(tags=["rehearsal", "rt-twin", f"rt:z{i}"], created=NOW) for i in range(3)]
    h.settings.twin_slot_wait_s = 120
    h.orch.sleep = lambda s: h.vultr_fake.instances.pop(leaked.pop(), None)  # the reaper frees one
    rec = h.run_preset("a")
    assert rec["status"] == "awaiting_approval"
    assert "waiting" in [e["type"] for e in h.events(rec["id"])]


def test_reap_cli_writes_one_line_even_on_error(harness, monkeypatch, capsys):
    from rt.orchestrator.__main__ import main as cli
    monkeypatch.delenv("VULTR_API_KEY", raising=False)
    monkeypatch.setenv("RT_DATA_DIR", str(harness.settings.data_dir))
    assert cli(["reap"]) == 1
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1 and json.loads(out[0])["tick"] == "reap" and "VULTR_API_KEY" in json.loads(out[0])["error"]
    log = (harness.settings.data_dir / "reaper.jsonl").read_text().strip().splitlines()
    assert len(log) == 1


# ---------------------------------------------------------------- production reset

def _restore_resets_prod(h, state_after=None):
    orig = h.vultr_fake._instances

    def wrapped(hh, method, rest, query, body):
        if method == "POST" and rest[1:] == ["restore"]:
            h.prod.state = state_after if state_after is not None else L.machine_state()
        return orig(hh, method, rest, query, body)
    h.vultr_fake._instances = wrapped


def test_restore_not_while_a_rehearsal_is_open(harness):
    h = harness
    queued = h.orch.create(preset="a")  # queued, not run yet
    out = h.orch.reserve_restore(only_if_idle=True)
    assert out["status"] == "skipped" and queued["id"] in out["open"]
    h.orch.run(queued["id"])  # now awaiting approval, inside the approval window: still open
    assert h.orch.reserve_restore(only_if_idle=True)["status"] == "skipped"
    assert h.vultr_fake.calls("POST", "/v2/instances/") == []


def test_restore_when_idle_and_rebase(harness):
    h = harness
    _restore_resets_prod(h)
    rec = h.run_preset("a")
    approval = dict(rec["approval"])
    h.prod.state["pg"]["tables"]["sessions"]["rows"]["k9"] = "left over by another apply"
    with pytest.raises(Conflict):
        h.orch.approve(rec["id"], approval)
    h.settings.approval_window_s = 0  # the waiting approval is old: the hourly tick may reset
    assert h.orch.reserve_restore(only_if_idle=True) is None
    st = h.orch.restore_prod(origin="timer")
    assert st["status"] == "idle" and st["rebased"] == {rec["id"]: "unchanged"} and st["last_restore_s"] >= 0
    post = h.vultr_fake.calls("POST", f"/v2/instances/{h.prod_id}/restore")
    assert post and post[0]["body"] == {"snapshot_id": h.settings.snapshot_id}
    assert h.orch.approve_and_apply(rec["id"], approval)["status"] == "applied"


def test_restore_rebases_only_onto_the_state_the_twin_started_from(harness):
    h = harness
    rec = h.run_preset("a")
    # production drifted before the rehearsal finished: the approval carries the drifted version
    h2 = h.orch.load(rec["id"])
    drifted = L.machine_state()
    drifted["files"]["/srv/app/uploads/stray.dat"] = {"t": "f", "size": 1, "mode": 420, "uid": 0, "gid": 0,
                                                      "sha256": "s", "mtime_ns": 1}
    h.prod.state = drifted
    from rt.orchestrator import remote
    m = remote.state_manifest(drifted, h2["scope"])
    h2["approval"]["prod_state_version"] = remote.state_version(m)
    h.orch.store.save(h2)
    h.orch.store.write_json(rec["id"], "prod-state-rehearsal.json", m)
    _restore_resets_prod(h)  # restore brings back exactly the golden state the twin started from
    assert h.orch.reserve_restore(only_if_idle=False) is None
    st = h.orch.restore_prod()
    assert st["rebased"] == {rec["id"]: "rebased"}
    rec2 = h.orch.load(rec["id"])
    assert rec2["approval"]["prod_state_version"] == rec2["attempts"][-1]["twin_state_version"]
    assert h.orch.approve_and_apply(rec["id"], rec2["approval"])["status"] == "applied"


def test_restore_leaves_a_stale_approval_stale(harness):
    h = harness
    rec = h.run_preset("a")
    other = L.machine_state()
    other["pg"]["tables"]["prices"]["rows"]["p1"] = "a different golden snapshot"
    _restore_resets_prod(h, other)
    h.orch.reserve_restore(only_if_idle=False)
    assert h.orch.restore_prod()["rebased"] == {rec["id"]: "stale"}
    with pytest.raises(Conflict) as e:
        h.orch.approve(rec["id"], h.orch.load(rec["id"])["approval"])
    assert "prices changed" in e.value.reasons


def test_restore_waits_for_apply_and_refuses_when_forced(harness):
    h = harness
    rec = h.run_preset("a")
    h.orch.approve(rec["id"], rec["approval"])  # production reserved for this apply
    assert h.orch.reserve_restore(only_if_idle=True)["status"] == "skipped"
    with pytest.raises(Busy):
        h.orch.reserve_restore(only_if_idle=False)
    h.orch.apply(rec["id"])
    assert h.orch.reserve_restore(only_if_idle=False) is None


def test_restore_endpoint(harness):
    h = harness
    _restore_resets_prod(h)
    api = TestClient(create_app(mode="live", orchestrator=h.orch, run_in_background=lambda fn: fn()))
    assert api.post("/api/prod/restore", json={"when": "now"}).status_code == 401
    assert api.post("/api/prod/restore", json={"when": "soon"}, headers=OPERATOR).status_code == 400
    r = api.post("/api/prod/restore", json={"when": "now"}, headers=OPERATOR)
    assert r.status_code == 202 and r.json() == {"status": "restoring"}
    st = api.get("/api/prod").json()
    assert st["status"] == "idle" and st["last_restore_at"] and st["snapshot_id"] == h.settings.snapshot_id
    h.orch.create(preset="a")
    assert api.post("/api/prod/restore", json={"when": "idle"}, headers=OPERATOR).json()["status"] == "skipped"


def test_restore_tick_cli(harness, monkeypatch, capsys):
    from rt.orchestrator.__main__ import restore_tick_cli
    s = harness.settings
    seen = {}

    class Resp(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        seen["auth"] = req.get_header("Authorization")
        seen["body"] = json.loads(req.data)
        return Resp(b'{"status": "skipped", "reason": "rehearsals are open"}')
    assert restore_tick_cli(s, opener) == 0
    line = json.loads(capsys.readouterr().out)
    assert line["tick"] == "restore" and line["result"]["status"] == "skipped"
    assert seen == {"auth": f"Bearer {API_TOKEN}", "body": {"when": "idle"}}
    s.api_token = ""
    assert restore_tick_cli(s, opener) == 2
    assert "RT_API_TOKEN" in json.loads(capsys.readouterr().out)["error"]


# ---------------------------------------------------------------- judge mode and queue

@pytest.fixture
def judge_api(harness):
    harness.settings.judge_mode = True
    app = create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn())
    return TestClient(app, client=("127.0.0.1", 50000))  # behind Caddy


def judge_post(api, ip, **body):
    return api.post("/api/rehearsals", json=body or {"preset": "a"}, headers={"X-Forwarded-For": ip})


def test_judge_mode_off_means_token_only(harness):
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()))
    assert api.post("/api/rehearsals", json={"preset": "a"}).status_code == 401


def test_judge_runs_presets_only(judge_api):
    r = judge_post(judge_api, "198.51.100.7")
    assert r.status_code == 202 and r.json()["owner_key"]
    for body in ({"script": "rm -rf /", "scope": {"paths": ["/"]}}, {"goal": "clean up", "scope": {}},
                 {"preset": "a", "scope": {"paths": ["/"]}}):
        assert judge_post(judge_api, "198.51.100.8", **body).status_code == 401
    assert judge_post(judge_api, "198.51.100.8", preset="zz").status_code == 400
    ok = judge_api.post("/api/rehearsals", json={"script": "echo hi", "scope": {"paths": ["/tmp"]}}, headers=OPERATOR)
    assert ok.status_code == 202 and "owner_key" not in ok.json()


def test_judge_limit_per_address_behind_the_proxy(judge_api, harness):
    for _ in range(3):
        assert judge_post(judge_api, "198.51.100.7").status_code == 202
    r = judge_post(judge_api, "198.51.100.7")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    assert "per hour" in r.json()["detail"]["reason"]
    assert judge_post(judge_api, "203.0.113.20").status_code == 202  # another address
    assert judge_post(judge_api, "198.51.100.7, 203.0.113.21").status_code == 202  # Caddy's hop is the last one
    runs = (harness.settings.data_dir / "judge-runs.json").read_text()
    assert "198.51.100.7" not in runs  # addresses only as salted hashes


def test_forwarded_for_is_ignored_from_untrusted_peers(harness):
    harness.settings.judge_mode = True
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()),
                     client=("192.0.2.50", 50000))
    for i in range(3):
        assert judge_post(api, f"10.0.0.{i}").status_code == 202
    assert judge_post(api, "10.0.0.99").status_code == 429  # spoofed header does not reset the count


def test_daily_budget(harness):
    harness.settings.judge_mode = True
    harness.settings.daily_run_budget = 2
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()),
                     client=("127.0.0.1", 50000))
    assert judge_post(api, "198.51.100.1").status_code == 202
    assert judge_post(api, "198.51.100.2").status_code == 202
    r = judge_post(api, "198.51.100.3")
    assert r.status_code == 429 and "daily budget" in r.json()["detail"]["reason"]
    judge = api.get("/api/queue").json()["judge"]
    assert {k: judge[k] for k in ("mode", "runs_today", "daily_budget", "per_ip_hour")} == {
        "mode": "on", "runs_today": 2, "daily_budget": 2, "per_ip_hour": 3}
    assert api.post("/api/rehearsals", json={"preset": "a"}, headers=OPERATOR).status_code == 202  # operator


def test_judge_approves_only_their_own_run(judge_api, harness):
    mine = judge_post(judge_api, "198.51.100.7").json()
    theirs = judge_post(judge_api, "198.51.100.8").json()
    view = judge_api.get(f"/api/rehearsals/{mine['id']}").json()
    assert view["status"] == "awaiting_approval" and view["origin"] == "judge"
    url = f"/api/rehearsals/{mine['id']}/approve"
    assert judge_api.post(url, json=view["approval"]).status_code == 401
    assert judge_api.post(url, json=view["approval"], headers={"X-RT-Owner": theirs["owner_key"]}).status_code == 401
    r = judge_api.post(url, json=view["approval"], headers={"X-RT-Owner": mine["owner_key"]})
    assert r.status_code == 202
    assert judge_api.get(f"/api/rehearsals/{mine['id']}").json()["status"] == "applied"
    rec = harness.orch.load(mine["id"])
    assert mine["owner_key"] not in json.dumps(rec)  # only its hash is kept


def test_queue_runs_at_most_cap_and_shows_positions(harness):
    h = harness
    h.settings.max_twins_alive = 1
    h.settings.max_queue = 2
    tasks = []
    api = TestClient(create_app(mode="live", orchestrator=h.orch, run_in_background=tasks.append), headers=OPERATOR)
    ids = [api.post("/api/rehearsals", json={"preset": p}).json()["id"] for p in ("a", "a", "a")]
    q = api.get("/api/queue").json()
    assert [r["id"] for r in q["running"]] == ids[:1]
    assert [(w["id"], w["position"]) for w in q["waiting"]] == [(ids[1], 1), (ids[2], 2)]
    assert api.get(f"/api/rehearsals/{ids[2]}").json()["queue"]["position"] == 2
    full = api.post("/api/rehearsals", json={"preset": "a"})
    assert full.status_code == 429 and "queue is full" in full.json()["detail"]["reason"]
    assert len(tasks) == 1  # only one slot was started
    tasks.pop(0)()  # first finishes -> second starts
    assert len(tasks) == 1 and [r["id"] for r in api.get("/api/queue").json()["running"]] == ids[1:2]
    while tasks:
        tasks.pop(0)()
    assert [api.get(f"/api/rehearsals/{i}").json()["status"] for i in ids] == ["awaiting_approval"] * 3
    assert api.get("/api/queue").json()["running"] == [] and api.get("/api/stats").json()["queue"]["waiting"] == 0


def test_empty_live_screen_has_presets_to_run(harness):
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()))
    v = api.get("/api/rehearsals/latest").json()
    assert v["empty"] is True and [o["id"] for o in v["preset_options"]] == ["a", "b", "c"]
    page = api.get("/").text
    assert 'id="run"' in page and 'id="queue"' in page
