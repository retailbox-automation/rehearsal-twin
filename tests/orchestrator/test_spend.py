"""Spend guard: judge runs pause when the account's pending charges reach RT_SPEND_CAP_USD."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from rt.api.app import create_app
from rt.orchestrator.settings import Settings
from rt.orchestrator.spend import SpendGuard, parse_pending
from tests.orchestrator.conftest import API_TOKEN

OPERATOR = {"Authorization": f"Bearer {API_TOKEN}"}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def judge(harness):
    harness.settings.judge_mode = True
    app = create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn())
    clock = Clock()
    app.state.spend.clock = clock
    api = TestClient(app, client=("127.0.0.1", 50000))
    return api, app.state.spend, clock


def run(api, ip="198.51.100.7", headers=None):
    return api.post("/api/rehearsals", json={"preset": "a"}, headers={"X-Forwarded-For": ip, **(headers or {})})


def account_reads(harness):
    return len(harness.vultr_fake.calls("GET", "/v2/account"))


def test_pending_below_cap_lets_a_preset_run(judge, harness):
    api, guard, _ = judge
    harness.vultr_fake.account["pending_charges"] = 149.99
    assert run(api).status_code == 202
    q = api.get("/api/queue").json()["judge"]
    assert q["spend_pending"] == 149.99 and q["spend_cap"] == 150.0 and q["paused_reason"] is None


@pytest.mark.parametrize("pending", [150, 150.0, "151.20", 4000])
def test_pending_at_or_above_cap_is_503(judge, harness, pending):
    api, _, _ = judge
    harness.vultr_fake.account["pending_charges"] = pending
    r = run(api)
    assert r.status_code == 503
    d = r.json()["detail"]
    assert d["error"] == "judge mode paused: spend cap" and d["spend_cap"] == 150.0
    assert api.get("/api/queue").json()["judge"]["paused_reason"].startswith("spend cap")
    assert api.get("/api/queue").json()["judge"]["runs_today"] == 0  # a refusal does not use the budget
    assert run(api, headers=OPERATOR).status_code == 202  # the token is not paused


@pytest.mark.parametrize("account", [None, {"balance": -200}, {"pending_charges": "n/a"},
                                     {"pending_charges": -1}, {"pending_charges": True},
                                     {"pending_charges": float("nan")}])
def test_unreadable_spend_fails_closed_for_judges_only(judge, harness, account):
    api, _, _ = judge
    harness.vultr_fake.account = account
    r = run(api)
    assert r.status_code == 503 and r.json()["detail"]["error"] == "judge mode paused: spend unknown"
    assert api.get("/api/queue").json()["judge"]["spend_pending"] is None
    assert run(api, headers=OPERATOR).status_code == 202


def test_cache_reads_the_account_at_most_once_per_window(judge, harness):
    api, guard, clock = judge
    assert account_reads(harness) == 0  # nothing read until a judge needs it
    for _ in range(3):
        assert run(api, ip=f"198.51.100.{_}").status_code == 202
        api.get("/api/queue")
    assert account_reads(harness) == 1 and guard.reads == 1
    clock.t += harness.settings.spend_cache_s - 1
    api.get("/api/queue")
    assert account_reads(harness) == 1
    harness.vultr_fake.account["pending_charges"] = 500
    clock.t += 1  # window over: one new read, and it sees the new value
    assert run(api, ip="198.51.100.9").status_code == 503
    api.get("/api/queue")
    assert account_reads(harness) == 2 and guard.reads == 2


def test_failures_are_cached_too(judge, harness):
    api, guard, clock = judge
    harness.vultr_fake.account = None
    for _ in range(4):
        run(api)
        api.get("/api/queue")
    assert guard.reads == 1  # one failed read (with the client's own retries), then the cached answer
    reads = account_reads(harness)
    harness.vultr_fake.account = {"pending_charges": 1.0}
    assert run(api).status_code == 503  # still inside the window
    clock.t += harness.settings.spend_cache_s
    assert run(api).status_code == 202 and account_reads(harness) == reads + 1


def test_judge_mode_off_never_reads_the_account(harness):
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()))
    api.get("/api/queue")
    assert api.post("/api/rehearsals", json={"preset": "a"}).status_code == 401
    assert account_reads(harness) == 0


def test_cap_from_env_and_fail_closed_values():
    assert Settings.from_env({}).spend_cap_usd == 150.0
    assert Settings.from_env({"RT_SPEND_CAP_USD": "0.01"}).spend_cap_usd == 0.01
    for bad in ("abc", "-5", "nan"):
        assert Settings.from_env({"RT_SPEND_CAP_USD": bad}).spend_cap_usd == 0.0
    assert Settings.from_env({"RT_SPEND_CACHE_S": "30"}).spend_cache_s == 30.0


def test_synthetic_cap_of_one_cent_refuses(harness):
    """What the live check does: RT_SPEND_CAP_USD=0.01 on control, then a preset without the token."""
    env = {"RT_SPEND_CAP_USD": "0.01"}
    harness.settings.spend_cap_usd = Settings.from_env(env).spend_cap_usd
    harness.settings.judge_mode = True
    harness.vultr_fake.account["pending_charges"] = 0.11
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()),
                     client=("127.0.0.1", 50000))
    r = api.post("/api/rehearsals", json={"preset": "a"}, headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 503 and r.json()["detail"]["error"] == "judge mode paused: spend cap"


def test_parse_pending():
    assert parse_pending({"pending_charges": 0}) == 0.0 and parse_pending({"pending_charges": "2.5"}) == 2.5
    for bad in (None, {}, {"pending_charges": None}, {"pending_charges": [1]}):
        with pytest.raises((ValueError, TypeError)):
            parse_pending(bad)
    guard = SpendGuard(client=None, cap_usd=1.0)  # no client at all: fail closed, no exception
    assert guard.check()["paused_reason"].startswith("spend unknown")


def test_reaper_tick_line_carries_pending(harness, monkeypatch, capsys):
    from rt.orchestrator.__main__ import reap_tick_cli
    harness.vultr_fake.account["pending_charges"] = 3.5
    assert reap_tick_cli(harness.settings, None, True, vultr_factory=lambda timing=None: harness.orch.vultr) == 0
    line = json.loads(capsys.readouterr().out)
    assert line["tick"] == "reap" and line["spend_pending"] == 3.5 and line["spend_cap"] == 150.0
    harness.vultr_fake.account = None
    reap_tick_cli(harness.settings, None, True, vultr_factory=lambda timing=None: harness.orch.vultr)
    line = json.loads(capsys.readouterr().out)
    assert line["spend_error"] == "VultrError" and "spend_pending" not in line
