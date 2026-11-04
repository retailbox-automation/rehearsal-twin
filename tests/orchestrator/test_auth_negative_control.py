"""POST /api/rehearsals without the token must never reach the orchestrator.

The token check sits inside the handler, so FastAPI validates the body first: a request with no body
gets 422, a request with a body gets 401. Either way nothing is created and Vultr is never called.
The control at the end proves the same counters do move when the token is given.
"""
from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient

from rt.api.app import create_app
from tests.orchestrator.conftest import API_TOKEN

NO_TOKEN_ATTEMPTS = [
    ("no body", {}, None, 422),
    ("malformed json", {"content": b"{not json"}, {"Content-Type": "application/json"}, 422),
    ("empty object", {"json": {}}, None, 401),
    ("preset a", {"json": {"preset": "a"}}, None, 401),
    ("free script", {"json": {"script": "rm -rf /srv/*"}}, None, 401),
    ("goal", {"json": {"goal": "clean the cache"}}, None, 401),
    ("preset with scope", {"json": {"preset": "a", "scope": {"paths": ["/"]}}}, None, 401),
    ("wrong bearer", {"json": {"preset": "a"}}, {"Authorization": "Bearer wrong"}, 401),
    ("empty bearer", {"json": {"preset": "a"}}, {"Authorization": "Bearer "}, 401),
    ("wrong x-rt-token", {"json": {"preset": "a"}}, {"X-RT-Token": "wrong"}, 401),
    ("token as basic auth", {"json": {"preset": "a"}}, {"Authorization": f"Basic {API_TOKEN}"}, 401),
]


def _client(harness):
    return TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()))


def _created(harness):
    return harness.vultr_fake.calls("POST", "/v2/instances")


@pytest.mark.parametrize("name,kw,headers,code", NO_TOKEN_ATTEMPTS, ids=[a[0] for a in NO_TOKEN_ATTEMPTS])
def test_no_token_never_reaches_the_orchestrator(harness, name, kw, headers, code):
    del name  # only the test id
    api = _client(harness)
    r = api.post("/api/rehearsals", headers=headers or {}, **kw)
    assert r.status_code == code, r.text
    assert harness.orch.store.ids() == []
    assert _created(harness) == []
    assert harness.live_twins() == []


def test_empty_server_token_fails_closed(harness):
    harness.orch.s = dataclasses.replace(harness.orch.s, api_token="")
    api = TestClient(create_app(mode="live", orchestrator=harness.orch, run_in_background=lambda fn: fn()))
    for headers in ({}, {"Authorization": "Bearer "}, {"X-RT-Token": ""}):
        assert api.post("/api/rehearsals", json={"preset": "a"}, headers=headers).status_code == 401
    assert harness.orch.store.ids() == [] and _created(harness) == []


def test_control_the_token_does_create(harness):
    api = _client(harness)
    r = api.post("/api/rehearsals", json={"preset": "a"}, headers={"X-RT-Token": API_TOKEN})
    assert r.status_code == 202, r.text
    assert len(harness.orch.store.ids()) == 1
    assert len(_created(harness)) >= 1
