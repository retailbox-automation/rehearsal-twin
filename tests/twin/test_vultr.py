from __future__ import annotations

import json

import pytest

from rt.twin.vultr import AccountBlocked, NotFound, Vultr, VultrError
from tests.twin.conftest import FAKE_KEY


def test_retry_on_429(fake, client, sleeps):
    fake.fail_queue += [
        ("GET", "/v2/instances", 429, {"Retry-After": "2"}, {"error": "Rate limit reached", "status": 429}),
        ("GET", "/v2/instances", 429, {}, {"error": "Rate limit reached", "status": 429}),
    ]
    assert client.list_instances() == []
    assert len(fake.calls("GET", "/v2/instances")) == 3
    assert len(sleeps) == 2
    assert sleeps[0] >= 2  # Retry-After honoured


def test_retry_gives_up(fake, timing_lines, sleeps):
    c = Vultr(api_key=FAKE_KEY, base_url=fake.url, sleep=sleeps.append, timing=timing_lines.append, max_attempts=3)
    fake.fail_queue += [("GET", "/v2/instances", 429, {}, {"error": "Rate limit reached", "status": 429})] * 3
    with pytest.raises(VultrError) as e:
        c.list_instances()
    assert e.value.status == 429
    assert len(fake.calls("GET", "/v2/instances")) == 3


def test_get_retried_on_503(fake, client):
    fake.fail_queue.append(("GET", "/v2/instances", 503, {}, {"error": "busy", "status": 503}))
    assert client.list_instances() == []
    assert len(fake.calls("GET", "/v2/instances")) == 2


def test_post_create_not_retried_on_5xx(fake, client):
    # a 5xx on create may still have created a machine; a blind retry could double it
    fake.fail_queue.append(("POST", "/v2/instances", 500, {}, {"error": "oops", "status": 500}))
    with pytest.raises(VultrError) as e:
        client.create_instance({"label": "t", "region": "ewr", "plan": "vc2-1c-1gb"})
    assert e.value.status == 500
    assert len(fake.calls("POST", "/v2/instances")) == 1


def test_post_create_retried_on_429(fake, client):
    fake.fail_queue.append(("POST", "/v2/instances", 429, {}, {"error": "Rate limit reached", "status": 429}))
    inst = client.create_instance({"label": "t", "region": "ewr", "plan": "vc2-1c-1gb", "tags": []})
    assert inst["id"]
    assert len(fake.calls("POST", "/v2/instances")) == 2


def test_account_problem_is_a_blocker_not_retried(fake, client):
    fake.fail_queue.append(("POST", "/v2/instances", 400, {},
                            {"error": "Insufficient account balance to deploy", "status": 400}))
    with pytest.raises(AccountBlocked):
        client.create_instance({"label": "t", "region": "ewr", "plan": "vc2-1c-1gb"})
    assert len(fake.calls("POST", "/v2/instances")) == 1


def test_not_found(fake, client):
    with pytest.raises(NotFound):
        client.get_instance("nope")


def test_timing_line_per_call(fake, client, timing_lines):
    fake.fail_queue.append(("GET", "/v2/instances", 429, {}, {"error": "Rate limit reached", "status": 429}))
    client.list_instances()
    client.list_ssh_keys()
    rows = [json.loads(x) for x in timing_lines]
    assert [(r["method"], r["path"], r["status"]) for r in rows] == [
        ("GET", "/instances", 429), ("GET", "/instances", 200), ("GET", "/ssh-keys", 200)]
    for r in rows:
        assert isinstance(r["ms"], (int, float)) and r["ms"] >= 0
        assert r["ts"].endswith("Z")
    assert all(FAKE_KEY not in line for line in timing_lines)
    assert all(r["auth"] == "Bearer " + FAKE_KEY for r in fake.requests)


def test_list_follows_cursor_and_passes_tag(fake, client):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for i in range(5):
        fake.add_instance(tags=["rt-twin"], created=now, label=f"t{i}")
    fake.add_instance(tags=["probe"], created=now, label="p")
    got = client.list_instances(tag="rt-twin", per_page=2)
    assert sorted(i["label"] for i in got) == ["t0", "t1", "t2", "t3", "t4"]
    gets = fake.calls("GET", "/v2/instances")
    assert len(gets) == 3
    assert all(g["query"]["tag"] == ["rt-twin"] for g in gets)


def test_missing_key_is_an_error(monkeypatch, fake):
    monkeypatch.delenv("VULTR_API_KEY", raising=False)
    with pytest.raises(VultrError):
        Vultr(base_url=fake.url)


def test_snapshot_vpc_calls(fake, client):
    s = client.create_snapshot("inst-1", "golden")
    assert client.get_snapshot(s["id"])["status"] == "complete"
    client.delete_snapshot(s["id"])
    v = client.create_vpc("ewr", "rehearsal-ewr", "10.77.0.0", 24)
    assert [x["id"] for x in client.list_vpcs()] == [v["id"]]
    assert fake.calls("POST", "/v2/snapshots")[0]["body"] == {"instance_id": "inst-1", "description": "golden"}
