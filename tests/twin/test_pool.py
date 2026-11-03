from __future__ import annotations

import pytest

from rt.twin.pool import WarmPool


class StubTwin:
    def __init__(self, n):
        self.id = f"twin-{n}"
        self.destroyed = False

    def destroy(self, **_):
        self.destroyed = True


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def sync(fn):
    fn()


def make_pool(**kw):
    made = []

    def factory():
        t = StubTwin(len(made))
        made.append(t)
        return t

    clock = Clock()
    pool = WarmPool(factory, spawn=sync, clock=clock, **kw)
    return pool, made, clock


def test_pool_size_capped_at_two():
    with pytest.raises(ValueError):
        WarmPool(lambda: None, size=3)
    with pytest.raises(ValueError):
        WarmPool(lambda: None, size=0)


def test_take_returns_ready_twin_and_refills():
    pool, made, _ = make_pool(size=2)
    pool.fill()
    assert len(made) == 2 and pool.ready_count() == 2
    t = pool.take(timeout=1)
    assert t is made[0]
    assert pool.ready_count() == 2 and len(made) == 3  # refilled to size


def test_pool_never_exceeds_size():
    pool, made, _ = make_pool(size=2)
    for _ in range(5):
        pool.fill()
    assert len(made) == 2


def test_pool_evicts_expired():
    pool, made, clock = make_pool(size=2, max_idle_s=600)
    pool.fill()
    clock.t += 601
    t = pool.take(timeout=1)
    assert made[0].destroyed and made[1].destroyed
    assert t is made[2]
    assert not t.destroyed


def test_failed_create_does_not_leak_pending_slot():
    calls = []

    def factory():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("create failed")
        return StubTwin(len(calls))

    pool = WarmPool(factory, size=1, spawn=sync, clock=Clock())
    pool.fill()
    assert pool.ready_count() == 0
    pool.fill()
    assert pool.ready_count() == 1


def test_take_times_out_when_nothing_ready():
    pool = WarmPool(lambda: (_ for _ in ()).throw(RuntimeError("no")), size=1, spawn=sync, clock=Clock())
    with pytest.raises(TimeoutError):
        pool.take(timeout=0.05)


def test_close_destroys_all_and_stops_refill():
    pool, made, _ = make_pool(size=2)
    pool.fill()
    pool.close()
    assert all(t.destroyed for t in made)
    pool.fill()
    assert len(made) == 2


def test_twin_factory_makes_ready_twin(fake, client, ssh):
    from rt.twin.pool import twin_factory

    make = twin_factory("snap-1", "vpc-1", "vc2-1c-1gb", client=client, ssh_factory=lambda: ssh)
    twin = make()
    assert twin.host == "10.77.0.21"
    body = fake.calls("POST", "/v2/instances")[0]["body"]
    assert body["plan"] == "vc2-1c-1gb" and "rt-twin" in body["tags"]


def test_twin_factory_cleans_up_failed_twin(fake, client, ssh):
    from rt.twin.pool import twin_factory

    fake.public_ip_on_create = True
    make = twin_factory("snap-1", "vpc-1", "vc2-1c-1gb", client=client, ssh_factory=lambda: ssh)
    with pytest.raises(Exception, match="public"):
        make()
    assert fake.instances == {}
