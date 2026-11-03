from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rt.twin.reaper import reap

NOW = datetime(2026, 11, 3, 16, 0, tzinfo=timezone.utc)
OLD = NOW - timedelta(minutes=40)
YOUNG = NOW - timedelta(minutes=5)


def seed(fake):
    ids = {
        "old_twin": fake.add_instance(tags=["rehearsal", "rt-twin", "rt:aaa111"], created=OLD),
        "young_twin": fake.add_instance(tags=["rehearsal", "rt-twin", "rt:bbb222"], created=YOUNG),
        "old_probe": fake.add_instance(tags=["probe", "agent-rush"], created=OLD),
        "old_keep": fake.add_instance(tags=["rt-keep"], created=OLD),
        "twin_and_keep": fake.add_instance(tags=["rehearsal", "rt-twin", "rt-keep"], created=OLD),
        "twin_and_probe": fake.add_instance(tags=["rt-twin", "probe"], created=OLD),
        "untagged": fake.add_instance(tags=[], created=OLD),
        "rehearsal_only": fake.add_instance(tags=["rehearsal"], created=OLD),
    }
    return ids


def test_reaper_never_touches_probe_or_keep(fake, client):
    ids = seed(fake)
    fake.ignore_tag_filter = True  # even if the server-side filter is ignored
    report = reap(client, ttl_s=15 * 60, now=NOW)
    deleted = {c["path"].rsplit("/", 1)[-1] for c in fake.calls("DELETE")}
    assert deleted == {ids["old_twin"]}
    by_id = {r["id"]: r for r in report}
    assert by_id[ids["old_twin"]]["action"] == "deleted"
    assert by_id[ids["young_twin"]]["action"] == "kept:young"
    for k in ("old_probe", "old_keep", "twin_and_keep", "twin_and_probe", "untagged", "rehearsal_only"):
        assert fake.instances[ids[k]]
        assert ids[k] not in by_id or by_id[ids[k]]["action"].startswith("kept")


def test_reaper_dry_run_deletes_nothing(fake, client):
    ids = seed(fake)
    report = reap(client, ttl_s=15 * 60, now=NOW, dry_run=True)
    assert fake.calls("DELETE") == []
    assert {r["id"]: r["action"] for r in report}[ids["old_twin"]] == "would-delete"


def test_reaper_skips_unparseable_date(fake, client):
    iid = fake.add_instance(tags=["rt-twin"], created=OLD)
    fake.instances[iid]["date_created"] = "yesterday-ish"
    report = reap(client, ttl_s=60, now=NOW)
    assert fake.calls("DELETE") == []
    assert report[0]["action"] == "kept:bad-date"


def test_reaper_asks_server_for_rt_twin_only(fake, client):
    seed(fake)
    reap(client, ttl_s=15 * 60, now=NOW, dry_run=True)
    lists = [c for c in fake.calls("GET") if c["path"] == "/v2/instances"]
    assert lists and all(c["query"].get("tag") == ["rt-twin"] for c in lists)
