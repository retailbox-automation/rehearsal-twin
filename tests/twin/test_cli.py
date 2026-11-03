from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pytest

from rt.twin.__main__ import main


def test_cli_destroy_refuses_foreign_instance(fake, client, ssh):
    keep = fake.add_instance(tags=["rt-keep"], created=datetime.now(timezone.utc))
    with pytest.raises(SystemExit) as e:
        main(["destroy", "--id", keep], client=client, ssh=ssh, out=io.StringIO())
    assert e.value.code != 0
    assert fake.calls("DELETE") == []


def test_cli_destroy_twin(fake, client, ssh):
    tid = fake.add_instance(tags=["rehearsal", "rt-twin", "rt:abc123"], created=datetime.now(timezone.utc))
    out = io.StringIO()
    assert main(["destroy", "--id", tid], client=client, ssh=ssh, out=out) == 0
    assert json.loads(out.getvalue())["absent"] is True
    assert tid not in fake.instances


def test_cli_create_prints_twin(fake, client, ssh):
    out = io.StringIO()
    rc = main(["create", "--snapshot", "snap-9", "--vpc", "vpc-1", "--rid", "abc123def"], client=client, ssh=ssh, out=out)
    assert rc == 0
    row = json.loads(out.getvalue())
    assert row["rid"] == "abc123def" and row["host"] == "10.77.0.21" and row["id"] in fake.instances


def test_cli_reap_dry_run(fake, client, ssh):
    fake.add_instance(tags=["rt-twin"], created=datetime(2026, 1, 1, tzinfo=timezone.utc))
    out = io.StringIO()
    assert main(["reap", "--dry-run"], client=client, ssh=ssh, out=out) == 0
    assert json.loads(out.getvalue().splitlines()[0])["action"] == "would-delete"
    assert fake.calls("DELETE") == []


def test_bench_writes_percentiles(fake, client, ssh, runner, tmp_path):
    dest = tmp_path / "bench" / "twin_lifecycle.json"
    out = io.StringIO()
    rc = main(["bench", "--n", "3", "--snapshot", "snap-9", "--vpc", "vpc-1", "--out", str(dest)],
              client=client, ssh=ssh, out=out)
    assert rc == 0
    data = json.loads(dest.read_text())
    assert data["n"] == 3 and len(data["observations"]) == 3
    for o in data["observations"]:
        assert o["echo_ok"] is True and o["absent"] is True
        for k in ("create_s", "ready_s", "echo_s", "destroy_s", "total_s"):
            assert o[k] >= 0
        assert o["api_calls"] >= 4
    for k in ("ready_s", "destroy_s", "total_s"):
        assert set(data["summary"][k]) == {"p50", "p95", "min", "max"}
    assert fake.instances == {}  # every twin is gone


def test_bench_refuses_large_n(fake, client, ssh, tmp_path):
    with pytest.raises(SystemExit):
        main(["bench", "--n", "50", "--snapshot", "s", "--vpc", "v", "--out", str(tmp_path / "b.json")],
             client=client, ssh=ssh, out=io.StringIO())
    assert fake.calls("POST") == []


def test_bench_records_failure_and_still_destroys(fake, client, ssh, tmp_path):
    fake.public_ip_on_create = True
    dest = tmp_path / "b.json"
    rc = main(["bench", "--n", "1", "--snapshot", "s", "--vpc", "vpc-1", "--out", str(dest)],
              client=client, ssh=ssh, out=io.StringIO())
    assert rc == 1
    o = json.loads(dest.read_text())["observations"][0]
    assert "public" in o["error"] and o["absent"] is True
    assert fake.instances == {}
