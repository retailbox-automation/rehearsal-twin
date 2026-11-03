from __future__ import annotations

import shlex
import subprocess
from datetime import datetime, timezone

import pytest

from rt.twin.lifecycle import SSH, Prod, SSHTimeout, Twin, TwinError

RID = "r7f3a9c2b1d0"


def make_twin(client, ssh, **kw):
    return Twin.create("snap-1", RID, "vpc-1", kw.pop("plan", "vc2-1c-2gb"), client=client, ssh=ssh, **kw)


def test_twin_has_no_public_ip(fake, client, ssh):
    twin = make_twin(client, ssh)
    body = fake.calls("POST", "/v2/instances")[0]["body"]
    assert body["disable_public_ipv4"] is True
    assert body["enable_ipv6"] is False
    assert body["attach_vpc"] == ["vpc-1"]
    assert body["tags"] == ["rehearsal", "rt-twin", f"rt:{RID}"]
    assert body["snapshot_id"] == "snap-1"
    assert body["label"] == f"twin-{RID[:6]}"
    assert body["region"] == "ewr" and body["plan"] == "vc2-1c-2gb"
    assert body["backups"] == "disabled"
    assert "os_id" not in body
    assert twin.id in fake.instances


def test_create_refuses_plans_outside_budget(client, ssh, fake):
    with pytest.raises(ValueError):
        make_twin(client, ssh, plan="vx1-g-2c-8g-120s")
    assert fake.calls("POST", "/v2/instances") == []


def test_create_refuses_bad_rid(client, ssh, fake):
    with pytest.raises(ValueError):
        Twin.create("snap-1", "Bad Rid; rm", "vpc-1", client=client, ssh=ssh)
    assert fake.calls("POST", "/v2/instances") == []


def test_wait_ready_waits_for_ok_and_ssh(fake, client, ssh, runner):
    fake.ready_after_gets = 2
    runner.results = [(255, b"", b"Connection refused"), (0, b"", b"")]
    twin = make_twin(client, ssh)
    assert twin.wait_ready(timeout=60, poll_s=0) is twin
    assert len(fake.calls("GET", f"/v2/instances/{twin.id}")) >= 3
    assert twin.host == "10.77.0.21"
    assert len(runner.calls) == 2
    assert runner.calls[-1]["argv"][-1] == "true"


def test_wait_ready_rejects_public_ip(fake, client, ssh):
    fake.public_ip_on_create = True
    twin = make_twin(client, ssh)
    with pytest.raises(TwinError, match="public"):
        twin.wait_ready(timeout=60, poll_s=0)
    assert fake.calls("DELETE", f"/v2/instances/{twin.id}")


def test_wait_ready_times_out(fake, client, ssh):
    fake.ready_after_gets = 10**6
    twin = make_twin(client, ssh)
    with pytest.raises(TwinError, match="not ready"):
        twin.wait_ready(timeout=0.2, poll_s=0.01)


def test_destroy_waits_until_absent(fake, client, ssh):
    twin = make_twin(client, ssh)
    fake.linger_after_delete = 3
    lists_before = len(fake.calls("GET", "/v2/instances"))
    twin.destroy(timeout=60, poll_s=0)
    lists = [c for c in fake.calls("GET", "/v2/instances")[lists_before:] if c["path"] == "/v2/instances"]
    assert len(lists) == 4  # three polls still saw it, the fourth did not
    assert twin.id not in fake.instances
    assert len(fake.calls("DELETE", f"/v2/instances/{twin.id}")) == 1


def test_destroy_raises_if_still_listed(fake, client, ssh):
    twin = make_twin(client, ssh)
    fake.linger_after_delete = 10**6
    with pytest.raises(TwinError, match="still listed"):
        twin.destroy(timeout=0.2, poll_s=0.01)


def test_destroy_already_gone_is_ok(fake, client, ssh):
    twin = make_twin(client, ssh)
    del fake.instances[twin.id]
    twin.destroy(timeout=5, poll_s=0)


def test_exec_goes_through_jump_with_key(fake, client, ssh, runner, tmp_path):
    twin = make_twin(client, ssh).wait_ready(timeout=10, poll_s=0)
    runner.results = [(3, b"out\n", b"err\n")]
    rc, out, err = twin.exec(["rtrace", "before", "--scope", "/opt/rt/scope with space.json"], timeout=30)
    assert (rc, out, err) == (3, "out\n", "err\n")
    argv = runner.calls[-1]["argv"]
    assert argv[0] == "ssh"
    assert argv[argv.index("-i") + 1] == str(tmp_path / "key")
    opts = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
    assert "BatchMode=yes" in opts and "IdentitiesOnly=yes" in opts
    proxy = next(o for o in opts if o.startswith("ProxyCommand="))
    assert "root@198.51.100.10" in proxy and "-W" in proxy
    assert argv[-2] == "root@10.77.0.21"
    assert shlex.split(argv[-1]) == ["rtrace", "before", "--scope", "/opt/rt/scope with space.json"]
    assert runner.calls[-1]["timeout"] == 30


def test_exec_timeout_raises(fake, client, ssh, runner):
    twin = make_twin(client, ssh).wait_ready(timeout=10, poll_s=0)
    runner.results = [subprocess.TimeoutExpired("ssh", 1)]
    with pytest.raises(SSHTimeout):
        twin.exec(["sleep", "99"], timeout=1)


def test_put_streams_bytes(fake, client, ssh, runner):
    twin = make_twin(client, ssh).wait_ready(timeout=10, poll_s=0)
    twin.put("/opt/rt/s.sh", b"#!/bin/sh\necho hi\n", mode=0o700)
    call = runner.calls[-1]
    assert call["input"] == b"#!/bin/sh\necho hi\n"
    remote = shlex.split(call["argv"][-1])
    assert remote[0] == "sh" and remote[-1] == "/opt/rt/s.sh" and "700" in remote


def test_ssh_requires_key(monkeypatch):
    monkeypatch.delenv("RT_SSH_KEY_FILE", raising=False)
    with pytest.raises(TwinError):
        SSH()


def test_attach_reads_rid_and_refuses_foreign(fake, client, ssh):
    now = datetime.now(timezone.utc)
    mine = fake.add_instance(tags=["rehearsal", "rt-twin", "rt:abc123"], created=now)
    keep = fake.add_instance(tags=["rt-keep"], created=now)
    t = Twin.attach(mine, client=client, ssh=ssh)
    assert t.rid == "abc123" and t.host == "10.77.0.9"
    with pytest.raises(TwinError):
        Twin.attach(keep, client=client, ssh=ssh)


def test_prod_restore(fake, client, ssh, runner):
    now = datetime.now(timezone.utc)
    pid = fake.add_instance(tags=["rt-keep"], created=now, label="prod", main_ip="203.0.113.9")
    prod = Prod.attach(pid, client=client, ssh=ssh)
    fake.ready_after_gets = 1
    prod.restore("golden-1", timeout=60, poll_s=0, settle_s=0)
    post = fake.calls("POST", f"/v2/instances/{pid}/restore")
    assert post and post[0]["body"] == {"snapshot_id": "golden-1"}
    assert fake.instances[pid]["server_status"] == "ok"
    assert runner.calls[-1]["argv"][-1] == "true"
    rc, out, _ = prod.exec(["echo", "ok"])
    assert rc == 0 and out == "ok\n"
