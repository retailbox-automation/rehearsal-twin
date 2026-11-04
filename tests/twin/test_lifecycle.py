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
    cmds = [" ".join(c["argv"]) for c in runner.calls]
    assert len(cmds) == 4  # ssh true (refused), ssh true, cloud-init status --wait, ssh true again
    assert "cloud-init status --wait" in cmds[2] and runner.calls[-1]["argv"][-1] == "true"
    assert twin.cloud_init == "done"


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


class _ByCommand:
    """ssh runner fake that answers by the remote command: {"cloud-init": [(rc, out, err), ...], "true": ...}."""

    def __init__(self, answers):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.calls = []

    def __call__(self, argv, input=None, stdin=None, capture_output=False, timeout=None, check=False):
        import subprocess
        self.calls.append({"argv": list(argv), "timeout": timeout})
        key = "cloud-init" if any("cloud-init" in a for a in argv) else "true"
        queue = self.answers.get(key) or []
        rc, out, err = queue.pop(0) if len(queue) > 1 else (queue[0] if queue else (0, b"", b""))
        return subprocess.CompletedProcess(argv, rc, out, err)


def _ssh_with(runner, tmp_path):
    from rt.twin.lifecycle import SSH
    key = tmp_path / "k2"
    key.write_text("placeholder")
    return SSH(key_file=str(key), jump="198.51.100.10", runner=runner, state_dir=str(tmp_path / "kh2"))


def test_wait_ready_retries_cloud_init_while_sshd_reloads(fake, client, tmp_path):
    # 04.11.2026: cloud-init reloads sshd ~2 s after SSH first answers; a command in that moment is refused
    r = _ByCommand({"true": [(0, b"", b"")],
                    "cloud-init": [(255, b"", b"ssh: connect to host 10.77.0.21 port 22: Connection refused"),
                                   (0, b"status: done\n", b"")]})
    twin = make_twin(client, _ssh_with(r, tmp_path)).wait_ready(timeout=60, poll_s=0)
    kinds = ["cloud-init" if any("cloud-init" in a for a in c["argv"]) else "true" for c in r.calls]
    assert kinds == ["true", "cloud-init", "cloud-init", "true"]
    assert twin.cloud_init == "done"


def test_cloud_init_absent_or_finished_with_errors_does_not_block(fake, client, tmp_path):
    for rc, seen in ((127, "absent"), (2, "done with recoverable errors"), (1, "done with errors")):
        r = _ByCommand({"true": [(0, b"", b"")], "cloud-init": [(rc, b"", b"")]})
        twin = make_twin(client, _ssh_with(r, tmp_path)).wait_ready(timeout=60, poll_s=0)
        assert twin.cloud_init == seen


def test_cloud_init_wait_gives_up_after_its_timeout_without_failing(fake, client, tmp_path):
    r = _ByCommand({"true": [(0, b"", b"")], "cloud-init": [(255, b"", b"Connection refused")]})
    twin = make_twin(client, _ssh_with(r, tmp_path))
    twin.host = "10.77.0.21"
    seen = twin._wait_cloud_init(timeout=0.2, poll_s=0)
    assert seen.startswith("still running after 0 s") and "Connection refused" in seen


def test_prod_restore_waits_for_cloud_init(fake, client, tmp_path):
    from datetime import datetime, timezone
    from rt.twin.lifecycle import Prod
    now = datetime.now(timezone.utc)
    pid = fake.add_instance(tags=["rt-keep"], created=now, label="prod", main_ip="203.0.113.9")
    r = _ByCommand({"true": [(0, b"", b"")], "cloud-init": [(0, b"status: done\n", b"")]})
    prod = Prod.attach(pid, client=client, ssh=_ssh_with(r, tmp_path))
    fake.ready_after_gets = 1
    prod.restore("golden-1", timeout=60, poll_s=0, settle_s=0)
    kinds = ["cloud-init" if any("cloud-init" in a for a in c["argv"]) else "true" for c in r.calls]
    assert kinds[-2:] == ["cloud-init", "true"] and prod.cloud_init == "done"
