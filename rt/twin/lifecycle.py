"""Twin and Prod machines: create from a snapshot, wait, run commands over SSH, destroy.

A twin is created VPC-only: no public IPv4, no IPv6, no keys of ours on it.
It is reached over SSH through a jump host (the control VM, same VPC);
when the caller already runs on the control VM, jump is None and SSH goes
straight to the VPC address.

Environment: RT_SSH_KEY_FILE (private key path), RT_SSH_KEY_ID (Vultr ssh-key id,
optional), RT_JUMP_HOST (optional), RT_SSH_KNOWN_HOSTS (known_hosts for the jump host,
optional). Vultr credentials are read by rt.twin.vultr.
"""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import shlex
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from rt.twin.vultr import NotFound, Vultr, VultrError

TWIN_TAG = "rt-twin"
PROTECTED_TAGS = frozenset({"probe", "rt-keep"})
ALLOWED_PLANS = ("vc2-1c-1gb", "vc2-1c-2gb", "vc2-2c-4gb")
DEFAULT_PLAN = "vc2-1c-2gb"
DEFAULT_REGION = "ewr"
RID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")


class TwinError(Exception):
    pass


class SSHTimeout(TwinError):
    pass


def new_rid() -> str:
    return secrets.token_hex(6)


def twin_tags(rid: str) -> list[str]:
    return ["rehearsal", TWIN_TAG, f"rt:{rid}"]


def _is_global(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False


def has_public_ip(inst: dict) -> bool:
    # A VPC-only instance reports its VPC address as main_ip (live 03.11: main_ip == internal_ip == 10.77.0.6),
    # so "non-empty" is not "public"; only a globally routable address counts.
    v4 = inst.get("main_ip") or ""
    v6 = inst.get("v6_main_ip") or ""
    return _is_global(v4) or _is_global(v6)


def is_ready(inst: dict) -> bool:
    return (inst.get("status") == "active" and inst.get("power_status") == "running"
            and inst.get("server_status") == "ok")


def parse_created(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return dt if dt.tzinfo else None


class SSH:
    """Runs one command on a VPC host with the system ssh client (optionally via a jump host)."""

    def __init__(self, key_file: str | None = None, *, user: str = "root", jump: str | None = None,
                 jump_user: str | None = None, connect_timeout_s: int = 10,
                 runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                 state_dir: str | None = None):
        key = key_file or os.environ.get("RT_SSH_KEY_FILE", "")
        if not key:
            raise TwinError("RT_SSH_KEY_FILE is not set")
        self.key_file = key
        self.user = user
        self.jump = jump if jump is not None else (os.environ.get("RT_JUMP_HOST") or None)
        if self.jump and "@" in self.jump:  # accept "user@host" as well as "host"
            embedded_user, self.jump = self.jump.rsplit("@", 1)
            jump_user = jump_user or embedded_user
        self.jump_user = jump_user or user
        self.connect_timeout_s = connect_timeout_s
        self.runner = runner
        self._state_dir = state_dir

    def _known_hosts(self, name: str) -> str:
        # One file per machine: twins come and go and VPC addresses get reused.
        if self._state_dir is None:
            self._state_dir = tempfile.mkdtemp(prefix="rt-ssh-")
        Path(self._state_dir).mkdir(parents=True, exist_ok=True)
        return str(Path(self._state_dir) / f"known_hosts-{re.sub(r'[^A-Za-z0-9_.-]', '_', name)}")

    def forget(self, name: str) -> None:
        if self._state_dir is None:
            return
        Path(self._known_hosts(name)).unlink(missing_ok=True)

    def _opts(self, known_hosts: str | None) -> list[str]:
        o = ["-i", self.key_file, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=accept-new", "-o", f"ConnectTimeout={self.connect_timeout_s}",
             "-o", "LogLevel=ERROR"]
        if known_hosts:
            o += ["-o", f'UserKnownHostsFile="{known_hosts}"' if " " in known_hosts else f"UserKnownHostsFile={known_hosts}"]
        return o

    def argv(self, host: str, remote: str, name: str) -> list[str]:
        a = ["ssh", *self._opts(self._known_hosts(name)), "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"]
        if self.jump:
            proxy = ["ssh", *self._opts(os.environ.get("RT_SSH_KNOWN_HOSTS")), "-W", "%h:%p", f"{self.jump_user}@{self.jump}"]
            a += ["-o", "ProxyCommand=" + shlex.join(proxy)]
        return a + [f"{self.user}@{host}", remote]

    def run(self, host: str, argv: list[str], *, name: str, stdin: bytes | str | None = None,
            timeout: float | None = None) -> tuple[int, bytes, bytes]:
        args = self.argv(host, shlex.join(argv), name)
        kw: dict = {"capture_output": True, "timeout": timeout}
        if stdin is None:
            kw["stdin"] = subprocess.DEVNULL
        else:
            kw["input"] = stdin.encode() if isinstance(stdin, str) else stdin
        try:
            r = self.runner(args, **kw)
        except subprocess.TimeoutExpired:
            raise SSHTimeout(f"ssh to {host} timed out after {timeout}s") from None
        return r.returncode, r.stdout or b"", r.stderr or b""


class _Machine:
    def __init__(self, instance_id: str, *, client: Vultr | None = None, ssh: SSH | None = None,
                 vpc_id: str | None = None, host: str | None = None, label: str = ""):
        self.id = instance_id
        self.client = client or Vultr()
        self._ssh = ssh
        self.vpc_id = vpc_id
        self.host = host
        self.label = label

    def __repr__(self) -> str:
        return f"{type(self).__name__}(id={self.id!r}, host={self.host!r})"

    @property
    def ssh(self) -> SSH:
        # Built on first use, so API-only work (destroy, reap) needs no key file.
        if self._ssh is None:
            self._ssh = SSH()
        return self._ssh

    # -- commands ------------------------------------------------------------
    def exec(self, argv: list[str], stdin: bytes | str | None = None, timeout: float = 60.0) -> tuple[int, str, str]:
        if not self.host:
            raise TwinError(f"{self.id}: no VPC address yet (call wait_ready first)")
        rc, out, err = self.ssh.run(self.host, list(argv), name=self.id, stdin=stdin, timeout=timeout)
        return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def put(self, path: str, data: bytes, mode: int = 0o644, timeout: float = 60.0) -> None:
        script = 'set -e; umask 077; mkdir -p "$(dirname "$2")"; cat > "$2"; chmod "$1" "$2"'
        rc, _, err = self.exec(["sh", "-c", script, "sh", format(mode, "o"), path], stdin=data, timeout=timeout)
        if rc != 0:
            raise TwinError(f"{self.id}: put {path} failed rc={rc}: {err[:300]}")

    # -- waiting -------------------------------------------------------------
    def _wait_api_ready(self, deadline: float, poll_s: float, settle_s: float = 0.0) -> dict:
        t0 = time.monotonic()
        saw_not_ready = False
        while True:
            inst = self.client.get_instance(self.id)
            if is_ready(inst):
                if saw_not_ready or time.monotonic() - t0 >= settle_s:
                    return inst
            else:
                saw_not_ready = True
            if time.monotonic() > deadline:
                raise TwinError(f"{self.id} not ready: status={inst.get('status')} power={inst.get('power_status')} "
                                f"server={inst.get('server_status')}")
            self.client.sleep(poll_s)

    def _wait_ssh(self, deadline: float, poll_s: float) -> None:
        last = ""
        while True:
            left = deadline - time.monotonic()
            try:
                rc, _, err = self.ssh.run(self.host, ["true"], name=self.id, timeout=max(1.0, min(30.0, left)))
                if rc == 0:
                    return
                last = f"rc={rc} {err[:120].decode('utf-8', 'replace').strip()}"
            except SSHTimeout as e:
                last = str(e)
            if time.monotonic() > deadline:
                raise TwinError(f"{self.id} not ready: ssh to {self.host} not answering ({last})")
            self.client.sleep(poll_s)

    def _resolve_host(self, inst: dict) -> str:
        try:
            vpcs = self.client.instance_vpcs(self.id)
        except VultrError:
            vpcs = []
        for v in vpcs:
            if (not self.vpc_id or v.get("id") == self.vpc_id) and v.get("ip_address"):
                return v["ip_address"]
        if inst.get("internal_ip"):
            return inst["internal_ip"]
        raise TwinError(f"{self.id}: no VPC address")


class Twin(_Machine):
    def __init__(self, instance_id: str, *, rid: str = "", created_at: float | None = None, **kw):
        super().__init__(instance_id, **kw)
        self.rid = rid
        self.created_at = created_at if created_at is not None else time.time()
        self.destroyed = False

    @classmethod
    def create(cls, snapshot_id: str, rid: str, vpc_id: str, plan: str = DEFAULT_PLAN, *,
               region: str = DEFAULT_REGION, client: Vultr | None = None, ssh: SSH | None = None,
               sshkey_ids: list[str] | None = None) -> "Twin":
        if not RID_RE.match(rid or ""):
            raise ValueError(f"bad rid {rid!r}: use 3-63 chars of a-z, 0-9, '-'")
        if plan not in ALLOWED_PLANS:
            raise ValueError(f"plan {plan!r} is outside the allowed set {ALLOWED_PLANS}")
        if not snapshot_id or not vpc_id:
            raise ValueError("snapshot_id and vpc_id are required")
        client = client or Vultr()
        label = f"twin-{rid[:6]}"
        body = {
            "region": region, "plan": plan, "snapshot_id": snapshot_id,
            "label": label, "hostname": label, "tags": twin_tags(rid),
            "attach_vpc": [vpc_id], "disable_public_ipv4": True, "enable_ipv6": False,
            "backups": "disabled",
        }
        keys = sshkey_ids if sshkey_ids is not None else [k for k in [os.environ.get("RT_SSH_KEY_ID", "")] if k]
        if keys:
            body["sshkey_id"] = keys
        inst = client.create_instance(body)
        return cls(inst["id"], rid=rid, vpc_id=vpc_id, label=label, client=client, ssh=ssh)

    @classmethod
    def attach(cls, instance_id: str, *, client: Vultr | None = None, ssh: SSH | None = None,
               vpc_id: str | None = None) -> "Twin":
        client = client or Vultr()
        inst = client.get_instance(instance_id)
        tags = set(inst.get("tags") or [])
        if TWIN_TAG not in tags or tags & PROTECTED_TAGS:
            raise TwinError(f"{instance_id} is not a twin (tags {sorted(tags)})")
        rid = next((t[3:] for t in tags if t.startswith("rt:")), "")
        created = parse_created(inst.get("date_created", ""))
        t = cls(instance_id, rid=rid, vpc_id=vpc_id, label=inst.get("label", ""), client=client, ssh=ssh,
                created_at=created.timestamp() if created else None)
        if is_ready(inst):
            t.host = t._resolve_host(inst)
        return t

    def wait_ready(self, timeout: float = 600.0, poll_s: float = 5.0) -> "Twin":
        deadline = time.monotonic() + timeout
        inst = self._wait_api_ready(deadline, poll_s)
        if has_public_ip(inst):
            msg = f"{self.id} came up with a public address"
            try:
                self.destroy()
            except Exception as e:
                raise TwinError(f"{msg}; destroy failed: {e}") from e
            raise TwinError(f"{msg}; destroyed")
        self.host = self._resolve_host(inst)
        self._wait_ssh(deadline, poll_s)
        return self

    def destroy(self, timeout: float = 300.0, poll_s: float = 3.0) -> float:
        """DELETE the instance and return seconds until it is gone from GET /instances."""
        t0 = time.monotonic()
        try:
            self.client.delete_instance(self.id)
        except NotFound:
            pass
        while True:
            if all(i.get("id") != self.id for i in self.client.list_instances()):
                break
            if time.monotonic() - t0 > timeout:
                raise TwinError(f"{self.id} still listed {timeout}s after DELETE")
            self.client.sleep(poll_s)
        self.destroyed = True
        if self._ssh is not None:
            self._ssh.forget(self.id)
        return round(time.monotonic() - t0, 3)


class Prod(_Machine):
    """The demo production machine: same exec/put interface, plus restore from the golden snapshot."""

    @classmethod
    def attach(cls, instance_id: str, *, client: Vultr | None = None, ssh: SSH | None = None,
               vpc_id: str | None = None) -> "Prod":
        client = client or Vultr()
        inst = client.get_instance(instance_id)
        tags = set(inst.get("tags") or [])
        if TWIN_TAG in tags or "probe" in tags:
            raise TwinError(f"{instance_id} is not the prod machine (tags {sorted(tags)})")
        p = cls(instance_id, vpc_id=vpc_id, label=inst.get("label", ""), client=client, ssh=ssh)
        p.host = p._resolve_host(inst)
        return p

    def restore(self, snapshot_id: str, timeout: float = 1800.0, poll_s: float = 10.0, settle_s: float = 30.0) -> float:
        """Restore from a snapshot, wait until the API says ready and SSH answers; return seconds."""
        t0 = time.monotonic()
        self.client.restore_instance(self.id, snapshot_id)
        deadline = t0 + timeout
        inst = self._wait_api_ready(deadline, poll_s, settle_s=settle_s)
        self.host = self._resolve_host(inst)
        self._wait_ssh(deadline, poll_s)
        return round(time.monotonic() - t0, 3)
