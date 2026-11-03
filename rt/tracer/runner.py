"""Run a script as a sandboxed transient systemd service and collect what happened.

On Vultr a VPC-only twin still reaches the internet through the mandatory NAT
gateway, so containment lives in the twin's kernel and the root script must not
be able to undo it:

* network: IPAddressDeny=any with IPAddressAllow=localhost and the recorder's
  fake address range (cgroup BPF, checked by a preflight before every run).
  iptables nat OUTPUT rewrites a connection to the recorder before the cgroup
  egress filter looks at the packet, so recorded calls still reach rt-egress;
  the fake range is allowed so the rewritten replies are accepted on the way back.
* no CAP_NET_ADMIN / CAP_NET_RAW / CAP_SYS_ADMIN ..., no AF_NETLINK or AF_PACKET:
  iptables, routes, raw sockets, namespaces and cgroup moves all fail.
* no way to run code outside the sandbox later: the systemd and D-Bus control
  sockets are hidden, cron, systemd units, shell and login startup files,
  ld.so preload, sshd/pam config, /usr and the tracer itself are read-only.
* limits: MemoryMax (no swap), TasksMax, RuntimeMaxSec, OOMPolicy=continue.

Measured by an ExecStopPost helper that runs outside the sandbox ("+") inside
the unit cgroup after the script ended: SERVICE_RESULT, EXIT_CODE, EXIT_STATUS,
memory.peak, memory.events oom_kill, pids.events max.
"""
from __future__ import annotations

import math
import os
import re
import secrets
import signal
import subprocess
import threading
import time

OUTPUT_LIMIT = 64 * 1024
FAKE_RANGE = "198.18.0.0/15"
DROP_CAPS = ("CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_BPF",
             "CAP_SYS_BOOT", "CAP_SYS_RAWIO", "CAP_SYS_TIME", "CAP_MKNOD", "CAP_DAC_READ_SEARCH",
             "CAP_AUDIT_CONTROL", "CAP_PERFMON", "CAP_SYSLOG")
# Files that root processes outside the sandbox would execute or trust later.
READ_ONLY_PATHS = (
    "/opt/rt",
    "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
    "/etc/cron.monthly", "/etc/anacrontab", "/var/spool/cron",
    "/etc/systemd", "/etc/default/rt-egress", "/etc/audit",
    "/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/environment",
    "/etc/ssh", "/etc/pam.d", "/etc/security", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
    "/var/log/rt-egress", "/var/log/postgresql", "/var/log/audit",
)
INACCESSIBLE_PATHS = ("/run/systemd/private", "/run/dbus/system_bus_socket", "/run/snapd.socket",
                      "/run/snapd-snap.socket")
SCRIPT_ENV = ("HOME=/root", "LANG=C.UTF-8", "SHELL=/bin/bash", "USER=root", "LOGNAME=root")
STOP_TIMEOUT_S = 5

STOPPOST = r"""#!/bin/bash
# ExecStopPost helper: runs outside the sandbox, inside the unit cgroup, after the script.
out="$1"
cg=$(sed -n 's/^0:://p' /proc/self/cgroup)
d="/sys/fs/cgroup$cg"
{
  echo "service_result=$SERVICE_RESULT"
  echo "exit_code=$EXIT_CODE"
  echo "exit_status=$EXIT_STATUS"
  echo "memory_peak=$(cat "$d/memory.peak" 2>/dev/null)"
  echo "oom_kill=$(sed -n 's/^oom_kill //p' "$d/memory.events" 2>/dev/null)"
  echo "pids_max_events=$(sed -n 's/^max //p' "$d/pids.events" 2>/dev/null)"
} > "$out.tmp" && mv -f "$out.tmp" "$out"
"""

_SIZE = re.compile(r"^(\d+)([KMGT]?)B?$", re.I)


def parse_size(s) -> int:
    if isinstance(s, int):
        return s
    m = _SIZE.match(str(s).strip())
    if not m:
        raise ValueError(f"bad size: {s!r}")
    mult = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2).upper()]
    return int(m.group(1)) * mult


def new_unit_name(prefix: str = "rt-run") -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


RESOLV_CONF = "nameserver 127.0.0.1\n"


def sandbox_properties(mem_bytes: int, pids: int, wall: float, allow=(), resolv_path: str | None = None) -> list:
    props = [
        f"MemoryMax={mem_bytes}", "MemorySwapMax=0", f"TasksMax={pids}",
        f"RuntimeMaxSec={max(1, math.ceil(wall))}", f"TimeoutStopSec={STOP_TIMEOUT_S}", "OOMPolicy=continue",
        "IPAddressDeny=any", "IPAddressAllow=localhost", f"IPAddressAllow={FAKE_RANGE}",
    ]
    props += [f"IPAddressAllow={a}" for a in allow]
    props += [
        "CapabilityBoundingSet=~" + " ".join(DROP_CAPS),
        "NoNewPrivileges=yes",
        "ProtectControlGroups=yes", "ProtectKernelModules=yes", "ProtectKernelTunables=yes",
        "ProtectKernelLogs=yes", "ProtectClock=yes",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "RestrictNamespaces=yes",
        "PrivateDevices=yes",
        "ProtectSystem=yes", "ProtectHome=read-only",
        "ReadOnlyPaths=" + " ".join("-" + p for p in READ_ONLY_PATHS),
        "InaccessiblePaths=" + " ".join("-" + p for p in INACCESSIBLE_PATHS),
    ]
    if resolv_path:
        # The machine's resolver may be a VPC address whose replies the IP filter rejects;
        # inside the sandbox names go to the recorder's DNS stub through loopback.
        props.append(f"BindReadOnlyPaths={resolv_path}:/etc/resolv.conf")
    return props


def build_command(unit: str, script: str, mem_bytes: int, pids: int, wall: float, stats_path: str,
                  helper_path: str, cwd: str, allow=(), slice_name: str = "rt.slice",
                  shell: str = "/bin/bash", resolv_path: str | None = None) -> list:
    argv = ["systemd-run", "--wait", "--pipe", "--collect", "--quiet",
            f"--unit={unit}", f"--slice={slice_name}", f"--working-directory={cwd}"]
    for e in SCRIPT_ENV:
        argv += ["-E", e]
    for p in sandbox_properties(mem_bytes, pids, wall, allow, resolv_path):
        argv += ["-p", p]
    argv += ["-p", f"ExecStopPost=+/bin/bash {helper_path} {stats_path}"]
    return argv + ["--", shell, script]


def parse_stats(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if not sep:
            continue
        v = v.strip()
        out[k.strip()] = int(v) if v.lstrip("-").isdigit() else (v or None)
    return out


def exit_from_stats(stats: dict, fallback_rc: int | None) -> int | None:
    """Exit code like a shell reports it: status for a normal exit, 128 + signal for a kill."""
    code, status = stats.get("exit_code"), stats.get("exit_status")
    if code == "exited" and isinstance(status, int):
        return status
    if code in ("killed", "dumped") and status is not None:
        if isinstance(status, int):
            return 128 + status
        try:
            return 128 + int(signal.Signals["SIG" + str(status).upper().removeprefix("SIG")])
        except (KeyError, ValueError):
            return None
    if fallback_rc is not None and fallback_rc < 0:
        return 128 - fallback_rc
    return fallback_rc


def parse_memory_events(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = int(parts[1])
    return out


class _Capture(threading.Thread):
    def __init__(self, stream):
        super().__init__(daemon=True)
        self.stream = stream
        self.buf = bytearray()
        self.total = 0

    def run(self):
        while True:
            chunk = self.stream.read(65536)
            if not chunk:
                break
            self.total += len(chunk)
            room = OUTPUT_LIMIT - len(self.buf)
            if room > 0:
                self.buf += chunk[:room]


def _systemctl(*args, timeout: int = 10) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def show(unit: str, *props) -> dict:
    p = _systemctl("show", unit, *[f"--property={x}" for x in props])
    out = {}
    if p is not None:
        for line in p.stdout.splitlines():
            k, sep, v = line.partition("=")
            if sep:
                out[k] = v
    return out


def preflight_ip_filter(timeout: float = 15.0, slice_name: str = "rt.slice") -> tuple[bool, str]:
    """True when the kernel applies per-unit IP filters (the same cgroup BPF that does accounting).

    systemd silently ignores IPAddressDeny= where cgroup BPF is not available,
    so the run refuses to start unless a probe unit gets real packet counters.
    """
    unit = new_unit_name("rt-pre")
    probe = ("import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
             "s.sendto(b'rt', ('127.0.0.1', 9))")
    try:
        p = subprocess.run(["systemd-run", "--quiet", f"--unit={unit}", f"--slice={slice_name}",
                            "-p", "RemainAfterExit=yes", "-p", "IPAccounting=yes",
                            "-p", "IPAddressDeny=any", "-p", "IPAddressAllow=localhost",
                            "--", "/usr/bin/python3", "-I", "-c", probe],
                           capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"systemd-run failed: {exc.__class__.__name__}"
    if p.returncode != 0:
        return False, f"systemd-run failed: {p.stderr.strip()[:200]}"
    deadline = time.monotonic() + timeout
    info = {}
    try:
        while time.monotonic() < deadline:
            info = show(f"{unit}.service", "ActiveState", "SubState", "IPEgressPackets")
            if info.get("SubState") in ("exited", "failed") or info.get("ActiveState") == "failed":
                break
            time.sleep(0.1)
    finally:
        _systemctl("stop", f"{unit}.service")
        _systemctl("reset-failed", f"{unit}.service")
    pk = info.get("IPEgressPackets", "")
    if pk.isdigit() and int(pk) >= 1:
        return True, f"cgroup IP filter active ({pk} packets accounted)"
    return False, f"cgroup IP filter not available (IPEgressPackets={pk or 'unknown'})"


def run_script(script: str, wall: float, mem: str, pids: int, cwd: str | None = None,
               slice_name: str = "rt.slice", stats_dir: str = "/opt/rt/state", allow=(),
               preflight=preflight_ip_filter) -> dict:
    os.makedirs(stats_dir, exist_ok=True)
    script = os.path.abspath(script)
    cwd = cwd or os.path.dirname(script)
    mem_bytes = parse_size(mem)
    base = {"script": script, "sandbox": {"mode": "service"}}
    ok, detail = preflight(slice_name=slice_name)
    base["sandbox"]["ip_filter"] = "active" if ok else "unavailable"
    base["sandbox"]["ip_filter_detail"] = detail
    if not ok:
        base.update(exit=None, error=f"refusing to run: {detail}")
        return base

    unit = new_unit_name()
    stats_path = os.path.join(stats_dir, f"{unit}.stats")
    helper_path = os.path.join(stats_dir, "rt-stoppost.sh")
    with open(helper_path, "w", encoding="utf-8") as f:
        f.write(STOPPOST)
    os.chmod(helper_path, 0o700)
    resolv_path = os.path.join(stats_dir, "resolv.conf")
    with open(resolv_path, "w", encoding="utf-8") as f:
        f.write(RESOLV_CONF)
    os.chmod(resolv_path, 0o644)
    argv = build_command(unit, script, mem_bytes, pids, wall, stats_path, helper_path, cwd, allow, slice_name,
                         resolv_path=resolv_path)
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
    started = time.time()
    t0 = time.monotonic()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd="/", env=env)
    out_cap, err_cap = _Capture(proc.stdout), _Capture(proc.stderr)
    out_cap.start()
    err_cap.start()
    try:
        rc = proc.wait(timeout=wall + STOP_TIMEOUT_S + 20)
    except subprocess.TimeoutExpired:
        _systemctl("kill", "--signal=SIGKILL", f"{unit}.service")
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait()
    wall_s = time.monotonic() - t0
    _systemctl("stop", f"{unit}.service")
    out_cap.join(timeout=5)
    err_cap.join(timeout=5)
    try:
        with open(stats_path, encoding="utf-8") as f:
            stats = parse_stats(f.read())
        os.unlink(stats_path)
    except OSError:
        stats = {}

    peak = stats.get("memory_peak") if isinstance(stats.get("memory_peak"), int) else None
    oom_kills = stats.get("oom_kill") if isinstance(stats.get("oom_kill"), int) else 0
    result = stats.get("service_result")
    wall_exceeded = result == "timeout"
    base.update({
        "unit_name": unit,
        "exit": exit_from_stats(stats, rc),
        "service_result": result,
        "stats_recorded": bool(stats),
        "wall_exceeded": wall_exceeded,
        "started_at": started,
        "ended_at": time.time(),
        "limits": {
            "wall_s": round(wall_s, 3),
            "wall_max_s": wall,
            "peak_mem_mb": round(peak / (1024 * 1024), 1) if peak else None,
            "mem_max_mb": round(mem_bytes / (1024 * 1024), 1),
            "oom": oom_kills > 0 or result == "oom-kill",
            "oom_kills": oom_kills,
            "pids_max": pids,
            "pids_limit_hit": stats.get("pids_max_events") if isinstance(stats.get("pids_max_events"), int) else 0,
            "wall_exceeded": wall_exceeded,
        },
        "stdout": out_cap.buf.decode("utf-8", "replace"),
        "stderr": err_cap.buf.decode("utf-8", "replace"),
        "stdout_bytes": out_cap.total,
        "stderr_bytes": err_cap.total,
    })
    return base
