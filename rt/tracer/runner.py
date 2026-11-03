"""Run a script in a transient systemd scope with limits and collect what happened.

Limits: wall time (killed on expiry), MemoryMax (+ no swap), TasksMax.
Measured: exit code, OOM kills (memory.events), memory.peak, pids.events max,
wall time, stdout/stderr (first 64 KB each, total byte counts).
"""
from __future__ import annotations

import os
import re
import secrets
import subprocess
import threading
import time

OUTPUT_LIMIT = 64 * 1024

# Runs as the scope's main process: the script is its child, so the cgroup is
# still alive when the wrapper reads memory.peak / memory.events after the exit.
WRAPPER = r"""
stats="$1"; shift
"$@"
rc=$?
cg=$(sed -n 's/^0:://p' /proc/self/cgroup)
d="/sys/fs/cgroup$cg"
{
  echo "rc=$rc"
  echo "memory_peak=$(cat "$d/memory.peak" 2>/dev/null)"
  echo "oom_kill=$(sed -n 's/^oom_kill //p' "$d/memory.events" 2>/dev/null)"
  echo "oom=$(sed -n 's/^oom //p' "$d/memory.events" 2>/dev/null)"
  echo "pids_max_events=$(sed -n 's/^max //p' "$d/pids.events" 2>/dev/null)"
} > "$stats"
exit $rc
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


def new_unit_name() -> str:
    return f"rt-run-{secrets.token_hex(4)}"


def build_command(unit: str, script: str, mem_bytes: int, pids: int, stats_path: str,
                  slice_name: str = "rt.slice", shell: str = "/bin/bash") -> list:
    return [
        "systemd-run", "--scope", "--quiet",
        f"--unit={unit}", f"--slice={slice_name}",
        "-p", f"MemoryMax={mem_bytes}",
        "-p", "MemorySwapMax=0",
        "-p", f"TasksMax={pids}",
        "--", "/bin/bash", "-c", WRAPPER, "rt-scope-wrap", stats_path, shell, script,
    ]


def parse_stats(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if not sep:
            continue
        v = v.strip()
        out[k.strip()] = int(v) if v.lstrip("-").isdigit() else None
    return out


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


def _cgroup_dir(unit: str) -> str | None:
    try:
        p = subprocess.run(["systemctl", "show", "-p", "ControlGroup", "--value", f"{unit}.scope"],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    cg = p.stdout.strip()
    return f"/sys/fs/cgroup{cg}" if cg else None


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


class _Poller(threading.Thread):
    """Backup readings of the scope cgroup in case the wrapper itself is killed."""

    def __init__(self, unit: str):
        super().__init__(daemon=True)
        self.unit = unit
        self.stop = threading.Event()
        self.peak = None
        self.oom_kill = 0
        self.pids_max_events = 0

    def run(self):
        d = None
        while not self.stop.is_set():
            d = d or _cgroup_dir(self.unit)
            if d:
                peak = _read(d + "/memory.peak").strip()
                if peak.isdigit():
                    self.peak = max(self.peak or 0, int(peak))
                ev = parse_memory_events(_read(d + "/memory.events"))
                self.oom_kill = max(self.oom_kill, ev.get("oom_kill", 0))
                pe = parse_memory_events(_read(d + "/pids.events"))
                self.pids_max_events = max(self.pids_max_events, pe.get("max", 0))
            self.stop.wait(0.1)


def _systemctl(*args):
    try:
        subprocess.run(["systemctl", *args], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def run_script(script: str, wall: float, mem: str, pids: int, cwd: str | None = None,
               slice_name: str = "rt.slice", stats_dir: str = "/opt/rt/state") -> dict:
    os.makedirs(stats_dir, exist_ok=True)
    unit = new_unit_name()
    stats_path = os.path.join(stats_dir, f"{unit}.stats")
    mem_bytes = parse_size(mem)
    argv = build_command(unit, os.path.abspath(script), mem_bytes, pids, stats_path, slice_name)
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "SHELL": "/bin/bash",
        "USER": "root",
        "LOGNAME": "root",
    }
    started = time.time()
    t0 = time.monotonic()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=cwd or os.path.dirname(os.path.abspath(script)), env=env)
    out_cap, err_cap = _Capture(proc.stdout), _Capture(proc.stderr)
    out_cap.start()
    err_cap.start()
    poller = _Poller(unit)
    poller.start()
    wall_exceeded = False
    try:
        rc = proc.wait(timeout=wall)
    except subprocess.TimeoutExpired:
        wall_exceeded = True
        _systemctl("kill", "--signal=SIGKILL", f"{unit}.scope")
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait()
    wall_s = time.monotonic() - t0
    cg = _cgroup_dir(unit)
    leftover = len([x for x in _read(cg + "/cgroup.procs").split() if x.strip()]) if cg else 0
    _systemctl("kill", "--signal=SIGKILL", f"{unit}.scope")
    _systemctl("stop", f"{unit}.scope")
    poller.stop.set()
    poller.join(timeout=2)
    out_cap.join(timeout=5)
    err_cap.join(timeout=5)
    stats = parse_stats(_read(stats_path))
    try:
        os.unlink(stats_path)
    except OSError:
        pass

    peak = stats.get("memory_peak") or poller.peak
    oom_kills = max(stats.get("oom_kill") or 0, poller.oom_kill)
    exit_code = stats.get("rc") if stats.get("rc") is not None else rc
    if exit_code is not None and exit_code < 0:
        exit_code = 128 - exit_code
    return {
        "unit_name": unit,
        "script": os.path.abspath(script),
        "exit": exit_code,
        "wall_exceeded": wall_exceeded,
        "started_at": started,
        "ended_at": time.time(),
        "limits": {
            "wall_s": round(wall_s, 3),
            "wall_max_s": wall,
            "peak_mem_mb": round(peak / (1024 * 1024), 1) if peak else None,
            "mem_max_mb": round(mem_bytes / (1024 * 1024), 1),
            "oom": oom_kills > 0,
            "oom_kills": oom_kills,
            "pids_max": pids,
            "pids_limit_hit": max(stats.get("pids_max_events") or 0, poller.pids_max_events),
            "wall_exceeded": wall_exceeded,
            "leftover_processes": leftover,
        },
        "stdout": out_cap.buf.decode("utf-8", "replace"),
        "stderr": err_cap.buf.decode("utf-8", "replace"),
        "stdout_bytes": out_cap.total,
        "stderr_bytes": err_cap.total,
    }
