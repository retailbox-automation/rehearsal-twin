#!/usr/bin/env python3
"""Red-team runner for Rehearsal Twin.

    python3 redteam/run.py --target docker [--only ID,ID] [--attacks DIR] [--keep] [--save-ledgers DIR]
    python3 redteam/run.py --target ssh://root@twin-host --i-confirm-twin   (needs a VM; not exercised here)

Every attack is a bash script plus expect.json. The runner puts the script on the target,
rehearses it with `rtrace before/run/after/diff`, judges the ledger against the expectations
(redteam/checks.py) and writes redteam/reports/<date>-<target>.json.

Safety: an attack is only ever executed through a Target object whose guard has just
proved that the target is the disposable red-team stand (container name prefix rt-l4-,
inside a container, its own systemd, a hostname different from this machine) or a twin
the operator confirmed explicitly. Nothing is executed on this machine.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from redteam import checks  # noqa: E402

PREFIX = "rt-l4-"
IMAGE = "rt-l4-prod:local"
PROD, SINK, NET = "rt-l4-prod", "rt-l4-sink", "rt-l4-net"


def stand_addresses(net24: str) -> tuple[str, str, str, str]:
    """(subnet, sink, control, gateway) of the stand's /24 from its first three octets ("172.31.77").

    Overridable with RT_L4_NET24 when another Docker network on the machine already uses the range."""
    octets = net24.split(".")
    if len(octets) != 3 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
        raise ValueError(f"RT_L4_NET24 must be three octets like 172.31.77, got {net24!r}")
    return f"{net24}.0/24", f"{net24}.10", f"{net24}.250", f"{net24}.1"


SUBNET, SINK_IP, CONTROL_IP, GATEWAY = stand_addresses(os.environ.get("RT_L4_NET24", "172.31.77"))
WORK = "/opt/rt/work"
RT = "/opt/rt/bin/rtrace"
DOCKERFILE = """FROM ubuntu:24.04
RUN apt-get update -q \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \\
    systemd systemd-sysv dbus procps postgresql auditd iptables iproute2 openssl curl wget \\
    dnsutils netcat-openbsd iputils-ping python3 ca-certificates \\
 && for u in systemd-binfmt.service proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount; do \\
      ln -sf /dev/null "/etc/systemd/system/$u"; done
"""
# The stand runs systemd in a --privileged container, so /proc/sys/fs/binfmt_misc is the Docker VM's own.
# systemd-binfmt would register Ubuntu's python3.12 entry there at boot and, on stop, unregister EVERY
# entry of the VM (Rosetta x86_64 included), breaking other containers on the machine. Masked in the
# image and checked before the privileged container starts.
BINFMT_MASKED = ("systemd-binfmt.service", "proc-sys-fs-binfmt_misc.automount", "proc-sys-fs-binfmt_misc.mount")
DEFAULT_SCOPE = {"paths": ["/srv/app/tmp"], "tables": ["sessions"], "hosts": []}


class GuardError(RuntimeError):
    pass


def sh(argv, input=None, timeout=120, check=False):
    p = subprocess.run(argv, input=input, capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:4])}: rc={p.returncode} {err.strip()[:300]}")
    return p.returncode, out, err


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def wait_for_load(limit=14.0, step=60, tries=10):
    for _ in range(tries):
        if os.getloadavg()[0] <= limit:
            return
        print(f"[{now_utc()}] load {os.getloadavg()[0]:.1f} > {limit}, waiting {step}s", flush=True)
        time.sleep(step)
    raise RuntimeError("machine stayed too loaded")


# ---------------------------------------------------------------- targets

def check_container_guard(run, name: str, image: str, host_name: str):
    """Raise GuardError unless `name` is our own disposable red-team container.

    `run(argv) -> (rc, out)` executes a docker CLI command; kept injectable for tests.
    """
    if not name.startswith(PREFIX):
        raise GuardError(f"container name {name!r} lacks the {PREFIX} prefix")
    rc, out = run(["docker", "inspect", "-f", "{{.Name}}|{{.State.Running}}|{{.Config.Image}}", name])
    if rc != 0 or out.strip() != f"/{name}|true|{image}":
        raise GuardError(f"docker inspect says {out.strip()!r}, expected /{name}|true|{image}")
    rc, out = run(["docker", "exec", name, "sh", "-c",
                   "test -f /.dockerenv && cat /proc/1/comm && hostname"])
    parts = out.split()
    if rc != 0 or len(parts) != 2 or parts[0] != "systemd":
        raise GuardError(f"not inside the stand container: {out.strip()!r}")
    if parts[1] == host_name:
        raise GuardError("container hostname equals the host name: refusing to run an attack")


class Target:
    kind = "?"
    has_sink = False
    audit = False

    def exec(self, argv, input=None, timeout=120):  # -> (rc, out, err)
        raise NotImplementedError

    def bash(self, script: str, timeout=120):
        return self.exec(["bash", "-c", script], timeout=timeout)

    def put(self, path: str, data: bytes, mode="0644"):
        rc, _, err = self.exec(["bash", "-c", f"cat > {shlex.quote(path)} && chmod {mode} {shlex.quote(path)}"],
                               input=data)
        if rc != 0:
            raise RuntimeError(f"put {path}: {err.strip()[:200]}")

    def get(self, path: str, timeout=60) -> str:
        rc, out, err = self.exec(["cat", path], timeout=timeout)
        return out if rc == 0 else ""

    def guard(self):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError


class DockerTarget(Target):
    kind = "docker"
    has_sink = True

    def __init__(self):
        self.base_present = False

    def _docker(self, argv):
        rc, out, _ = sh(argv, timeout=60)
        return rc, out

    def guard(self):
        check_container_guard(self._docker, PROD, IMAGE, socket.gethostname())

    def exec(self, argv, input=None, timeout=120):
        if not argv:
            raise ValueError("empty argv")
        flags = ["-i"] if input is not None else []
        return sh(["docker", "exec", *flags, PROD, *argv], input=input, timeout=timeout)

    def sink_events(self):
        rc, out, _ = sh(["docker", "exec", SINK, "cat", "/sink/events.jsonl"], timeout=30)
        evs = []
        for line in out.splitlines():
            try:
                evs.append(json.loads(line))
            except ValueError:
                pass
        return evs

    def reset(self):
        rc, out, err = self.bash("bash /var/lib/rt-l4/stand.sh reset", timeout=240)
        if rc != 0:
            raise RuntimeError(f"stand reset failed: {out.strip()[-300:]} {err.strip()[-300:]}")
        rc, out, _ = self.bash("bash /var/lib/rt-l4/stand.sh probe", timeout=60)
        if "PROBE_OK" not in out:
            raise RuntimeError("egress recorder does not record after the reset")

    # -- stand life cycle
    def build(self):
        rc, _, _ = sh(["docker", "image", "inspect", "ubuntu:24.04"])
        self.base_present = rc == 0
        sh(["docker", "build", "-q", "-t", IMAGE, "-"], input=DOCKERFILE.encode(), timeout=900, check=True)

    def check_binfmt_masked(self):
        """Refuse to boot the privileged stand unless systemd-binfmt is masked in the image (see BINFMT_MASKED)."""
        for unit in BINFMT_MASKED:
            rc, out, _ = sh(["docker", "run", "--rm", "--network", "none", "--entrypoint", "readlink", IMAGE,
                             f"/etc/systemd/system/{unit}"])
            if rc != 0 or out.strip() != "/dev/null":
                raise GuardError(f"{unit} is not masked in {IMAGE}: the privileged stand would rewrite the "
                                 "Docker VM's binfmt_misc (Rosetta) on boot and on stop")

    def up(self):
        self.check_binfmt_masked()
        sh(["docker", "network", "create", "--internal", "--subnet", SUBNET, NET], check=True)
        sh(["docker", "run", "-d", "--name", SINK, "--network", NET, "--ip", SINK_IP,
            "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--memory", "256m",
            "-v", f"{HERE / 'sink.py'}:/sink.py:ro", IMAGE, "python3", "-u", "/sink.py"], check=True)
        sh(["docker", "run", "-d", "--name", PROD, "--privileged", "--cgroupns=private", "--network", NET,
            "--cpus", "4", "--memory", "3g", "--memory-swap", "3g", "--pids-limit", "4096",
            "--tmpfs", "/run", "--tmpfs", "/run/lock", "-v", f"{REPO}:/src:ro", IMAGE,
            "/lib/systemd/systemd"], check=True)
        state = ""
        for _ in range(90):
            _, state, _ = sh(["docker", "exec", PROD, "systemctl", "is-system-running"])
            if state.strip() in ("running", "degraded"):
                break
            time.sleep(1)
        self.guard()
        # docker --internal gives the subnet a gateway address but no endpoint gets a default
        # route to it (true isolation): nothing outside the stand's /24 even reaches the routing
        # layer, so rt-egress's iptables REDIRECT never fires for a public-looking destination.
        # A real twin has exactly one interface too (no public IP) but DOES get a default route
        # from its VPC DHCP even though that gateway cannot forward past the VPC; this route makes
        # the stand match that: a lookalike destination gets a route, reaches netfilter OUTPUT,
        # and is redirected locally -- it still can never leave the machine.
        rc, _, err = self.exec(["ip", "route", "replace", "default", "via", GATEWAY, "dev", "eth0"])
        if rc != 0:
            raise RuntimeError("could not install the stand's default route: " + err.strip()[:200])
        env = dict(os.environ, RT_CONTROL_IP=CONTROL_IP)
        p = subprocess.run(["bash", str(REPO / "fixtures/prod/make-userdata.sh")], capture_output=True, env=env,
                           timeout=120)
        if p.returncode != 0:
            raise RuntimeError("make-userdata failed: " + p.stderr.decode()[:300])
        self.put("/var/tmp/prod-userdata.sh", p.stdout)
        rc, out, err = self.exec(["bash", "/var/tmp/prod-userdata.sh"], timeout=900)
        if rc != 0:
            raise RuntimeError("demo PROD build failed: " + (out + err)[-600:])
        self.exec(["install", "-d", "/var/lib/rt-l4"])
        self.put("/var/lib/rt-l4/stand.sh", (HERE / "stand/stand.sh").read_bytes(), "0755")
        rc, out, err = self.bash("bash /var/lib/rt-l4/stand.sh probe", timeout=60)
        if "PROBE_OK" not in out:
            raise RuntimeError("egress recorder is not working in the stand: " + (out + err)[-300:])
        rc, out, err = self.bash("bash /var/lib/rt-l4/stand.sh golden", timeout=300)
        if rc != 0:
            raise RuntimeError("golden state failed: " + (out + err)[-300:])
        print("stand:", out.strip().splitlines()[-1], flush=True)

    def down(self):
        sh(["docker", "rm", "-f", PROD, SINK])
        sh(["docker", "network", "rm", NET])
        sh(["docker", "rmi", IMAGE])
        if not self.base_present:
            sh(["docker", "rmi", "ubuntu:24.04"])

    def leftovers(self) -> list:
        left = []
        _, out, _ = sh(["docker", "ps", "-a", "--format", "{{.Names}}"])
        left += [n for n in out.split() if n.startswith(PREFIX)]
        _, out, _ = sh(["docker", "network", "ls", "--format", "{{.Name}}"])
        left += [n for n in out.split() if n.startswith(PREFIX)]
        _, out, _ = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
        left += [n for n in out.split() if n.startswith(PREFIX)]
        return left


class SshTarget(Target):
    """A real twin over SSH. Not exercised in this repo yet: it needs a VM without a public IP."""
    kind = "ssh"

    def __init__(self, dest: str, confirmed: bool, reset_cmd: str | None):
        self.dest, self.confirmed, self.reset_cmd = dest, confirmed, reset_cmd
        self.audit = True

    def guard(self):
        host = self.dest.split("@")[-1]
        if not self.confirmed:
            raise GuardError("ssh target needs --i-confirm-twin: attacks run as root on that machine")
        if host in ("localhost", "127.0.0.1", "::1", socket.gethostname()):
            raise GuardError("refusing to attack this machine")
        rc, out, _ = self.exec(["bash", "-c", "test -x /opt/rt/bin/rtrace && test -f /opt/rt/canaries.json && echo twin"])
        if rc != 0 or out.strip() != "twin":
            raise GuardError("the remote machine has no rtrace and no decoy registry: not a twin")

    def exec(self, argv, input=None, timeout=120):
        return sh(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self.dest, shlex.join(argv)],
                  input=input, timeout=timeout)

    def reset(self):
        if self.reset_cmd:
            sh(["bash", "-c", self.reset_cmd], timeout=900, check=True)


# ---------------------------------------------------------------- attack execution

def load_attacks(root: Path, only=None) -> list:
    out = []
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        exp = json.loads((d / "expect.json").read_text())
        if only and exp["id"] not in only:
            continue
        exp["_dir"] = d
        out.append(exp)
    return out


def rehearse(t: Target, exp: dict) -> dict:
    """before -> run -> after -> diff for one attack. Returns raw facts (files stay on the target)."""
    aid = exp["id"]
    lim = dict(wall=20, mem="256M", pids=128)
    lim.update(exp.get("limits") or {})
    scope = exp.get("scope") or DEFAULT_SCOPE
    script = f"{WORK}/{aid}.sh"
    t.put(script, (exp["_dir"] / "attack.sh").read_bytes(), "0755")
    t.put(f"{WORK}/{aid}.scope.json", json.dumps(scope).encode(), "0600")
    sc = f"{WORK}/{aid}.scope.json"
    facts = {"flow": {"ok": True, "failed_step": None}, "started": now_utc()}

    # Optional setup.sh: runs as root on the target, OUTSIDE the sandbox, BEFORE the before-snapshot,
    # so an attack can start from a planted precondition (e.g. a large file already on disk, which the
    # attack then rewrites in place). Attacks with no setup.sh behave exactly as before.
    setup_src = exp["_dir"] / "setup.sh"
    if setup_src.exists():
        setup = f"{WORK}/{aid}.setup.sh"
        t.put(setup, setup_src.read_bytes(), "0755")
        rc, _, err = t.bash(f"bash {setup}", timeout=120)
        if rc != 0:
            facts["flow"] = {"ok": False, "failed_step": f"setup rc={rc} {err.strip()[-120:]}"}
            return facts

    def step(name, argv, out_file, timeout):
        rc, _, err = t.bash(f"{shlex.join(argv)} > {out_file}", timeout=timeout)
        body = t.get(out_file)
        ok = rc == 0 and body.strip() != ""
        if not ok and facts["flow"]["ok"]:
            facts["flow"] = {"ok": False, "failed_step": f"{name} rc={rc} {err.strip()[-120:]}"}
        return ok, body

    ok, _ = step("before", [RT, "before", "--scope", sc], f"{WORK}/{aid}.s0.json", 120)
    if ok:
        ok, run_body = step("run", [RT, "run", "--script", script, "--wall", str(lim["wall"]), "--mem", lim["mem"],
                                    "--pids", str(lim["pids"])], f"{WORK}/{aid}.run.json", lim["wall"] + 90)
        facts["run"] = json.loads(run_body) if ok else None
    if ok:
        ok, _ = step("after", [RT, "after", "--scope", sc], f"{WORK}/{aid}.s1.json", 180)
    ledger = None
    if ok:
        ok, body = step("diff", [RT, "diff", f"{WORK}/{aid}.s0.json", f"{WORK}/{aid}.s1.json",
                                 f"{WORK}/{aid}.run.json", "--scope", sc], f"{WORK}/{aid}.ledger.json", 120)
        if ok:
            try:
                ledger = json.loads(body)
            except ValueError:
                facts["flow"] = {"ok": False, "failed_step": "diff produced invalid JSON"}
    facts["ledger"] = ledger
    facts["scope"] = scope
    facts["offset_egress_end"] = None
    if ledger is not None:
        try:
            s1 = json.loads(t.get(f"{WORK}/{aid}.s1.json"))
            facts["offset_egress_end"] = (s1.get("offsets") or {}).get("egress_log")
        except ValueError:
            pass
    return facts


def survivor_pattern(aid: str) -> str:
    """pgrep -f pattern for what the script left running: processes marked rt-l4-mark, and any process
    still running the attack's own script file (subshells, fork-bomb children, busy loops). The bracket
    keeps pgrep from matching its own command line."""
    return f"[r]t-l4-mark|[/]opt/rt/work/{aid}[.]sh"


def collect_after(t: Target, facts: dict, tokens: list, aid: str | None = None):
    """Facts that do not come from the ledger: survivors, late egress, fake live API."""
    time.sleep(4)
    rc, out, _ = t.exec(["pgrep", "-fc", survivor_pattern(aid) if aid else "[r]t-l4-mark"])
    facts["survivors"] = int(out.strip() or 0) if out.strip().isdigit() else 0
    _, out, _ = t.bash("cat /var/log/prod-api/requests.log 2>/dev/null | wc -l")
    facts["prod_api_lines"] = int(out.strip() or 0)
    late = []
    off = facts.get("offset_egress_end")
    if isinstance(off, int):
        _, out, _ = t.bash(f"tail -c +{off + 1} /var/log/rt-egress/egress.jsonl 2>/dev/null")
        ignore = ("systemd-timesyncd", "snapd", "unattended", "apt-daily", "motd", "fwupd", "ua-timer")
        for line in out.splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("kind") == "dns" or any(x in (r.get("unit") or "") for x in ignore):
                continue
            if "rt-l4-probe" in (r.get("path") or ""):
                continue
            late.append(f"{r.get('host')}{r.get('path') or ''} from {r.get('unit') or '?'}")
    facts["late_egress"] = late


def ground_truth_files(t: Target, paths) -> dict:
    """{path: sha256 of the content | "missing"} read as root OUTSIDE the sandbox and outside the tracer.

    An attack lists the files it tries to plant (expect.json "ground_truth_files"); the runner reads them
    before and after the rehearsal, so a check can tell "the sandbox refused, nothing changed" from "the
    file changed and the ledger did not list it". None when the read failed (checks then fail closed)."""
    paths = list(paths or [])
    if not paths:
        return {}
    # Files: sha256 of the content. Directories: a mode/owner signature (a chmod/chown is the change we
    # watch for there, and a directory has no content to hash). Missing: "missing".
    script = ('for p in "$@"; do if [ -d "$p" ]; then s=$(stat -c \'dir:%a:%u:%g\' "$p" 2>/dev/null); '
              'printf \'%s\\t%s\\n\' "$p" "${s:-unreadable}"; elif [ -e "$p" ]; then '
              's=$(sha256sum < "$p" 2>/dev/null | cut -c1-64); printf \'%s\\t%s\\n\' "$p" "${s:-unreadable}"; '
              'else printf \'%s\\tmissing\\n\' "$p"; fi; done')
    rc, out, _ = t.exec(["bash", "-c", script, "rt-l4-gt", *paths], timeout=30)
    got = {}
    if rc == 0:
        for line in out.splitlines():
            p, sep, sig = line.partition("\t")
            if sep and p in paths:
                got[p] = sig.strip()
    return {p: got.get(p) for p in paths}


SAVED = ("ledger", "run", "s0", "s1")


def save_raw(t: Target, aid: str, dest: Path, tokens: list, extra: dict | None = None) -> dict:
    """Copy the attack's raw rtrace files off the stand before the reset deletes them.

    <id>.ledger.json, <id>.run.json (exit, limits, stdout/stderr up to 64 KiB each), <id>.s0.json and
    <id>.s1.json (machine state before/after), plus <id>.meta.json. Decoy token values are replaced by
    <token> in every file; meta.json counts the replacements, so a leak stays visible."""
    dest.mkdir(parents=True, exist_ok=True)
    meta = {"id": aid, "saved_at": now_utc(), "files": {}, "tokens_redacted": 0}
    for name in SAVED:
        body = t.get(f"{WORK}/{aid}.{name}.json")
        if not body:
            meta["files"][name] = "missing"
            continue
        for tok in tokens:
            if tok and tok in body:
                meta["tokens_redacted"] += body.count(tok)
                body = body.replace(tok, "<token>")
        (dest / f"{aid}.{name}.json").write_text(body)
        meta["files"][name] = len(body.encode())
    meta.update(extra or {})
    (dest / f"{aid}.meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def redact(obj, tokens):
    s = json.dumps(obj)
    for t in tokens:
        if t:
            s = s.replace(t, "<token>")
    return json.loads(s)


def compact_fact(facts: dict, sink) -> dict:
    led = facts.get("ledger")
    run = facts.get("run") or {}
    out = {"flow": facts["flow"], "run_exit": run.get("exit"), "limits": run.get("limits"),
           "survivors": facts.get("survivors"), "late_egress": facts.get("late_egress"),
           "prod_api_lines": facts.get("prod_api_lines")}
    if led:
        out.update({
            "verdict": (led.get("summary") or {}).get("verdict"),
            "summary": led.get("summary"),
            "integrity": led.get("integrity"),
            "files": {k: len(v) for k, v in (led.get("files") or {}).items()},
            "rows": led.get("rows"),
            "egress": (led.get("egress") or [])[:6],
            "dns": (led.get("dns") or [])[:6],
            "egress_dropped": led.get("egress_dropped"),
            "egress_denied": led.get("egress_denied"),
            "system_noise": led.get("system_noise"),
            "canaries": led.get("canaries"),
            "sql_count": len(led.get("sql") or []),
            "out_of_scope_kinds": sorted({o.get("kind") for o in led.get("out_of_scope") or []}),
        })
    if facts.get("gt_files"):
        out["gt_files"] = facts["gt_files"]
    if sink is not None:
        out["sink_events"] = len(sink)
        out["sink_sample"] = sink[:3]
    return out


def verify_problems(ledger, scope):
    try:
        from rt.ledger import verify
        return verify(ledger, scope)
    except Exception as exc:  # the check itself must never hide a result
        return [f"verify raised {exc.__class__.__name__}: {exc}"]


def run_all(t: Target, attacks: list, tokens: list, caps: dict, save_dir: Path | None = None) -> list:
    results = []
    sink_seen = len(t.sink_events()) if t.has_sink else 0
    for i, exp in enumerate(attacks, 1):
        if i % 10 == 1:
            wait_for_load()
        t.guard()
        t0 = time.time()
        print(f"[{now_utc()}] {i}/{len(attacks)} {exp['id']}", flush=True)
        facts = {}
        gt_paths = exp.get("ground_truth_files") or []
        try:
            gt_before = ground_truth_files(t, gt_paths)
            facts = rehearse(t, exp)
            collect_after(t, facts, tokens, exp["id"])
            if gt_paths:
                gt_after = ground_truth_files(t, gt_paths)
                facts["gt_files"] = {p: {"before": gt_before.get(p), "after": gt_after.get(p)} for p in gt_paths}
            time.sleep(1.5)
            sink = None
            if t.has_sink:
                evs = t.sink_events()
                frames = [e for e in evs[sink_seen:] if e.get("kind") == "frame"]
                sink = frames
                sink_seen = len(evs)
            led = facts.get("ledger")
            ctx = {"ledger": led, "flow": facts["flow"], "sink": sink, "tokens": tokens,
                   "survivors": facts.get("survivors"), "prod_api_lines": facts.get("prod_api_lines"),
                   "late_egress": facts.get("late_egress"), "gt_files": facts.get("gt_files"),
                   "verify_problems": verify_problems(led, facts["scope"]) if led else None}
            verdict = checks.evaluate(exp, ctx, caps)
            res = {"id": exp["id"], "class": exp["class"], "title": exp["title"],
                   "expect": exp.get("expect_text") or [c["name"] for c in exp.get("checks", [])],
                   "status": verdict["status"], "breakthrough": verdict["breakthrough"],
                   "failures": verdict["failures"], "warnings": verdict["warnings"],
                   "needs_vm": verdict["needs_vm"], "checks": verdict["checks"],
                   "fact": compact_fact(facts, sink), "seconds": round(time.time() - t0, 1)}
        except Exception as exc:
            res = {"id": exp["id"], "class": exp["class"], "title": exp["title"], "status": "ERROR",
                   "breakthrough": False, "failures": [f"runner error: {exc.__class__.__name__}: {exc}"],
                   "warnings": [], "needs_vm": [], "checks": [], "fact": {}, "seconds": round(time.time() - t0, 1)}
        results.append(redact(res, tokens))
        print(f"      {res['status']}{' BREAKTHROUGH' if res['breakthrough'] else ''}  {res['seconds']}s", flush=True)
        for f in res["failures"][:4]:
            print(f"      FAIL {f}", flush=True)
        if save_dir is not None:
            try:
                save_raw(t, exp["id"], save_dir, tokens, {"status": res["status"], "survivors": facts.get("survivors"),
                                                          "gt_files": facts.get("gt_files")})
            except Exception as exc:  # saving must never hide or change a result
                results[-1]["warnings"].append(f"raw files not saved: {exc.__class__.__name__}: {exc}")
        try:
            t.reset()
        except Exception as exc:
            print(f"      reset failed, stopping: {exc}", flush=True)
            results[-1]["warnings"].append(f"stand reset failed afterwards, run stopped: {exc}")
            break
    return results


def summarize(results: list) -> dict:
    n = len(results)
    cnt = {s: sum(1 for r in results if r["status"] == s) for s in ("PASS", "FAIL", "WARN", "NEEDS_VM", "ERROR")}
    bt = sum(1 for r in results if r["breakthrough"])
    by_class = {}
    for r in results:
        by_class[r["class"]] = by_class.get(r["class"], 0) + 1
    return {"attacks": n, "breakthroughs": bt, "by_status": cnt, "by_class": by_class,
            "line": f"{n} атак · {bt} прорывов"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="redteam")
    ap.add_argument("--target", required=True, help="docker | ssh://user@host")
    ap.add_argument("--attacks", default=str(HERE / "attacks"))
    ap.add_argument("--only", default="", help="comma-separated attack ids")
    ap.add_argument("--out", default="")
    ap.add_argument("--keep", action="store_true", help="leave the stand running (debug)")
    ap.add_argument("--save-ledgers", default="", metavar="DIR",
                    help="after each attack copy <id>.ledger/run/s0/s1.json off the stand (tokens redacted)")
    ap.add_argument("--i-confirm-twin", action="store_true")
    ap.add_argument("--reset-cmd", default=None)
    args = ap.parse_args(argv)

    only = {x for x in args.only.split(",") if x}
    attacks = load_attacks(Path(args.attacks), only or None)
    if not attacks:
        print("no attacks selected", file=sys.stderr)
        return 2
    if args.target == "docker":
        t = DockerTarget()
    elif args.target.startswith("ssh://"):
        t = SshTarget(args.target[len("ssh://"):], args.i_confirm_twin, args.reset_cmd)
    else:
        print("bad --target", file=sys.stderr)
        return 2

    started = now_utc()
    try:
        if isinstance(t, DockerTarget):
            wait_for_load()
            for stale in t.leftovers():
                print("removing stale own object:", stale, flush=True)
            t.down()
            t.build()
            t.up()
        else:
            t.guard()
        # decoy tokens stay in memory only; they are redacted from everything written
        reg = t.get("/opt/rt/canaries.json")
        tokens = [c["token"] for c in json.loads(reg).get("canaries", [])] if reg else []
        rc, out, _ = t.bash("curl -s -m 3 -o /dev/null http://192.0.2.88:81/x; sleep 1; cat /srv/app/.env.canary >/dev/null;"
                            " sleep 2; grep -c rt_canary_env /var/log/audit/audit.log 2>/dev/null || echo 0")
        audit_ok = out.strip().splitlines()[-1].strip().isdigit() and int(out.strip().splitlines()[-1]) > 0
        caps = {"audit": bool(audit_ok), "sink": t.has_sink}
        print(f"[{now_utc()}] capabilities {caps}", flush=True)
        t.bash(f"cat > {WORK}/target.env <<'EOF'\nSINK_IP={SINK_IP}\nCONTROL_IP={CONTROL_IP}\nEOF")
        if t.has_sink:
            info = json.loads(sh(["docker", "exec", SINK, "cat", "/sink/info.json"])[1] or "{}")
            v6 = next((a for a in info.get("v6", []) if a.startswith("fe80")), "")
            t.bash(f"printf 'SINK_V6=%s\\n' '{v6}' >> {WORK}/target.env")
        results = run_all(t, attacks, tokens, caps, Path(args.save_ledgers) if args.save_ledgers else None)
    finally:
        left = []
        if isinstance(t, DockerTarget) and not args.keep:
            t.down()
            left = t.leftovers()
    report = {"generated_at": now_utc(), "started_at": started, "target": args.target,
              "capabilities": caps if "caps" in locals() else None, "summary": summarize(results),
              "leftover_own_objects": left, "attacks": results}
    day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    out = Path(args.out) if args.out else HERE / "reports" / f"{day}-{args.target.split('://')[0]}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    s = report["summary"]
    print(f"\n{s['line']}  | PASS {s['by_status']['PASS']} FAIL {s['by_status']['FAIL']} "
          f"WARN {s['by_status']['WARN']} NEEDS_VM {s['by_status']['NEEDS_VM']} ERROR {s['by_status']['ERROR']}")
    print("report:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
