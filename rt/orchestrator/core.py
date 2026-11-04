"""Rehearsal state machine on the control machine.

    create(preset | script | goal, scope)                       -> queued
    run():  [goal: input filter -> planner.plan]
            attempt 1 on a fresh twin: Twin.create from the golden snapshot -> wait_ready
              -> script + scope.json into /opt/rt/work/<run>/ -> rtrace before/run/after/diff
              -> Twin.destroy (always, finally) -> ledger re-checked HERE (rt.ledger.verify)
            out of scope -> input filter on ledger data -> planner.explain -> safer script
              -> next attempt on a NEW twin (at most 3 safer attempts)
            in scope, exit 0 -> production state version read -> awaiting_approval
    approve(ledger_sha256, script_sha256, snapshot_id, prod_state_version, files_sha256[, override_drift])
            any field off, golden snapshot changed or production changed -> Conflict (HTTP 409);
            companion files re-hashed (they are part of what was approved); a twin that did not start
            from production's current data (snapshot_drift) -> 409 unless override_drift is true, and
            the override is written into the receipt
    apply(): same tracer on production; before the script runs its state must still have the
            approved version -> ledger re-checked here -> compare(twin, prod) -> signed receipt
            -> "applied" only when production matched the rehearsal and its own verdict (computed
            here) is in scope; otherwise "diverged": the receipt is still signed, and says so

    restore_prod(): Prod.restore(golden snapshot); the timer asks only when nothing is open; after it,
            every rehearsal awaiting approval whose twin started from exactly the restored state
            gets its prod_state_version re-based onto it (others keep theirs and will get 409)

The twin's verdict is never trusted: a ledger whose facts do not give its own scope check
and hash on this machine is rejected. The model never decides in/out of scope.
Every step appends an event to events.jsonl; the API streams it as SSE.

Concurrency: rehearsals queue (FIFO) and at most RT_MAX_TWINS_ALIVE run at once, each holding
at most one twin, leased so the reaper never takes it. Everything that touches production
(state probe, approval probe, apply, restore) holds one production lock. Production reserved
for an apply or a restore also holds an exclusive flock on <data_dir>/prod.lock, from approve()
to the end of apply() (or from reserve_restore() to the end of restore_prod()): a second control
process on the same data dir (the CLI next to the API) gets Busy, never a second apply. The
kernel drops the flock when the process dies.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
import time
from collections import deque
from typing import Any, Callable

from rt.ledger import compare as ledger_compare
from rt.ledger import finalize, ledger_sha256, normalize_scope, verify
from rt.ledger.scope import ScopeError
from rt.orchestrator import remote
from rt.orchestrator.leases import Leases
from rt.orchestrator.presets import load_presets
from rt.orchestrator.settings import Settings
from rt.orchestrator.store import Store, UnknownRehearsal, new_id, utc_now
from rt.orchestrator.view import effect_counts, ledger_view, screen_view
from rt.twin.lifecycle import PROTECTED_TAGS, TWIN_TAG, Prod, Twin, has_public_ip

RUNNING = ("queued", "planning", "rehearsing", "reviewing", "applying")
TERMINAL = ("failed", "no_safe_variant", "blocked_goal", "applied", "diverged", "apply_failed", "apply_aborted",
            "interrupted")
APPROVAL_FIELDS = ("ledger_sha256", "script_sha256", "snapshot_id", "prod_state_version", "files_sha256")
MAX_SCRIPT_CHARS = 20000
MAX_GOAL_CHARS = 4000


class Conflict(Exception):
    """The approval does not match the rehearsal or production any more (HTTP 409)."""

    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


class Busy(Exception):
    """Another rehearsal or apply is running, or the twin cap is reached."""


class NotConfigured(Exception):
    """Live settings are missing (names only)."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def files_digest(hashes: dict[str, str]) -> str:
    """One sha256 over the companion files' names and sha256 (sorted): what an approval binds."""
    return sha256_hex(json.dumps(dict(sorted(hashes.items())), sort_keys=True, separators=(",", ":")).encode())


class FilesChanged(RuntimeError):
    """A stored companion file no longer has the hash recorded when the rehearsal was created."""


def _err(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"[:500]


def _thread(fn: Callable[[], object]) -> None:
    def safe():
        try:
            fn()
        except Exception as e:  # each task records its own failure; this is the last resort
            print(f"rt.orchestrator: background task failed: {_err(e)}", flush=True)
    threading.Thread(target=safe, daemon=True).start()


def divergence_reasons(verify_problems: list, prod_summary: dict, cmp: dict) -> list[str]:
    """Why an apply is not a success. Empty: production did what the twin predicted, in scope."""
    out = []
    if verify_problems:
        out.append("the production ledger failed verification on control: " + "; ".join(verify_problems))
    if prod_summary.get("verdict") != "in_scope":
        out.append(f"production verdict {prod_summary.get('verdict')}: "
                   f"{prod_summary.get('out_of_scope_total')} out of scope")
    if not cmp.get("match"):
        out.append(f"production differs from the rehearsal: {len(cmp.get('surprises') or [])} surprises")
    return out


class Orchestrator:
    def __init__(self, settings: Settings, store: Store | None = None, *, vultr, ssh_factory: Callable[[], Any],
                 planner=None, safety=None, signer=None, inference=None,
                 spawn: Callable[[Callable[[], object]], None] | None = None, sleep: Callable[[float], Any] = time.sleep,
                 heartbeat: bool = True):
        self.s = settings
        self.store = store or Store(settings.data_dir)
        self.vultr = vultr
        self.ssh_factory = ssh_factory
        self.planner = planner
        self.safety = safety
        self.signer = signer
        self.inference = inference or getattr(planner, "client", None) or getattr(safety, "client", None)
        self.presets = load_presets(settings.presets_dir)
        self.spawn = spawn or _thread
        self.sleep = sleep
        self.leases = Leases(settings.data_dir, start_heartbeat=heartbeat)
        self._lock = threading.RLock()
        self._queue: deque[str] = deque()
        self._active: set[str] = set()
        self._prod_lock = threading.RLock()
        self._prod_owner: str | None = None
        self._prod_flock: int | None = None

    # ------------------------------------------------------------------ production reservation
    def _take_prod_flock(self, owner: str) -> None:
        """Exclusive, non-blocking flock on <data_dir>/prod.lock (call with self._lock held)."""
        path = self.s.data_dir / "prod.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise Busy("production is busy (another control process holds prod.lock)") from None
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps({"owner": owner, "pid": os.getpid(), "since": utc_now()}).encode())
        self._prod_flock = fd

    def _drop_prod_flock(self) -> None:
        fd, self._prod_flock = self._prod_flock, None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _release_prod(self, owner: str) -> None:
        with self._lock:
            if self._prod_owner == owner:
                self._prod_owner = None
                self._drop_prod_flock()

    # ------------------------------------------------------------------ records and events
    def _emit(self, rid: str, type_: str, data: dict | None = None) -> None:
        self.store.append_event(rid, type_, data or {})

    def _save(self, rec: dict, **changes) -> dict:
        with self._lock:
            rec.update(changes)
            self.store.save(rec)
        if "status" in changes:
            self._emit(rec["id"], "status", {"status": rec["status"], "error": rec.get("error")})
        return rec

    def _emit_view(self, rec: dict) -> None:
        try:
            view = self.view(rec["id"], with_timeline=False)
        except Exception as e:  # the feed must go on (and reach "done") even if a view cannot be built
            self._emit(rec["id"], "error", {"message": f"view not built: {_err(e)}"})
            return
        self._emit(rec["id"], "view", view)

    def _attempt(self, rec: dict, n: int) -> dict:
        return next(a for a in rec["attempts"] if a["n"] == n)

    def load(self, rid: str) -> dict:
        if rid == "latest":
            rid = self.store.latest() or ""
        return self.store.load(rid)

    def view(self, rid: str, with_timeline: bool = True) -> dict:
        rec = self.load(rid)
        rid = rec["id"]
        shown = next((a for a in reversed(rec.get("attempts") or []) if a.get("ledger_sha256")), None)
        ledger = self.store.read_json(rid, f"ledger-{shown['n']}.json") if shown else None
        prod = self.store.read_json(rid, "prod-ledger.json") if self.store.has_file(rid, "prod-ledger.json") else None
        cmp = self.store.read_json(rid, "compare.json") if self.store.has_file(rid, "compare.json") else None
        events = self.store.events(rid) if with_timeline else None
        view = screen_view(rec, presets=[p.name for p in self.presets.values()], ledger=ledger, prod_ledger=prod,
                           compare=cmp, events=events)
        view["preset_options"] = [{"id": p.id, "name": p.name} for p in self.presets.values()]
        view["origin"] = rec.get("origin")
        view["queue"] = self.queue_position(rid)
        return view

    def ledgers(self, rid: str) -> dict:
        rec = self.load(rid)
        rid = rec["id"]
        out: dict[str, Any] = {"attempts": {}}
        for a in rec.get("attempts") or []:
            name = f"ledger-{a['n']}.json"
            if self.store.has_file(rid, name):
                out["attempts"][str(a["n"])] = self.store.read_json(rid, name)
        for key, name in (("prod", "prod-ledger.json"), ("compare", "compare.json")):
            if self.store.has_file(rid, name):
                out[key] = self.store.read_json(rid, name)
        return out

    def receipt(self, rid: str) -> dict:
        rec = self.load(rid)
        if not rec.get("receipt"):
            raise UnknownRehearsal(f"{rec['id']}/receipt")
        return self.store.read_json(rec["id"], "receipt.json")

    def recover(self) -> list[str]:
        """Mark records left running by a restart as interrupted. Their twins fall to the reaper TTL."""
        hit = []
        for rid in self.store.ids():
            rec = self.store.load(rid)
            if rec.get("status") in RUNNING:
                self._save(rec, status="interrupted", error="control restarted during the run")
                self._emit(rid, "done", {"status": "interrupted"})
                hit.append(rid)
        return hit

    # ------------------------------------------------------------------ create
    def create(self, *, preset: str | None = None, script: str | None = None, goal: str | None = None,
               scope: dict | None = None, origin: str = "operator", owner_sha256: str | None = None,
               client_tag: str | None = None) -> dict:
        if self.s.missing:
            raise NotConfigured("missing settings: " + ", ".join(self.s.missing))
        files: dict[str, bytes] = {}
        name = "script.sh"
        if preset:
            p = self.presets.get(preset) or next((x for x in self.presets.values() if x.name == preset), None)
            if p is None:
                raise ValueError(f"unknown preset {preset!r}")
            source, script, files, name = "preset", p.script, dict(p.files), p.name
            goal = goal or p.goal
            scope = scope if scope is not None else p.scope
        elif script:
            source = "operator"
        elif goal:
            source = "agent"
        else:
            raise ValueError("give a preset, a script or a goal")
        if scope is None:
            raise ValueError("declare a scope: {paths, tables, hosts}")
        try:
            norm = normalize_scope(scope)
        except ScopeError as e:
            raise ValueError(f"bad scope: {e}") from None
        if script is not None and (not script.strip() or len(script) > MAX_SCRIPT_CHARS):
            raise ValueError(f"script must be 1..{MAX_SCRIPT_CHARS} characters")
        if goal is not None and len(goal) > MAX_GOAL_CHARS:
            raise ValueError(f"goal must be at most {MAX_GOAL_CHARS} characters")

        with self._lock:
            if self.queue_full():
                raise Busy(f"the queue is full ({self.s.max_queue} waiting)")
            rid = new_id()
            while self.store.exists(rid):
                rid = new_id()
            rec = {
                "id": rid, "created_at": utc_now(), "status": "queued", "error": None,
                "source": source, "preset": preset if source == "preset" else None, "name": name,
                "goal": goal, "script_text": script, "scope": norm,
                "files": {k: sha256_hex(v) for k, v in sorted(files.items())},
                "snapshot_id": self.s.snapshot_id, "vpc_id": self.s.vpc_id,
                "prod_instance_id": self.s.prod_instance_id, "prod_label": self.s.prod_label,
                "twin_plan": self.s.twin_plan, "attempts": [], "approvable": None, "approval": None,
                "approved": None, "apply": None, "receipt": None, "llm_calls": [],
                "origin": origin, "owner_sha256": owner_sha256, "client_tag": client_tag,
            }
            self.store.create(rec)
            for k, v in files.items():
                self.store.write_file(rid, f"file-{k}", v)
        self._emit(rid, "status", {"status": "queued"})
        self._emit_view(rec)
        return rec

    # ------------------------------------------------------------------ rehearsal
    def run(self, rid: str) -> dict:
        rec = self.store.load(rid)
        if rec["status"] != "queued":  # checked before anything is written: a stray call changes nothing
            raise RuntimeError(f"rehearsal is {rec['status']}, not queued")
        llm_mark = len(getattr(self.inference, "llm_calls", []) or [])
        try:
            self._emit(rid, "step", {"step": "rehearse"})
            script = rec.get("script_text")
            if rec["source"] == "agent":
                script = self._plan(rec)
                if script is None:
                    return rec
            n, kind, seen = 1, "original", set()
            while True:
                seen.add(sha256_hex(script.encode()))
                a = self._rehearse_once(rec, n, kind, script)
                if not a["verified"]:
                    self._save(rec, status="failed", error=f"attempt {n}: the twin's ledger failed verification "
                                                            f"on control: {'; '.join(a['verify']['problems'])}")
                    break
                if a["acceptable"]:
                    self._ready_for_approval(rec, a)
                    break
                if n - 1 >= self.s.max_safer_attempts:
                    self._save(rec, status="no_safe_variant",
                               error=f"no variant stayed in scope and exited 0 in {n} attempts")
                    break
                script = self._explain(rec, a, script)
                if sha256_hex(script.encode()) in seen:
                    self._save(rec, status="no_safe_variant", error="the safer variant repeats an earlier script")
                    break
                n, kind = n + 1, "safer"
                self._emit(rid, "step", {"step": "rehearse"})
        except Exception as e:  # any failure ends the rehearsal; twins were destroyed in their own finally
            rec = self._reload(rec)
            self._save(rec, status="failed", error=_err(e))
            self._emit(rid, "error", {"message": _err(e)})
        finally:
            rec = self._reload(rec)
            self._collect_llm(rec, llm_mark)
            self._emit_view(rec)
            if rec["status"] in TERMINAL:
                self._emit(rid, "done", {"status": rec["status"]})
        return rec

    def _reload(self, rec: dict) -> dict:
        try:
            return self.store.load(rec["id"])
        except UnknownRehearsal:
            return rec

    def _collect_llm(self, rec: dict, mark: int) -> None:
        calls = list(getattr(self.inference, "llm_calls", []) or [])[mark:]
        if not calls:
            return
        for c in calls:
            self._emit(rec["id"], "llm", {k: c.get(k) for k in ("purpose", "model_requested", "model_returned",
                                                                 "tokens_in", "tokens_out", "ms", "outcome")})
        self._save(rec, llm_calls=(rec.get("llm_calls") or []) + calls)

    def _plan(self, rec: dict) -> str | None:
        rid = rec["id"]
        self._save(rec, status="planning")
        if self.safety is None or self.planner is None:
            raise NotConfigured("a goal needs the planner and the input filter")
        v = self.safety.check_goal(rec["goal"])
        rec["goal_safety"] = v.as_dict()
        self._emit(rid, "input_check", {"source": "goal", **v.as_dict()})
        if v.unsafe:
            self._save(rec, status="blocked_goal", error="the input filter flagged the goal: "
                                                         + (", ".join(v.categories) or "unsafe"))
            return None
        plan = self.planner.plan(rec["goal"], rec["scope"], self.s.target_desc, files=sorted(rec.get("files") or {}))
        script = plan["script"]
        self._save(rec, script_text=script, plan={"rationale": plan["rationale"], "expected": plan["expected"]})
        self._emit(rid, "plan", {"rationale": plan["rationale"], "script_sha256": sha256_hex(script.encode())})
        return script

    def _check_twin_cap(self, rid: str) -> None:
        """Wait (up to RT_TWIN_SLOT_WAIT_S) until fewer than RT_MAX_TWINS_ALIVE twins exist on the account."""
        deadline = time.monotonic() + self.s.twin_slot_wait_s
        told = False
        while True:
            alive = [i for i in self.vultr.list_instances(tag=TWIN_TAG) if TWIN_TAG in (i.get("tags") or [])]
            if len(alive) < self.s.max_twins_alive:
                return
            left = deadline - time.monotonic()
            if left <= 0:
                raise Busy(f"{len(alive)} twins alive, cap is {self.s.max_twins_alive}")
            if not told:
                self._emit(rid, "waiting", {"reason": f"{len(alive)} twins alive, cap {self.s.max_twins_alive}"})
                told = True
            self.sleep(min(15.0, left))

    def _files(self, rec: dict) -> dict[str, bytes]:
        """The companion files, re-hashed against the hashes recorded at create(): never sent changed."""
        files = {k: self.store.read_file(rec["id"], f"file-{k}") for k in rec.get("files") or {}}
        changed = sorted(k for k, v in files.items() if sha256_hex(v) != rec["files"][k])
        if changed:
            raise FilesChanged("companion files changed since the rehearsal was created: " + ", ".join(changed))
        return files

    def _rehearse_once(self, rec: dict, n: int, kind: str, script: str) -> dict:
        rid = rec["id"]
        data = script.encode()
        self.store.write_file(rid, f"attempt-{n}.sh", data)
        a = {"n": n, "kind": kind, "status": "running", "script_name": rec["name"] if n == 1 else f"safer-{n - 1}.sh",
             "script_sha256": sha256_hex(data), "script_text": script, "twin": {}, "verified": False,
             "acceptable": False, "ledger_sha256": None, "verdict": None, "error": None}
        rec["attempts"].append(a)
        self._save(rec, status="rehearsing")
        self._emit(rid, "attempt", {"n": n, "kind": kind, "script_sha256": a["script_sha256"]})

        twin_rid = f"{n}{rid}"
        try:
            self._check_twin_cap(rid)
            self.leases.take(twin_rid, rid)  # before create: the reaper skips the rt:<twin_rid> tag from now on
            twin = Twin.create(rec["snapshot_id"], twin_rid, rec["vpc_id"], rec["twin_plan"], region=self.s.region,
                               client=self.vultr, ssh=self.ssh_factory())
            self.leases.bind(twin_rid, twin.id)
        except Exception as e:
            self.leases.drop(twin_rid)
            a["status"], a["error"] = "failed", _err(e)
            self._save(rec)
            raise
        a["twin"] = {"id": twin.id, "label": twin.label, "rid": twin_rid, "created_at": utc_now(),
                     "destroyed": False}
        self._save(rec)
        self._emit_view(rec)
        self._emit(rid, "instance_add", {"id": twin.id, "label": twin.label})
        result = None
        try:
            t0 = time.monotonic()
            twin.wait_ready(timeout=self.s.ready_timeout_s, poll_s=self.s.poll_s)
            a["twin"]["ready_s"] = round(time.monotonic() - t0, 1)
            self._emit(rid, "twin_ready", {"id": twin.id, "seconds": a["twin"]["ready_s"]})
            result = remote.trace(
                twin, f"{rid}-{n}", data, rec["scope"], self._files(rec), wall_s=self.s.wall_s, mem=self.s.mem,
                pids=self.s.pids, on_phase=lambda ph, info: self._emit(rid, "trace", {"where": "twin", "n": n,
                                                                                    "phase": ph, **info}))
        except Exception as e:
            a["status"], a["error"] = "failed", _err(e)
            raise
        finally:
            try:
                a["twin"]["destroy_s"] = twin.destroy()
                a["twin"]["destroyed"] = True
            except Exception as e:  # the reaper TTL is the backstop; say so loudly
                a["twin"]["destroy_error"] = _err(e)
                self._emit(rid, "error", {"message": f"twin {twin.id} not destroyed: {_err(e)}"})
            self.leases.drop(twin_rid)  # released either way: a twin that failed to delete is the reaper's
            self._save(rec)
            self._emit(rid, "instance_remove", {"id": twin.id, "destroyed": a["twin"]["destroyed"]})

        ledger = result["ledger"]
        self.store.write_json(rid, f"ledger-{n}.json", ledger)
        self.store.write_json(rid, f"twin-state-{n}.json", result["manifest"])
        try:
            problems = verify(ledger, rec["scope"])
        except Exception as e:  # a ledger whose facts cannot even be checked is not a ledger
            problems = [f"ledger cannot be checked: {_err(e)}"]
        a["verify"] = {"ok": not problems, "problems": problems}
        a["twin_state_version"] = result["state_version"]
        self._emit(rid, "verify", {"where": "control", "n": n, **a["verify"]})
        if problems:
            a["status"] = "rejected"
            self._save(rec)
            return a
        fresh = finalize(ledger, rec["scope"])  # the verdict used from here on is this machine's
        limits = ledger.get("limits") or {}
        a.update(verified=True, status="done", ledger_sha256=fresh["ledger_sha256"],
                 verdict=fresh["summary"]["verdict"], out_of_scope_total=fresh["summary"]["out_of_scope_total"],
                 exit=ledger.get("exit"), effects=effect_counts(fresh))
        a["acceptable"] = (a["verdict"] == "in_scope" and ledger.get("exit") == 0 and not limits.get("oom")
                           and not limits.get("wall_exceeded"))
        self._save(rec)
        self._emit(rid, "ledger", {"n": n, "ledger_sha256": a["ledger_sha256"], "verdict": a["verdict"],
                                   "exit": a["exit"], "summary": fresh["summary"]})
        self._emit_view(rec)
        for i, _ in enumerate(ledger_view(fresh)):
            self._emit(rid, "ledger_row", {"index": i})
        self._emit(rid, "twin_summary", {"n": n, "verdict": a["verdict"]})
        return a

    def _explain(self, rec: dict, a: dict, script: str) -> str:
        rid, n = rec["id"], a["n"]
        self._save(rec, status="reviewing")
        self._emit(rid, "step", {"step": "review"})
        if self.planner is None:
            raise NotConfigured("a safer variant needs the planner")
        ledger = self.store.read_json(rid, f"ledger-{n}.json")
        if self.safety is not None:
            from rt.agent.safety import ledger_fragments
            try:
                verdicts = self.safety.check_data(ledger_fragments(ledger))
                a["data_checked"] = len(verdicts)
                a["data_flags"] = [v.as_dict() for v in verdicts if v.unsafe]
                for f in a["data_flags"]:
                    self._emit(rid, "input_check", {"n": n, **f})
            except Exception as e:  # informational filter: a failed check is recorded, never read as safe
                a["data_check_error"] = _err(e)
                self._emit(rid, "error", {"message": f"input filter on ledger data failed: {_err(e)}"})
        # Companion files sit in the script's working directory; the model is told their names.
        ex = self.planner.explain(ledger, rec["scope"], script, files=sorted(rec.get("files") or {}))
        self.store.write_json(rid, f"explain-{n}.json", ex)
        a["explain"] = {"summary": ex["summary"], "why_safer": ex["why_safer"],
                        "safer_script_sha256": sha256_hex(ex["safer_script"].encode())}
        self._save(rec)
        self._emit(rid, "explain", {"n": n, **a["explain"]})
        return ex["safer_script"]

    def _prod(self) -> Prod:
        return Prod.attach(self.s.prod_instance_id, client=self.vultr, ssh=self.ssh_factory(), vpc_id=self.s.vpc_id)

    def _probe_prod(self, rec: dict, tag: str) -> tuple[str, dict, float | None]:
        with self._prod_lock:
            return self._probe_prod_locked(rec, tag)

    def _probe_prod_locked(self, rec: dict, tag: str) -> tuple[str, dict, float | None]:
        prod = self._prod()
        run = f"{rec['id']}-{tag}"
        state = remote.read_state(prod, run, rec["scope"])
        remote.drop_run_dir(prod, run)
        manifest = remote.state_manifest(state, rec["scope"])
        uptime = None
        try:
            rc, out, _ = prod.exec(["cat", "/proc/uptime"], timeout=30)
            uptime = float(out.split()[0]) if rc == 0 and out.split() else None
        except Exception:
            uptime = None
        return remote.state_version(manifest), manifest, uptime

    def _ready_for_approval(self, rec: dict, a: dict) -> None:
        rid = rec["id"]
        version, manifest, uptime = self._probe_prod(rec, "probe")
        self.store.write_json(rid, "prod-state-rehearsal.json", manifest)
        twin_manifest = self.store.read_json(rid, f"twin-state-{a['n']}.json")
        files = self._files(rec)
        approval = {"ledger_sha256": a["ledger_sha256"], "script_sha256": a["script_sha256"],
                    "snapshot_id": rec["snapshot_id"], "prod_state_version": version,
                    "files_sha256": files_digest({k: sha256_hex(v) for k, v in files.items()})}
        drift = remote.manifest_changes(twin_manifest, manifest)
        self._save(rec, approvable=a["n"], approval=approval, prod_uptime_s=uptime,
                   snapshot_matches_prod=a.get("twin_state_version") == version, snapshot_drift=drift)
        if drift:
            self._emit(rid, "drift", {"message": "the twin did not start from production's current data",
                                      "changes": drift})
        self._save(rec, status="awaiting_approval")
        self._emit(rid, "step", {"step": "review"})
        self._emit(rid, "approval", approval)

    # ------------------------------------------------------------------ approval and apply
    def approve(self, rid: str, req: dict) -> dict:
        """Check the approval against the rehearsal and production; reserve production for apply()."""
        with self._lock:
            rec = self.load(rid)
            rid = rec["id"]
            if rec.get("status") != "awaiting_approval":
                raise Conflict([f"rehearsal is {rec.get('status')}, not awaiting approval"])
            if self._prod_owner:
                raise Busy(f"production is busy ({'restore' if self._prod_owner == 'restore' else 'apply'})")
            # Records from before files_sha256 existed: the hashes recorded at create() stand in.
            appr = {"files_sha256": files_digest(rec.get("files") or {}), **rec["approval"]}
            reasons = []
            for k in APPROVAL_FIELDS:
                given = req.get(k)
                if k == "files_sha256" and given is None and not rec.get("files"):
                    continue  # no companion files: a client that does not send the field binds nothing less
                if not isinstance(given, str) or given != appr[k]:
                    reasons.append(f"{k} does not match the rehearsal")
            if rec["snapshot_id"] != self.s.snapshot_id:
                reasons.append("snapshot_id: the golden snapshot changed since the rehearsal")
            n = rec["approvable"]
            ledger = self.store.read_json(rid, f"ledger-{n}.json")
            if ledger_sha256(ledger) != appr["ledger_sha256"] or verify(ledger, rec["scope"]):
                reasons.append("ledger_sha256: the stored ledger no longer gives the approved hash")
            if sha256_hex(self.store.read_file(rid, f"attempt-{n}.sh")) != appr["script_sha256"]:
                reasons.append("script_sha256: the stored script no longer gives the approved hash")
            try:
                stored = {k: sha256_hex(v) for k, v in self._files(rec).items()}
            except (FilesChanged, OSError, UnknownRehearsal) as e:
                stored = None
                reasons.append(f"files_sha256: {e}")
            if stored is not None and files_digest(stored) != appr["files_sha256"]:
                reasons.append("files_sha256: the stored companion files no longer give the approved hash")
            drift = rec.get("snapshot_drift") or []
            override = req.get("override_drift") is True
            if drift and not override:
                reasons.append(f"snapshot_drift: the twin did not start from production's current data "
                               f"({len(drift)} changes); approve with override_drift: true to accept that")
            if reasons:
                self._emit(rid, "approval_refused", {"reasons": reasons})
                raise Conflict(reasons)
            self._take_prod_flock(rid)  # Busy when another control process has production
            self._prod_owner = rid
        try:
            if not self._prod_lock.acquire(timeout=10):
                raise Busy("production is busy")
            try:
                version, manifest, _ = self._probe_prod_locked(rec, "approve")
            finally:
                self._prod_lock.release()
            if version != appr["prod_state_version"]:
                old = self.store.read_json(rid, "prod-state-rehearsal.json")
                reasons = ["prod_state_version: production changed since the rehearsal"]
                reasons += remote.manifest_changes(old, manifest, limit=10)
                self._emit(rid, "approval_refused", {"reasons": reasons})
                raise Conflict(reasons)
            rec = self.store.load(rid)
            approved = {k: appr[k] for k in APPROVAL_FIELDS}  # every field equals the request, checked above
            if drift:
                approved.update(override_drift=True, snapshot_drift=drift)
            self._save(rec, approved={**approved, "approved_at": utc_now()},
                       apply={"status": "applying"}, status="applying")
            self._emit(rid, "approved", approved)
            return rec
        except BaseException:
            self._release_prod(rid)
            raise

    def apply(self, rid: str) -> dict:
        rec = self.load(rid)
        rid = rec["id"]
        if rec.get("status") != "applying" or not rec.get("approved"):  # checked before anything is written
            raise RuntimeError(f"rehearsal is {rec.get('status')}, not approved")
        llm_mark = len(getattr(self.inference, "llm_calls", []) or [])
        try:
            n = rec["approvable"]
            script = self.store.read_file(rid, f"attempt-{n}.sh")
            if sha256_hex(script) != rec["approved"]["script_sha256"]:
                raise RuntimeError("stored script does not match the approved hash")
            files = self._files(rec)  # exactly these bytes go to production and into the receipt
            sent = {k: sha256_hex(v) for k, v in sorted(files.items())}
            if files_digest(sent) != rec["approved"].get("files_sha256", files_digest(rec.get("files") or {})):
                raise FilesChanged("companion files do not match the approved files_sha256")
            self._emit(rid, "step", {"step": "apply"})
            self._prod_lock.acquire()
            try:
                prod = self._prod()
                result = remote.trace(
                    prod, f"{rid}-apply", script, rec["scope"], files, wall_s=self.s.wall_s,
                    mem=self.s.mem, pids=self.s.pids,
                    on_phase=lambda ph, info: self._emit(rid, "trace", {"where": "prod", "phase": ph, **info}),
                    expect_version=rec["approved"]["prod_state_version"],
                    expect_manifest=self.store.read_json(rid, "prod-state-rehearsal.json"))
            except remote.StateShift as e:
                self._save(rec, status="apply_aborted", error=f"{e}; script not run",
                           apply={"status": "aborted", "changes": e.changed})
                self._emit(rid, "error", {"message": f"apply aborted before the script ran: {e}",
                                          "changes": e.changed})
                return rec
            finally:
                self._prod_lock.release()
            prod_ledger = result["ledger"]
            self.store.write_json(rid, "prod-ledger.json", prod_ledger)
            problems = verify(prod_ledger, rec["scope"])
            self._emit(rid, "verify", {"where": "control", "n": "prod", "ok": not problems, "problems": problems})
            twin_ledger = self.store.read_json(rid, f"ledger-{n}.json")
            cmp = ledger_compare(twin_ledger, prod_ledger)
            self.store.write_json(rid, "compare.json", cmp)
            # Production's verdict comes from this machine, never from the ledger's own summary.
            prod_summary = finalize(prod_ledger, rec["scope"])["summary"]
            divergence = divergence_reasons(problems, prod_summary, cmp)
            rec["apply"] = {"status": "done", "prod_ledger_sha256": prod_ledger.get("ledger_sha256"),
                            "verify": {"ok": not problems, "problems": problems},
                            "prod_before_state_version": result["state_version"],
                            "match": cmp["match"], "counts": cmp["counts"],
                            "compare_basis": cmp.get("compare_basis", "counts"),
                            "prod_verdict": prod_summary["verdict"],
                            "prod_out_of_scope_total": prod_summary["out_of_scope_total"],
                            "outcome": "diverged" if divergence else "applied", "divergence": divergence}
            self._save(rec)
            self._emit_view(rec)  # the screen has the comparison before the compare step lands
            self._emit(rid, "prod_counters", effect_counts(prod_ledger))
            self._emit(rid, "compare", {"match": cmp["match"], "counts": cmp["counts"],
                                        "prod_verdict": prod_summary["verdict"],
                                        "outcome": rec["apply"]["outcome"]})
            self._emit(rid, "step", {"step": "compare"})
            self._collect_llm(rec, llm_mark)
            receipt = self._receipt(rec, twin_ledger, prod_ledger, cmp, script, sent)
            self.store.write_json(rid, "receipt.json", receipt)
            sig = receipt.get("signature") or {}
            self._save(rec, receipt={"key_id": sig.get("key_id"), "signed": bool(sig),
                                     "sha256": sha256_hex(self.store.read_file(rid, "receipt.json"))},
                       status=rec["apply"]["outcome"],
                       error=("production diverged from the rehearsal: " + "; ".join(divergence))
                       if divergence else None)
            if divergence:
                self._emit(rid, "diverged", {"reasons": divergence, "prod_verdict": prod_summary["verdict"],
                                             "match": cmp["match"]})
            self._emit(rid, "receipt", {"key_id": sig.get("key_id"), "signed": bool(sig)})
        except Exception as e:
            rec = self._reload(rec)
            phase = "before the script ran" if not self.store.has_file(rid, "prod-ledger.json") else "after the run"
            self._save(rec, status="apply_failed", error=f"{_err(e)} ({phase})")
            self._emit(rid, "error", {"message": _err(e)})
        finally:
            rec = self._reload(rec)
            self._release_prod(rid)
            self._emit_view(rec)
            self._emit(rid, "done", {"status": rec["status"]})
        return rec

    def approve_and_apply(self, rid: str, req: dict) -> dict:
        self.approve(rid, req)
        return self.apply(rid)

    def _receipt(self, rec: dict, twin_ledger: dict, prod_ledger: dict, cmp: dict, script: bytes,
                 files_sent: dict[str, str]) -> dict:
        from rt.receipts.sign import canonical
        limits = prod_ledger.get("limits") or {}
        body = {
            "kind": "rehearsal-twin/receipt",
            "version": 1,
            "rehearsal_id": rec["id"],
            "issued_at": utc_now(),
            "source": rec["source"],
            "preset": rec.get("preset"),
            "script": {"name": rec["name"], "sha256": sha256_hex(script), "files": files_sent,
                       "files_sha256": files_digest(files_sent)},
            "scope": rec["scope"],
            "snapshot_id": rec["snapshot_id"],
            "prod_instance_id": rec["prod_instance_id"],
            "approval": rec["approved"],
            "snapshot_drift": {"changes": rec.get("snapshot_drift") or [],
                               "overridden": bool(rec["approved"].get("override_drift"))},
            "attempts": [{"n": a["n"], "kind": a["kind"], "twin_id": a["twin"].get("id"),
                          "twin_label": a["twin"].get("label"), "twin_destroyed": a["twin"].get("destroyed"),
                          "ledger_sha256": a.get("ledger_sha256"), "verdict": a.get("verdict"),
                          "out_of_scope_total": a.get("out_of_scope_total"),
                          "verified_on_control": bool((a.get("verify") or {}).get("ok"))}
                         for a in rec["attempts"]],
            "twin_ledger_sha256": ledger_sha256(twin_ledger),
            "prod_ledger_sha256": ledger_sha256(prod_ledger),
            "prod_ledger_verified_on_control": bool(rec["apply"]["verify"]["ok"]),
            "prod_before_state_version": rec["apply"]["prod_before_state_version"],
            # The outcome a reader must not miss: "applied" only when production did exactly what
            # was rehearsed and stayed in scope by this machine's own check.
            "outcome": rec["apply"]["outcome"],
            "divergence": rec["apply"]["divergence"],
            "prod_verdict": {"verdict": rec["apply"]["prod_verdict"],
                             "out_of_scope_total": rec["apply"]["prod_out_of_scope_total"],
                             "computed_on": "control"},
            "result": {"exit": prod_ledger.get("exit"), "effects": effect_counts(prod_ledger),
                       "limits": {k: limits.get(k) for k in ("oom", "wall_exceeded", "pids_limit_hit",
                                                             "wall_max_s", "mem_max_mb", "pids_max")
                                  if k in limits}},
            "compare": {"match": cmp["match"], "counts": cmp["counts"], "surprises": len(cmp["surprises"]),
                        "compare_basis": cmp.get("compare_basis", "counts"),
                        "compare_sha256": sha256_hex(canonical(cmp))},
            "models": [{k: c.get(k) for k in ("purpose", "model_requested", "model_returned", "tokens_in",
                                              "tokens_out", "outcome")} for c in rec.get("llm_calls") or []],
        }
        return self.signer.sign(body) if self.signer is not None else body

    # ------------------------------------------------------------------ queue
    def queue_full(self) -> bool:
        with self._lock:
            return len(self._queue) >= self.s.max_queue

    def submit(self, rid: str) -> None:
        """Queue a created rehearsal; it starts when one of RT_MAX_TWINS_ALIVE slots is free."""
        with self._lock:
            if rid in self._queue or rid in self._active:
                return
            self._queue.append(rid)
        self._emit(rid, "queue", self.queue_position(rid))
        self._dispatch()

    def _dispatch(self) -> None:
        while True:
            with self._lock:
                if not self._queue or len(self._active) >= self.s.max_twins_alive:
                    return
                rid = self._queue.popleft()
                self._active.add(rid)
            self.spawn(lambda rid=rid: self._run_slot(rid))

    def _run_slot(self, rid: str) -> None:
        try:
            self.run(rid)
        except Exception as e:  # run() records its own failures; a refusal here is logged on the record
            self._emit(rid, "error", {"message": _err(e)})
        finally:
            with self._lock:
                self._active.discard(rid)
            self._dispatch()

    def queue_position(self, rid: str) -> dict:
        with self._lock:
            waiting = list(self._queue)
            running = sorted(self._active)
        return {"position": waiting.index(rid) + 1 if rid in waiting else None, "waiting": len(waiting),
                "running": len(running), "cap": self.s.max_twins_alive}

    def queue_state(self) -> dict:
        with self._lock:
            waiting = list(self._queue)
            running = sorted(self._active)

        def item(rid: str, pos: int | None) -> dict:
            try:
                r = self.store.load(rid)
            except UnknownRehearsal:
                return {"id": rid, "position": pos}
            return {"id": rid, "name": r.get("name"), "preset": r.get("preset"), "status": r.get("status"),
                    "origin": r.get("origin"), "position": pos}

        return {"running": [item(r, None) for r in running], "waiting": [item(r, i + 1) for i, r in enumerate(waiting)],
                "cap": self.s.max_twins_alive, "max_queue": self.s.max_queue}

    # ------------------------------------------------------------------ production reset
    def _prod_status_path(self):
        return self.s.data_dir / "prod-status.json"

    def prod_status(self) -> dict:
        try:
            return json.loads(self._prod_status_path().read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {"status": "unknown"}

    def _set_prod_status(self, **fields) -> dict:
        from rt.orchestrator.store import _atomic_write
        st = {**self.prod_status(), **fields}
        _atomic_write(self._prod_status_path(), json.dumps(st, sort_keys=True, indent=1).encode())
        return st

    def open_rehearsals(self) -> list[str]:
        """Rehearsals a reset would disturb: queued or running, applying, or awaiting approval recently."""
        now = time.time()
        out = []
        for rid in self.store.ids():
            r = self.store.load(rid)
            st = r.get("status")
            if st in RUNNING:
                out.append(rid)
            elif st == "awaiting_approval":
                age = now - (self.store.dir(rid) / "record.json").stat().st_mtime
                if age < self.s.approval_window_s:
                    out.append(rid)
        with self._lock:
            out += [r for r in list(self._queue) + list(self._active) if r not in out]
        return out

    def reserve_restore(self, *, only_if_idle: bool) -> dict | None:
        """Claim production for a reset. Returns a skip reason, or None when the reset may start."""
        with self._lock:
            if self._prod_owner:
                if only_if_idle:
                    return {"status": "skipped", "reason": f"production is busy ({self._prod_owner})"}
                raise Busy(f"production is busy ({self._prod_owner})")
            if only_if_idle:
                busy = self.open_rehearsals()
                if busy:
                    return {"status": "skipped", "reason": "rehearsals are open", "open": busy}
            try:
                self._take_prod_flock("restore")
            except Busy as e:
                if only_if_idle:
                    return {"status": "skipped", "reason": str(e)}
                raise
            self._prod_owner = "restore"
        return None

    def restore_prod(self, *, origin: str = "operator") -> dict:
        """Restore production from the golden snapshot (after reserve_restore), then re-base approvals."""
        with self._lock:
            if self._prod_owner != "restore":
                raise RuntimeError("call reserve_restore first")
        started = utc_now()
        self._set_prod_status(status="restoring", started_at=started, origin=origin, snapshot_id=self.s.snapshot_id,
                              error=None)
        try:
            with self._prod_lock:
                prod = self._prod()
                secs = prod.restore(self.s.snapshot_id, timeout=self.s.restore_timeout_s, poll_s=self.s.restore_poll_s,
                                    settle_s=self.s.restore_settle_s)
                rebased = self._rebase_after_restore()
            return self._set_prod_status(status="idle", last_restore_at=utc_now(), last_restore_started_at=started,
                                         last_restore_s=secs, rebased=rebased)
        except Exception as e:
            self._set_prod_status(status="error", error=_err(e))
            raise
        finally:
            self._release_prod("restore")

    def _rebase_after_restore(self) -> dict:
        """Re-read production's state version for every rehearsal awaiting approval.

        The approval is re-based only when production now equals the state the twin started from:
        then the ledger predicts exactly this production. Otherwise the old version stays and the
        approval answers 409 with the changed paths and tables.
        """
        out = {}
        for rid in self.store.ids():
            rec = self.store.load(rid)
            if rec.get("status") != "awaiting_approval" or not rec.get("approval"):
                continue
            version, manifest, uptime = self._probe_prod_locked(rec, "restore")
            a = self._attempt(rec, rec["approvable"])
            if version == rec["approval"]["prod_state_version"]:
                out[rid] = "unchanged"
            elif version == a.get("twin_state_version"):
                self.store.write_json(rid, "prod-state-rehearsal.json", manifest)
                approval = {**rec["approval"], "prod_state_version": version}
                self._save(rec, approval=approval, prod_uptime_s=uptime, snapshot_matches_prod=True, snapshot_drift=[])
                self._emit(rid, "approval", approval)
                self._emit_view(rec)
                out[rid] = "rebased"
            else:
                out[rid] = "stale"
        return out

    # ------------------------------------------------------------------ fleet and stats
    def instances(self) -> list[dict]:
        out = []
        for inst in self.vultr.list_instances():
            tags = set(inst.get("tags") or [])
            if not tags & {TWIN_TAG, "rt-keep", "rehearsal"}:
                continue
            twin = TWIN_TAG in tags and not tags & PROTECTED_TAGS
            public = has_public_ip(inst)
            meta = "rehearsal · no public IPv4" if twin and not public else ("public" if public else "VPC only")
            out.append({"id": inst.get("id"), "label": inst.get("label", ""), "tags": sorted(tags),
                        "dot": "blue" if twin else "green", "meta": meta, "vpc_only": not public,
                        "status": inst.get("status"), "power_status": inst.get("power_status"),
                        "server_status": inst.get("server_status"), "plan": inst.get("plan"),
                        "region": inst.get("region"), "date_created": inst.get("date_created")})
        return out

    def stats(self) -> dict:
        records = [self.store.load(r) for r in self.store.ids()]
        applied = [r for r in records if (r.get("apply") or {}).get("status") == "done"]
        matched = [r for r in applied if r["apply"].get("match")]
        diverged = [r for r in records if r.get("status") == "diverged"]
        twins = sum(1 for i in self.instances() if i["dot"] == "blue")
        q = self.queue_state()
        return {"twins_alive": twins, "runs": len(records), "applied": len(applied), "matched": len(matched),
                "diverged": len(diverged),
                "match_rate": round(len(matched) / len(applied), 4) if applied else None,
                "queue": {"running": len(q["running"]), "waiting": len(q["waiting"]), "cap": q["cap"]},
                "statuses": {s: sum(1 for r in records if r.get("status") == s)
                             for s in sorted({r.get("status") for r in records})}}


def build_live(settings: Settings | None = None) -> Orchestrator:
    """Wire the real clients from the environment (control machine)."""
    from rt.agent.inference import InferenceClient
    from rt.agent.planner import Planner
    from rt.agent.safety import SafetyFilter
    from rt.receipts.sign import Signer
    from rt.twin.lifecycle import SSH
    from rt.twin.vultr import Vultr

    s = settings or Settings.from_env()
    if s.missing:
        raise NotConfigured("missing settings: " + ", ".join(s.missing))
    ssh_dir = str(s.data_dir / "ssh")
    inference = InferenceClient()
    return Orchestrator(
        s, vultr=Vultr(), ssh_factory=lambda: SSH(key_file=s.ssh_key_file, jump=s.jump_host, state_dir=ssh_dir),
        planner=Planner(inference), safety=SafetyFilter(inference), signer=Signer.from_env(), inference=inference)
