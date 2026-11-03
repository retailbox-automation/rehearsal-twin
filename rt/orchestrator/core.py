"""Rehearsal state machine on the control machine.

    create(preset | script | goal, scope)                       -> queued
    run():  [goal: input filter -> planner.plan]
            attempt 1 on a fresh twin: Twin.create from the golden snapshot -> wait_ready
              -> script + scope.json into /opt/rt/work/<run>/ -> rtrace before/run/after/diff
              -> Twin.destroy (always, finally) -> ledger re-checked HERE (rt.ledger.verify)
            out of scope -> input filter on ledger data -> planner.explain -> safer script
              -> next attempt on a NEW twin (at most 3 safer attempts)
            in scope, exit 0 -> production state version read -> awaiting_approval
    approve(ledger_sha256, script_sha256, snapshot_id, prod_state_version)
            any field off, golden snapshot changed or production changed -> Conflict (HTTP 409)
    apply(): same tracer on production; before the script runs its state must still have the
            approved version -> ledger re-checked here -> compare(twin, prod) -> signed receipt

The twin's verdict is never trusted: a ledger whose facts do not give its own scope check
and hash on this machine is rejected. The model never decides in/out of scope.
Every step appends an event to events.jsonl; the API streams it as SSE.
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Callable

from rt.ledger import compare as ledger_compare
from rt.ledger import finalize, ledger_sha256, normalize_scope, verify
from rt.ledger.scope import ScopeError
from rt.orchestrator import remote
from rt.orchestrator.presets import load_presets
from rt.orchestrator.settings import Settings
from rt.orchestrator.store import Store, UnknownRehearsal, new_id, utc_now
from rt.orchestrator.view import effect_counts, ledger_view, screen_view
from rt.twin.lifecycle import PROTECTED_TAGS, TWIN_TAG, Prod, Twin, has_public_ip

RUNNING = ("queued", "planning", "rehearsing", "reviewing", "applying")
TERMINAL = ("failed", "no_safe_variant", "blocked_goal", "applied", "apply_failed", "apply_aborted", "interrupted")
APPROVAL_FIELDS = ("ledger_sha256", "script_sha256", "snapshot_id", "prod_state_version")
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


def _err(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"[:500]


class Orchestrator:
    def __init__(self, settings: Settings, store: Store | None = None, *, vultr, ssh_factory: Callable[[], Any],
                 planner=None, safety=None, signer=None, inference=None):
        self.s = settings
        self.store = store or Store(settings.data_dir)
        self.vultr = vultr
        self.ssh_factory = ssh_factory
        self.planner = planner
        self.safety = safety
        self.signer = signer
        self.inference = inference or getattr(planner, "client", None) or getattr(safety, "client", None)
        self.presets = load_presets(settings.presets_dir)
        self._lock = threading.RLock()
        self._running: str | None = None

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
        return screen_view(rec, presets=[p.name for p in self.presets.values()], ledger=ledger, prod_ledger=prod,
                           compare=cmp, events=events)

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
               scope: dict | None = None) -> dict:
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
            if self._running:
                raise Busy(f"rehearsal {self._running} is running")
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
            }
            self.store.create(rec)
            for k, v in files.items():
                self.store.write_file(rid, f"file-{k}", v)
            self._running = rid
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
            with self._lock:
                if self._running == rid:
                    self._running = None
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
        plan = self.planner.plan(rec["goal"], rec["scope"], self.s.target_desc)
        script = plan["script"]
        self._save(rec, script_text=script, plan={"rationale": plan["rationale"], "expected": plan["expected"]})
        self._emit(rid, "plan", {"rationale": plan["rationale"], "script_sha256": sha256_hex(script.encode())})
        return script

    def _check_twin_cap(self) -> None:
        alive = [i for i in self.vultr.list_instances(tag=TWIN_TAG) if TWIN_TAG in (i.get("tags") or [])]
        if len(alive) >= self.s.max_twins_alive:
            raise Busy(f"{len(alive)} twins alive, cap is {self.s.max_twins_alive}")

    def _files(self, rec: dict) -> dict[str, bytes]:
        return {k: self.store.read_file(rec["id"], f"file-{k}") for k in rec.get("files") or {}}

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
            self._check_twin_cap()
            twin = Twin.create(rec["snapshot_id"], twin_rid, rec["vpc_id"], rec["twin_plan"], region=self.s.region,
                               client=self.vultr, ssh=self.ssh_factory())
        except Exception as e:
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
        ex = self.planner.explain(ledger, rec["scope"], script)
        self.store.write_json(rid, f"explain-{n}.json", ex)
        a["explain"] = {"summary": ex["summary"], "why_safer": ex["why_safer"],
                        "safer_script_sha256": sha256_hex(ex["safer_script"].encode())}
        self._save(rec)
        self._emit(rid, "explain", {"n": n, **a["explain"]})
        return ex["safer_script"]

    def _prod(self) -> Prod:
        return Prod.attach(self.s.prod_instance_id, client=self.vultr, ssh=self.ssh_factory(), vpc_id=self.s.vpc_id)

    def _probe_prod(self, rec: dict, tag: str) -> tuple[str, dict, float | None]:
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
        approval = {"ledger_sha256": a["ledger_sha256"], "script_sha256": a["script_sha256"],
                    "snapshot_id": rec["snapshot_id"], "prod_state_version": version}
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
            if self._running:
                raise Busy(f"rehearsal {self._running} is running")
            appr = rec["approval"]
            reasons = [f"{k} does not match the rehearsal" for k in APPROVAL_FIELDS
                       if not isinstance(req.get(k), str) or req.get(k) != appr[k]]
            if rec["snapshot_id"] != self.s.snapshot_id:
                reasons.append("snapshot_id: the golden snapshot changed since the rehearsal")
            n = rec["approvable"]
            ledger = self.store.read_json(rid, f"ledger-{n}.json")
            if ledger_sha256(ledger) != appr["ledger_sha256"] or verify(ledger, rec["scope"]):
                reasons.append("ledger_sha256: the stored ledger no longer gives the approved hash")
            if sha256_hex(self.store.read_file(rid, f"attempt-{n}.sh")) != appr["script_sha256"]:
                reasons.append("script_sha256: the stored script no longer gives the approved hash")
            if reasons:
                self._emit(rid, "approval_refused", {"reasons": reasons})
                raise Conflict(reasons)
            self._running = rid
        try:
            version, manifest, _ = self._probe_prod(rec, "approve")
            if version != appr["prod_state_version"]:
                old = self.store.read_json(rid, "prod-state-rehearsal.json")
                reasons = ["prod_state_version: production changed since the rehearsal"]
                reasons += remote.manifest_changes(old, manifest, limit=10)
                self._emit(rid, "approval_refused", {"reasons": reasons})
                raise Conflict(reasons)
            rec = self.store.load(rid)
            self._save(rec, approved={**{k: req[k] for k in APPROVAL_FIELDS}, "approved_at": utc_now()},
                       apply={"status": "applying"}, status="applying")
            self._emit(rid, "approved", {k: req[k] for k in APPROVAL_FIELDS})
            return rec
        except BaseException:
            with self._lock:
                if self._running == rid:
                    self._running = None
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
            self._emit(rid, "step", {"step": "apply"})
            prod = self._prod()
            try:
                result = remote.trace(
                    prod, f"{rid}-apply", script, rec["scope"], self._files(rec), wall_s=self.s.wall_s,
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
            prod_ledger = result["ledger"]
            self.store.write_json(rid, "prod-ledger.json", prod_ledger)
            problems = verify(prod_ledger, rec["scope"])
            self._emit(rid, "verify", {"where": "control", "n": "prod", "ok": not problems, "problems": problems})
            twin_ledger = self.store.read_json(rid, f"ledger-{n}.json")
            cmp = ledger_compare(twin_ledger, prod_ledger)
            self.store.write_json(rid, "compare.json", cmp)
            rec["apply"] = {"status": "done", "prod_ledger_sha256": prod_ledger.get("ledger_sha256"),
                            "verify": {"ok": not problems, "problems": problems},
                            "prod_before_state_version": result["state_version"],
                            "match": cmp["match"], "counts": cmp["counts"]}
            self._save(rec)
            self._emit_view(rec)  # the screen has the comparison before the compare step lands
            self._emit(rid, "prod_counters", effect_counts(prod_ledger))
            self._emit(rid, "compare", {"match": cmp["match"], "counts": cmp["counts"]})
            self._emit(rid, "step", {"step": "compare"})
            self._collect_llm(rec, llm_mark)
            receipt = self._receipt(rec, twin_ledger, prod_ledger, cmp, script)
            self.store.write_json(rid, "receipt.json", receipt)
            sig = receipt.get("signature") or {}
            self._save(rec, receipt={"key_id": sig.get("key_id"), "signed": bool(sig),
                                     "sha256": sha256_hex(self.store.read_file(rid, "receipt.json"))},
                       status="applied")
            self._emit(rid, "receipt", {"key_id": sig.get("key_id"), "signed": bool(sig)})
        except Exception as e:
            rec = self._reload(rec)
            phase = "before the script ran" if not self.store.has_file(rid, "prod-ledger.json") else "after the run"
            self._save(rec, status="apply_failed", error=f"{_err(e)} ({phase})")
            self._emit(rid, "error", {"message": _err(e)})
        finally:
            rec = self._reload(rec)
            with self._lock:
                if self._running == rid:
                    self._running = None
            self._emit_view(rec)
            self._emit(rid, "done", {"status": rec["status"]})
        return rec

    def approve_and_apply(self, rid: str, req: dict) -> dict:
        self.approve(rid, req)
        return self.apply(rid)

    def _receipt(self, rec: dict, twin_ledger: dict, prod_ledger: dict, cmp: dict, script: bytes) -> dict:
        from rt.receipts.sign import canonical
        limits = prod_ledger.get("limits") or {}
        body = {
            "kind": "rehearsal-twin/receipt",
            "version": 1,
            "rehearsal_id": rec["id"],
            "issued_at": utc_now(),
            "source": rec["source"],
            "preset": rec.get("preset"),
            "script": {"name": rec["name"], "sha256": sha256_hex(script), "files": rec.get("files") or {}},
            "scope": rec["scope"],
            "snapshot_id": rec["snapshot_id"],
            "prod_instance_id": rec["prod_instance_id"],
            "approval": rec["approved"],
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
            "result": {"exit": prod_ledger.get("exit"), "effects": effect_counts(prod_ledger),
                       "limits": {k: limits.get(k) for k in ("oom", "wall_exceeded", "pids_limit_hit",
                                                             "wall_max_s", "mem_max_mb", "pids_max")
                                  if k in limits}},
            "compare": {"match": cmp["match"], "counts": cmp["counts"], "surprises": len(cmp["surprises"]),
                        "compare_sha256": sha256_hex(canonical(cmp))},
            "models": [{k: c.get(k) for k in ("purpose", "model_requested", "model_returned", "tokens_in",
                                              "tokens_out", "outcome")} for c in rec.get("llm_calls") or []],
        }
        return self.signer.sign(body) if self.signer is not None else body

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
        twins = sum(1 for i in self.instances() if i["dot"] == "blue")
        return {"twins_alive": twins, "runs": len(records), "applied": len(applied), "matched": len(matched),
                "match_rate": round(len(matched) / len(applied), 4) if applied else None,
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
