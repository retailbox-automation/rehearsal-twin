"""Live endpoints over the orchestrator (RT_MODE=live).

    GET  /api/presets
    POST /api/rehearsals                      {preset | script | goal, scope?}  -> 202 {id, queue}; queued FIFO
    GET  /api/rehearsals                      newest first
    GET  /api/rehearsals/{id}                 screen view built from the real ledgers ({id} may be "latest")
    GET  /api/rehearsals/{id}/events          SSE: replays the feed, then follows it (?follow=0: replay only)
    GET  /api/rehearsals/{id}/ledgers         raw ledgers (twin attempts, production) and compare.json
    POST /api/rehearsals/{id}/approve         {ledger_sha256, script_sha256, snapshot_id, prod_state_version}
                                              -> 202, or 409 with the reasons when anything shifted
    GET  /api/rehearsals/{id}/receipt         signed receipt
    GET  /api/receipts/pubkey                 public key that signs receipts
    GET  /api/queue                           running and waiting rehearsals, cap, judge budget
    GET  /api/prod                            production reset status
    POST /api/prod/restore                    {when: "idle" | "now"}  (token only) -> 202 restoring / 200 skipped
    GET  /api/instances                       live GET /v2/instances, rt-twin / rt-keep / rehearsal tags only
    GET  /api/stats                           twins alive, runs, share of applied runs where predicted = happened

Who may do what:
  token (RT_API_TOKEN, as Authorization: Bearer or X-RT-Token): everything.
  no token, RT_JUDGE_MODE=on: start a preset (a|b|c) only, within the per-address and daily limits,
      and approve a rehearsal they started (X-RT-Owner: the owner key returned when it was started).
  no token otherwise: read-only.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import time

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from rt.orchestrator import Busy, Conflict, NotConfigured, Orchestrator, Settings, UnknownRehearsal, build_live
from rt.orchestrator.judge import JudgeGate, Limited, client_address, new_owner_key, owner_matches
from rt.orchestrator.spend import SpendGuard


class RehearsalIn(BaseModel):
    preset: str | None = None
    script: str | None = None
    goal: str | None = None
    scope: dict | None = None


class ApprovalIn(BaseModel):
    ledger_sha256: str
    script_sha256: str
    snapshot_id: str
    prod_state_version: str


class RestoreIn(BaseModel):
    when: str = "idle"


def _frame(event_id: int, event: str, data: dict) -> str:
    return f"id: {event_id}\nevent: {event}\ndata: {json.dumps(data)}\n\n"


async def follow(orch: Orchestrator, rid: str, *, live: bool, max_s: float, after: int = 0, poll_s: float = 0.25):
    offset = 0
    t0 = last = time.monotonic()
    while True:
        events, offset = orch.store.read_events(rid, offset)
        for ev in events:
            if ev["seq"] <= after:
                continue
            yield _frame(ev["seq"], ev["type"], ev["data"])
            if ev["type"] == "done":
                return
        now = time.monotonic()
        if not live or now - t0 > max_s:
            return
        if now - last > 15:
            last = now
            yield ": keep-alive\n\n"
        await asyncio.sleep(poll_s)


def install(app: FastAPI, orch: Orchestrator | None = None, *, run_in_background=None,
            settings: Settings | None = None) -> None:
    settings = settings or (orch.s if orch is not None else Settings.from_env())
    problem = ""
    if orch is None:
        try:
            orch = build_live(settings)
        except NotConfigured as e:
            problem = str(e)
        except Exception as e:  # e.g. an unreadable signing key: keep serving health and say why (no values)
            problem = f"{type(e).__name__}: {e}"
    gate = spend = None
    if orch is not None:
        if run_in_background is not None:
            orch.spawn = run_in_background
        orch.recover()
        gate = JudgeGate(settings.data_dir, per_ip_hour=settings.judge_runs_per_ip_hour,
                         daily_budget=settings.daily_run_budget)
        spend = SpendGuard(orch.vultr, settings.spend_cap_usd, cache_s=settings.spend_cache_s)
    app.state.spend = spend

    def need() -> Orchestrator:
        if orch is None:
            raise HTTPException(503, {"error": "not configured", "detail": problem})
        return orch

    def has_token(authorization: str | None, x_rt_token: str | None) -> bool:
        token = settings.api_token
        if not token:
            return False
        given = x_rt_token or ""
        if not given and authorization and authorization.lower().startswith("bearer "):
            given = authorization[7:].strip()
        return bool(given) and hmac.compare_digest(given.encode(), token.encode())

    def address(request: Request) -> str:
        peer = request.client.host if request.client else None
        return client_address(peer, request.headers.get("x-forwarded-for"))

    def known(o: Orchestrator, rid: str) -> str:
        try:
            return o.load(rid)["id"]
        except UnknownRehearsal:
            raise HTTPException(404, "unknown rehearsal") from None

    def limited(e: Limited) -> JSONResponse:
        return JSONResponse({"detail": {"error": "limit", "reason": e.reason, "retry_after_s": e.retry_after_s}},
                            status_code=429, headers={"Retry-After": str(e.retry_after_s)})

    @app.get("/api/presets")
    def presets() -> dict:
        return {"presets": [p.public() for p in need().presets.values()]}

    @app.post("/api/rehearsals", status_code=202)
    def create(body: RehearsalIn, request: Request, authorization: str | None = Header(None),
               x_rt_token: str | None = Header(None)):
        o = need()
        operator = has_token(authorization, x_rt_token)
        owner_key = owner_sha = tag = None
        if not operator:
            if not settings.judge_mode:
                raise HTTPException(401, "token required")
            if body.script is not None or body.goal is not None or body.scope is not None:
                raise HTTPException(401, "a free script, goal or scope needs the token; judges run presets")
            if not body.preset or body.preset not in o.presets:
                raise HTTPException(400, f"preset must be one of {sorted(o.presets)}")
            sp = spend.check()
            if sp["paused_reason"]:
                what = "spend cap" if sp["paused_reason"].startswith("spend cap") else "spend unknown"
                return JSONResponse({"detail": {"error": f"judge mode paused: {what}", "reason": sp["paused_reason"],
                                                "spend_pending": sp["spend_pending"],
                                                "spend_cap": sp["spend_cap"]}}, status_code=503)
            if o.queue_full():
                return limited(Limited("the queue is full", 60))
            ip = address(request)
            try:
                gate.admit(ip)
            except Limited as e:
                return limited(e)
            owner_key, owner_sha = new_owner_key()
            tag = gate.address_tag(ip)
        try:
            rec = o.create(preset=body.preset, script=body.script, goal=body.goal, scope=body.scope,
                           origin="operator" if operator else "judge", owner_sha256=owner_sha, client_tag=tag)
        except NotConfigured as e:
            raise HTTPException(503, str(e)) from None
        except Busy as e:
            return limited(Limited(str(e), 60))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        o.submit(rec["id"])
        out = {"id": rec["id"], "status": "queued", "events": f"/api/rehearsals/{rec['id']}/events",
               "queue": o.queue_position(rec["id"])}
        if owner_key:
            out["owner_key"] = owner_key
        return out

    @app.get("/api/rehearsals")
    def listing() -> dict:
        o = need()
        recs = [o.store.load(r) for r in reversed(o.store.ids())]
        return {"rehearsals": [{k: r.get(k) for k in ("id", "created_at", "status", "name", "preset", "source",
                                                       "origin", "error")} for r in recs]}

    @app.get("/api/rehearsals/{rid}")
    def view(rid: str) -> dict:
        o = need()
        if rid == "latest" and o.store.latest() is None:
            return {"id": None, "empty": True, "mode": "live",
                    "preset_options": [{"id": p.id, "name": p.name} for p in o.presets.values()],
                    "queue": o.queue_state()}
        return o.view(known(o, rid))

    @app.get("/api/rehearsals/{rid}/ledgers")
    def ledgers(rid: str) -> dict:
        o = need()
        return o.ledgers(known(o, rid))

    @app.get("/api/rehearsals/{rid}/receipt")
    def receipt(rid: str) -> dict:
        o = need()
        try:
            return o.receipt(known(o, rid))
        except UnknownRehearsal:
            raise HTTPException(404, "no receipt yet") from None

    @app.get("/api/rehearsals/{rid}/events")
    def events(rid: str, request: Request) -> StreamingResponse:
        o = need()
        rid = known(o, rid)
        live = request.query_params.get("follow", "1") != "0"
        try:
            after = int(request.headers.get("last-event-id") or 0)
        except ValueError:
            after = 0
        return StreamingResponse(follow(o, rid, live=live, max_s=o.s.sse_max_s, after=after),
                                 media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.post("/api/rehearsals/{rid}/approve", status_code=202)
    def approve(rid: str, body: ApprovalIn, authorization: str | None = Header(None),
                x_rt_token: str | None = Header(None), x_rt_owner: str | None = Header(None)) -> dict:
        o = need()
        rid = known(o, rid)
        if not has_token(authorization, x_rt_token):
            rec = o.load(rid)
            if not (settings.judge_mode and rec.get("origin") == "judge"
                    and owner_matches(x_rt_owner, rec.get("owner_sha256"))):
                raise HTTPException(401, "only the token or the owner of this rehearsal can approve it")
        try:
            o.approve(rid, body.model_dump())
        except Conflict as e:
            raise HTTPException(409, {"error": "shift", "reasons": e.reasons}) from None
        except Busy as e:
            raise HTTPException(409, {"error": "busy", "detail": str(e)}) from None
        o.spawn(lambda: o.apply(rid))
        return {"id": rid, "status": "applying"}

    @app.get("/api/queue")
    def queue() -> dict:
        o = need()
        q = o.queue_state()
        judge = {"mode": "on" if settings.judge_mode else "off", **(gate.status() if gate else {})}
        if settings.judge_mode and spend is not None:
            sp = spend.check()
            judge.update(spend_pending=sp["spend_pending"], spend_cap=sp["spend_cap"],
                         paused_reason=sp["paused_reason"])
        q["judge"] = judge
        return q

    @app.get("/api/prod")
    def prod_status() -> dict:
        o = need()
        return {**o.prod_status(), "snapshot_id": o.s.snapshot_id, "open_rehearsals": len(o.open_rehearsals())}

    @app.post("/api/prod/restore")
    def prod_restore(body: RestoreIn, authorization: str | None = Header(None),
                     x_rt_token: str | None = Header(None)):
        o = need()
        if not has_token(authorization, x_rt_token):
            raise HTTPException(401, "token required")
        if body.when not in ("idle", "now"):
            raise HTTPException(400, "when must be idle or now")
        try:
            skipped = o.reserve_restore(only_if_idle=body.when == "idle")
        except Busy as e:
            raise HTTPException(409, {"error": "busy", "detail": str(e)}) from None
        if skipped:
            return skipped

        def restore() -> None:
            try:
                o.restore_prod(origin="timer" if body.when == "idle" else "operator")
            except Exception:  # recorded in prod-status.json (GET /api/prod)
                pass
        o.spawn(restore)
        return JSONResponse({"status": "restoring"}, status_code=202)

    @app.get("/api/receipts/pubkey")
    def pubkey() -> dict:
        o = need()
        if o.signer is None:
            raise HTTPException(503, "no signing key")
        return o.signer.public_info()

    @app.get("/api/instances")
    def instances() -> dict:
        try:
            return {"instances": need().instances()}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"Vultr API: {type(e).__name__}") from None

    @app.get("/api/stats")
    def stats() -> dict:
        try:
            return need().stats()
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"stats: {type(e).__name__}") from None
