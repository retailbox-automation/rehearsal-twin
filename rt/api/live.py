"""Live endpoints over the orchestrator (RT_MODE=live).

    GET  /api/presets
    POST /api/rehearsals                      {preset | script | goal, scope?}      -> 202 {id}
    GET  /api/rehearsals                      newest first
    GET  /api/rehearsals/{id}                 screen view built from the real ledgers ({id} may be "latest")
    GET  /api/rehearsals/{id}/events          SSE: replays the feed, then follows it (?follow=0: replay only)
    GET  /api/rehearsals/{id}/ledgers         raw ledgers (twin attempts, production) and compare.json
    POST /api/rehearsals/{id}/approve         {ledger_sha256, script_sha256, snapshot_id, prod_state_version}
                                              -> 202, or 409 with the reasons when anything shifted
    GET  /api/rehearsals/{id}/receipt         signed receipt
    GET  /api/receipts/pubkey                 public key that signs receipts
    GET  /api/instances                       live GET /v2/instances, rt-twin / rt-keep / rehearsal tags only
    GET  /api/stats                           twins alive, runs, share of applied runs where predicted = happened

POST endpoints need RT_API_TOKEN (Authorization: Bearer or X-RT-Token) when it is set.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import sys
import threading
import time
from typing import Callable

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from rt.orchestrator import Busy, Conflict, NotConfigured, Orchestrator, Settings, UnknownRehearsal, build_live


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


def _thread(fn: Callable[[], object]) -> None:
    def safe():
        try:
            fn()
        except Exception as e:  # the orchestrator records its own failures; this is the last resort
            print(f"rt.api.live: background task failed: {type(e).__name__}: {e}", file=sys.stderr)
    threading.Thread(target=safe, daemon=True).start()


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


def install(app: FastAPI, orch: Orchestrator | None = None, *,
            run_in_background: Callable[[Callable[[], object]], None] | None = None,
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
    if orch is not None:
        orch.recover()
    background = run_in_background or _thread
    token = settings.api_token

    def need() -> Orchestrator:
        if orch is None:
            raise HTTPException(503, {"error": "not configured", "detail": problem})
        return orch

    def guard(authorization: str | None, x_rt_token: str | None) -> None:
        if not token:
            return
        given = x_rt_token or ""
        if not given and authorization and authorization.lower().startswith("bearer "):
            given = authorization[7:].strip()
        if not hmac.compare_digest(given.encode(), token.encode()):
            raise HTTPException(401, "token required")

    def known(o: Orchestrator, rid: str) -> str:
        try:
            return o.load(rid)["id"]
        except UnknownRehearsal:
            raise HTTPException(404, "unknown rehearsal") from None

    @app.get("/api/presets")
    def presets() -> dict:
        return {"presets": [p.public() for p in need().presets.values()]}

    @app.post("/api/rehearsals", status_code=202)
    def create(body: RehearsalIn, authorization: str | None = Header(None),
               x_rt_token: str | None = Header(None)) -> dict:
        guard(authorization, x_rt_token)
        o = need()
        try:
            rec = o.create(preset=body.preset, script=body.script, goal=body.goal, scope=body.scope)
        except NotConfigured as e:
            raise HTTPException(503, str(e)) from None
        except Busy as e:
            raise HTTPException(409, {"error": "busy", "detail": str(e)}) from None
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        background(lambda: o.run(rec["id"]))
        return {"id": rec["id"], "status": rec["status"], "events": f"/api/rehearsals/{rec['id']}/events"}

    @app.get("/api/rehearsals")
    def listing() -> dict:
        o = need()
        recs = [o.store.load(r) for r in reversed(o.store.ids())]
        return {"rehearsals": [{k: r.get(k) for k in ("id", "created_at", "status", "name", "preset", "source",
                                                       "error")} for r in recs]}

    @app.get("/api/rehearsals/{rid}")
    def view(rid: str) -> dict:
        o = need()
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
                x_rt_token: str | None = Header(None)) -> dict:
        guard(authorization, x_rt_token)
        o = need()
        rid = known(o, rid)
        try:
            o.approve(rid, body.model_dump())
        except Conflict as e:
            raise HTTPException(409, {"error": "shift", "reasons": e.reasons}) from None
        except Busy as e:
            raise HTTPException(409, {"error": "busy", "detail": str(e)}) from None
        background(lambda: o.apply(rid))
        return {"id": rid, "status": "applying"}

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
