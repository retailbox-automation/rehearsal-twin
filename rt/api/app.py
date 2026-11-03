"""API: the static screen plus either the demo fixture (RT_MODE=fixture, default) or the live
orchestrator (RT_MODE=live, routes in rt/api/live.py)."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

WEB_DIR = Path(__file__).resolve().parents[2] / "web"
FIXTURE_DIR = WEB_DIR / "fixtures"
PRESET_DIR = WEB_DIR.parent / "presets"


def load_rehearsal(rid: str) -> dict:
    """Return the fixture for a rehearsal id; only plain ids are looked up."""
    if not rid.isalnum():
        raise HTTPException(404, "unknown rehearsal")
    path = FIXTURE_DIR / f"rehearsal-{rid}.json"
    if not path.is_file():
        raise HTTPException(404, "unknown rehearsal")
    return json.loads(path.read_text())


def sse_frame(event_id: int, event: str, data: dict) -> str:
    return f"id: {event_id}\nevent: {event}\ndata: {json.dumps(data)}\n\n"


async def replay(rehearsal: dict, pace: float):
    """Yield the fixture timeline as SSE frames, sleeping delay_ms * pace between them."""
    for i, item in enumerate(rehearsal["timeline"]):
        delay = item["delay_ms"] / 1000 * pace
        if delay > 0:
            await asyncio.sleep(delay)
        yield sse_frame(i, item["type"], item["data"])
    yield sse_frame(len(rehearsal["timeline"]), "done", {})


def create_app(mode: str | None = None, orchestrator=None, run_in_background=None) -> FastAPI:
    mode = (mode or os.environ.get("RT_MODE") or "fixture").strip().lower()
    if mode not in ("fixture", "live"):
        raise ValueError(f"RT_MODE must be fixture or live, not {mode!r}")
    app = FastAPI(title="Rehearsal Twin", docs_url=None, redoc_url=None)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    if mode == "live":
        from rt.api.live import install
        install(app, orchestrator, run_in_background=run_in_background)
    else:
        _fixture_routes(app)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    app.mount("/", StaticFiles(directory=WEB_DIR), name="web")
    return app


def _fixture_routes(app: FastAPI) -> None:
    @app.get("/api/rehearsals/{rid}")
    def get_rehearsal(rid: str) -> dict:
        return load_rehearsal(rid)

    @app.get("/api/rehearsals/{rid}/events")
    def rehearsal_events(rid: str, pace: float = 1.0) -> StreamingResponse:
        rehearsal = load_rehearsal(rid)
        return StreamingResponse(
            replay(rehearsal, max(pace, 0.0)),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/presets")
    def presets() -> dict:
        items = [json.loads(p.read_text()) for p in sorted(PRESET_DIR.glob("*/preset.json"))]
        return {"presets": [{k: i.get(k) for k in ("id", "name", "title", "goal")} for i in items]}

    @app.get("/api/instances")
    def instances() -> dict:
        return {"instances": load_rehearsal("a")["instances"]}

    @app.get("/api/stats")
    def stats() -> dict:
        r = load_rehearsal("a")
        c = r["compare"]
        match = c["predicted"] == c["happened"]
        return {"_demo": r["_demo"], "twins_alive": sum(i["label"].startswith("twin-") for i in r["instances"]),
                "runs": 1, "applied": 1, "matched": int(match), "match_rate": 1.0 if match else 0.0}


app = create_app()
