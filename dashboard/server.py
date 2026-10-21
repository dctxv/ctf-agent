"""Phase 4 dashboard backend (FastAPI).

Serves saved agent sessions and replays a session's events over SSE to mock a
live feed (the real agent emits the same typed events; wiring a running session
straight into /stream is the next step). Read-only over workspace/sessions/.

Run:  python dashboard/server.py      (or: uvicorn dashboard.server:app --port 8900)
"""
import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

ROOT = Path(__file__).resolve().parent.parent
SESSIONS = (ROOT / "workspace" / "sessions").resolve()

app = FastAPI(title="CTF Agent Dashboard")


def _list_sessions():
    out = []
    if not SESSIONS.is_dir():
        return out
    for ev in SESSIONS.rglob("events.json"):
        sid = ev.parent.relative_to(SESSIONS).as_posix()
        try:
            events = json.loads(ev.read_text(encoding="utf-8"))
        except Exception:
            continue
        goal, cost, finished, last_ts = "", 0.0, False, ""
        for e in events:
            t = e.get("type")
            data = e.get("data", {}) or {}
            if t == "session_start":
                goal = str(data.get("goal", ""))[:140]
            elif t == "cost_update":
                cost = data.get("total_usd", cost)
            elif t == "session_end":
                finished = True
            last_ts = e.get("ts", last_ts)
        out.append({"id": sid, "goal": goal, "events": len(events),
                    "cost_usd": round(cost, 4),
                    "status": "finished" if finished else "open",
                    "last_ts": last_ts})
    out.sort(key=lambda s: s["last_ts"], reverse=True)
    return out


def _events_path(sid: str) -> Path:
    p = (SESSIONS / sid / "events.json").resolve()
    if not (p.is_file() and p.is_relative_to(SESSIONS)):  # block path traversal
        raise HTTPException(status_code=404, detail="session not found")
    return p


@app.get("/api/sessions")
def api_sessions():
    return _list_sessions()


@app.get("/api/sessions/{sid:path}/events")
def api_events(sid: str):
    return JSONResponse(json.loads(_events_path(sid).read_text(encoding="utf-8")))


@app.get("/api/sessions/{sid:path}/stream")
def api_stream(sid: str):
    path = _events_path(sid)

    async def gen():
        for e in json.loads(path.read_text(encoding="utf-8")):
            yield f"data: {json.dumps(e)}\n\n"
            await asyncio.sleep(0.25)  # mock live pacing
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/")
def index():
    return HTMLResponse((Path(__file__).parent / "index.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8900)
