"""Phase 4 dashboard backend (FastAPI).

Live sessions: the agent appends each event to <session>/events.jsonl as it runs,
and /stream TAILS that file in real time. Finished/old sessions without a live log
fall back to replaying events.json. Read-only over workspace/sessions/.

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


def _read_events(sdir: Path):
    """(events, live): prefer the live JSONL log, else the final events.json."""
    jsonl = sdir / "events.jsonl"
    if jsonl.is_file():
        evs = []
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    evs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return evs, True
    j = sdir / "events.json"
    if j.is_file():
        try:
            return json.loads(j.read_text(encoding="utf-8")), False
        except Exception:
            return [], False
    return [], False


def _summary(sid, events, live):
    goal, cost, finished, last_ts = "", 0.0, False, ""
    for e in events:
        t, data = e.get("type"), (e.get("data", {}) or {})
        if t == "session_start":
            goal = str(data.get("goal", ""))[:140]
        elif t == "cost_update":
            cost = data.get("total_usd", cost)
        elif t == "session_end":
            finished = True
        last_ts = e.get("ts", last_ts)
    status = "finished" if finished else ("running" if live else "open")
    return {"id": sid, "goal": goal, "events": len(events),
            "cost_usd": round(cost, 4), "status": status, "last_ts": last_ts}


def _session_dirs():
    dirs = set()
    if SESSIONS.is_dir():
        for p in SESSIONS.rglob("events.json*"):   # events.json and events.jsonl
            dirs.add(p.parent)
    return dirs


def _sdir(sid: str) -> Path:
    p = (SESSIONS / sid).resolve()
    if not (p.is_dir() and p.is_relative_to(SESSIONS)):
        raise HTTPException(status_code=404, detail="session not found")
    return p


@app.get("/api/sessions")
def api_sessions():
    out = []
    for sdir in _session_dirs():
        events, live = _read_events(sdir)
        if events:
            out.append(_summary(sdir.relative_to(SESSIONS).as_posix(), events, live))
    out.sort(key=lambda s: s["last_ts"], reverse=True)
    out.sort(key=lambda s: s["status"] != "running")  # running sessions first (stable)
    return out


@app.get("/api/sessions/{sid:path}/events")
def api_events(sid: str):
    events, _ = _read_events(_sdir(sid))
    if not events:
        raise HTTPException(status_code=404, detail="no events")
    return JSONResponse(events)


@app.get("/api/sessions/{sid:path}/stream")
def api_stream(sid: str):
    sdir = _sdir(sid)
    if (sdir / "events.jsonl").is_file():
        return StreamingResponse(_tail(sdir / "events.jsonl"), media_type="text/event-stream")
    if (sdir / "events.json").is_file():
        return StreamingResponse(_replay(sdir / "events.json"), media_type="text/event-stream")
    raise HTTPException(status_code=404, detail="no events")


async def _tail(path: Path):
    """Emit existing + newly-appended events; stop on session_end or long idle."""
    sent, idle = 0, 0
    while True:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            lines = []
        if len(lines) > sent:
            idle = 0
            for line in lines[sent:]:
                sent += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield f"data: {json.dumps(ev)}\n\n"
                if ev.get("type") == "session_end":
                    yield "event: end\ndata: {}\n\n"
                    return
        else:
            idle += 1
            if idle > 400:        # ~120s with no new events and no session_end
                yield "event: end\ndata: {}\n\n"
                return
        await asyncio.sleep(0.3)


async def _replay(path: Path):
    try:
        events = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        events = []
    for e in events:
        yield f"data: {json.dumps(e)}\n\n"
        await asyncio.sleep(0.2)
    yield "event: end\ndata: {}\n\n"


@app.get("/")
def index():
    return HTMLResponse((Path(__file__).parent / "index.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8900)
