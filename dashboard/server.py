"""Phase 4 dashboard backend (FastAPI).

Live sessions: the agent appends each event to <session>/events.jsonl as it runs,
and /stream TAILS that file in real time. Finished/old sessions without a live log
fall back to replaying events.json. Read-only over workspace/sessions/.

Run:  python dashboard/server.py      (or: uvicorn dashboard.server:app --port 8900)
"""
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # so we can import agent.* when run as a script

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from agent import storyboard
from agent.adapters import github_engagement_name
from agent.findings import load_findings
from agent.learn import _events_path
from eval import report as eval_report
from eval import store as eval_store

SESSIONS = (ROOT / "workspace" / "sessions").resolve()
EVAL_STORE = (ROOT / "eval" / "results.sqlite")
DASH_TOKEN = os.environ.get("DASHBOARD_TOKEN", "")

app = FastAPI(title="CTF Agent Dashboard")


@app.middleware("http")
async def _auth(request, call_next):
    # Optional token gate (defense in depth; the server also binds localhost only).
    # Active only when DASHBOARD_TOKEN is set, so the default localhost flow is unchanged.
    if DASH_TOKEN and request.url.path.startswith("/api"):
        tok = request.headers.get("X-Dashboard-Token") or request.query_params.get("token")
        if tok != DASH_TOKEN:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


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


@app.post("/api/github/audit")
async def api_github_audit(req: Request):
    """Launch a file-only audit of a github.com repo (host-side clone + run_audit).
    Returns the session id; progress is on /stream, results on /findings. Localhost
    only, single operator (invariant #5); the URL is validated to github.com/owner/repo."""
    body = await req.json()
    url = (body or {}).get("url", "")
    try:
        max_steps = max(1, min(int((body or {}).get("max_steps", 40)), 80))
    except (TypeError, ValueError):
        max_steps = 40
    try:
        name = github_engagement_name(url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    # clear any prior run of this session so the UI waits for the fresh run,
    # not a stale finished one with the same id.
    old = SESSIONS / name
    for fn in ("events.jsonl", "events.json"):
        try:
            (old / fn).unlink()
        except (FileNotFoundError, OSError):
            pass
    subprocess.Popen(
        [sys.executable, str(ROOT / "run_audit.py"), "--github", url,
         "--unattended", "--max-steps", str(max_steps)],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"session_id": name, "status": "launching"}


@app.get("/api/sessions/{sid:path}/findings")
def api_findings(sid: str):
    events, _ = _read_events(_sdir(sid))
    audit = next((e.get("data", {}).get("_audit") for e in events
                  if e.get("type") == "session_start"), None)
    if not audit or "findings" not in audit:
        return JSONResponse([])
    return JSONResponse(load_findings((ROOT / "workspace" / audit["findings"]).parent))


# ---------------- attack-map storyboard (animated, plain-English replay) ----------------

def _sb_path(sid: str):
    """storyboard.json lives next to events.json (handles run_NN/ subdirs)."""
    try:
        return _events_path(_sdir(sid)).parent / "storyboard.json"
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="no events for this session")


@app.get("/api/sessions/{sid:path}/storyboard")
def api_storyboard(sid: str):
    """Return the cached storyboard if it exists. Does NOT generate (no LLM, no cost)."""
    p = _sb_path(sid)
    if p.is_file():
        return JSONResponse({"generated": True, "storyboard": json.loads(p.read_text(encoding="utf-8"))})
    return JSONResponse({"generated": False})


@app.post("/api/sessions/{sid:path}/storyboard")
async def api_generate_storyboard(sid: str, req: Request):
    """Generate (or force-regenerate) the storyboard. This makes ONE LLM call and
    costs money; it only runs on explicit request. Localhost, single operator."""
    _sb_path(sid)  # validates the session exists
    try:
        body = await req.json()
    except Exception:
        body = {}
    force = bool((body or {}).get("force"))
    try:
        r = storyboard.build_storyboard(_sdir(sid), force=force)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"storyboard generation failed: {e}")
    return {"generated": True, "cached": r["cached"], "cost_usd": r["cost_usd"],
            "storyboard": r["storyboard"]}


@app.get("/api/sessions/{sid:path}/replay")
def api_replay(sid: str, download: int = 0):
    """Self-contained animated player with the storyboard inlined. Iframed by the
    dashboard and saved verbatim as the shareable export (?download=1)."""
    p = _sb_path(sid)
    if not p.is_file():
        raise HTTPException(status_code=404, detail="no storyboard yet - generate it first")
    sb = json.loads(p.read_text(encoding="utf-8"))
    html = storyboard.render_html(sb)
    headers = {}
    if download:
        fname = sid.replace("/", "-").replace("\\", "-") + "-attack-map.html"
        headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    return HTMLResponse(html, headers=headers)


# ---------------- evaluation subsystem views (read-only over eval/results.sqlite) ----------------

def _eval_rows(experiment=""):
    if not EVAL_STORE.exists():
        return []
    st = eval_store.Store(EVAL_STORE)
    try:
        rows = st.all_rows()
    finally:
        st.close()
    return [r for r in rows if (not experiment or r.get("experiment_id") == experiment)]


@app.get("/api/eval/experiments")
def api_eval_experiments():
    by = {}
    for r in _eval_rows():
        e = r.get("experiment_id") or "(none)"
        d = by.setdefault(e, {"experiment_id": e, "trials": 0, "solved": 0,
                              "infra": 0, "last_ts": ""})
        d["trials"] += 1
        if r.get("outcome") == "verified_success":
            d["solved"] += 1
        elif r.get("outcome") == "infra_error":
            d["infra"] += 1
        if (r.get("ts_utc") or "") > d["last_ts"]:
            d["last_ts"] = r.get("ts_utc") or ""
    return sorted(by.values(), key=lambda x: x["last_ts"], reverse=True)


@app.get("/api/eval/report")
def api_eval_report(experiment: str = ""):
    rows = _eval_rows(experiment)
    if not rows:
        return JSONResponse({"empty": True})
    return JSONResponse(eval_report.summarize(rows))


@app.get("/api/eval/regression")
def api_eval_regression(before: str, after: str):
    return JSONResponse(eval_report.regression(_eval_rows(before), _eval_rows(after)))


@app.post("/api/sessions/{sid:path}/control")
async def api_control(sid: str, req: Request):
    """Operator control of a running session: pause | resume | cancel. Writes the
    session's control.json, which the agent loop checks between steps."""
    sdir = _sdir(sid)
    body = await req.json()
    action = (body or {}).get("action", "")
    state = {"pause": "paused", "resume": "running", "cancel": "cancelled"}.get(action)
    if not state:
        raise HTTPException(status_code=400, detail="action must be pause|resume|cancel")
    (sdir / "control.json").write_text(json.dumps({"state": state}), encoding="utf-8")
    return {"session_id": sid, "state": state}


@app.get("/")
def index():
    return HTMLResponse((Path(__file__).parent / "index.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8900)
