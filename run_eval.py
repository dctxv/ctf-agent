import argparse, csv, json, os, re, statistics, subprocess, sys, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

from agent.agent import AgentSession, MODELS

load_dotenv()

ROOT = Path(__file__).parent
CHALLENGES_DIR = ROOT / "challenges"
RESULTS_CSV = ROOT / "results.csv"

# Pinned so a mid-study upstream change cannot masquerade as a regression.
JUICE_IMAGE = "bkimminich/juice-shop@sha256:42843723a7bf4246aa5d63c324978b17ef296ac78434aeddd34c427bfb5853f4"

FIELDS = ["timestamp_utc", "git_sha", "model", "challenge", "run_index",
          "solved", "finished_naturally", "steps", "cost_usd",
          "escalations", "ask_human", "budget_hits", "duration_s", "error"]


def git_sha():
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else "nogit"
    except Exception:
        return "nogit"


def check_evidence(ev, ws):
    # A solve needs a real artifact: present, non-empty, and matching the
    # challenge assertion. A "could not do it" file must never score.
    if not ev or ev.get("type") != "file_exists":
        return False
    p = ws / ev["path"]
    if not p.exists() or p.stat().st_size == 0:
        return False
    content = p.read_text(errors="replace")
    if not content.strip():
        return False
    if "contains" in ev and ev["contains"] not in content:
        return False
    if "matches" in ev:
        try:
            if not re.search(ev["matches"], content):
                return False
        except re.error:
            print(f"   WARN invalid evidence regex {ev['matches']!r}; counting unsolved")
            return False
    return True


def reset_juice():
    r = subprocess.run(["docker", "rm", "-f", "juice"], capture_output=True, text=True)
    if r.returncode != 0 and "No such container" not in (r.stderr or ""):
        print(f"   WARN docker rm: {r.stderr.strip()}")
    time.sleep(1.5)  # let the published port release before re-binding
    r = subprocess.run(["docker", "run", "--rm", "-d", "-p", "3000:3000",
                        "--name", "juice", JUICE_IMAGE], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"docker run failed: {(r.stderr or '').strip()}")
    # The SPA answers before the DB is seeded; poll a route that returns seeded
    # rows, then settle.
    print("   waiting for seed", end="", flush=True)
    for _ in range(90):
        try:
            resp = requests.get("http://localhost:3000/api/Products", timeout=3)
            if resp.status_code == 200 and len(resp.text) > 3000:
                time.sleep(2.0)
                print(" up")
                return
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(2)
    raise RuntimeError("Juice Shop never finished seeding (180s)")


def run_once(cfg, ws, run_idx, sha):
    ev = cfg.get("evidence", {})
    if ev.get("type") == "file_exists":
        target = ws / ev["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.unlink()
    reset_juice()

    human_calls = {"n": 0}

    def auto_human(question):
        human_calls["n"] += 1
        print(f"   [ask_human #{human_calls['n']}] {question[:120]}")
        return ("Automated eval run; the operator is not answering live. Continue within "
                "scope using your best judgment. Evidence files must contain the actual "
                "result data, never a statement that you failed. If you truly cannot "
                "proceed without a human, call finish and explain in the summary.")

    t0 = time.time()
    session, error = None, ""
    try:
        session = AgentSession(cfg, auto_human, run_index=run_idx)
        session.run()
    except Exception as e:
        error = f"{type(e).__name__}: {e}"[:200]
        print(f"   SESSION CRASHED: {error}")

    if session is None:
        counts, steps, cost, finished = Counter(), 0, 0.0, False
    else:
        counts = Counter(e["type"] for e in session.events)
        steps, cost, finished = session.steps, session.cost_usd, session.finished

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_sha": sha,
        "model": MODELS["loop"],
        "challenge": cfg["engagement_name"],
        "run_index": run_idx,
        "solved": check_evidence(ev, ws),
        "finished_naturally": finished,
        "steps": steps,
        "cost_usd": round(cost, 4),
        "escalations": counts.get("escalation", 0),
        "ask_human": counts.get("ask_human", 0),
        "budget_hits": counts.get("budget_hit", 0),
        "duration_s": round(time.time() - t0),
        "error": error,
    }


def append_row(row):
    new = not RESULTS_CSV.exists()
    with open(RESULTS_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)


def summarize(rows):
    n = len(rows)
    solved = sum(r["solved"] for r in rows)

    def ms(key):
        vals = [r[key] for r in rows]
        return statistics.mean(vals), (statistics.stdev(vals) if n > 1 else 0.0)

    cm, cs = ms("cost_usd")
    sm, ss = ms("steps")
    crashed = sum(1 for r in rows if r["error"])
    print(f"   SUMMARY: solved {solved}/{n} | crashed {crashed} | "
          f"cost ${cm:.4f}+/-{cs:.4f} | steps {sm:.1f}+/-{ss:.1f}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1,
                    help="repetitions per challenge (use 3 for a baseline)")
    ap.add_argument("only", nargs="*", help="substring filters on challenge filenames")
    args = ap.parse_args()

    if not os.getenv("DEEPSEEK_API_KEY"):
        sys.exit("DEEPSEEK_API_KEY missing; is .env present?")

    if "PASTE" in JUICE_IMAGE:
        print("WARN: Juice Shop image is not pinned; baselines will not be reproducible")
    else:
        r = subprocess.run(["docker", "image", "inspect", JUICE_IMAGE], capture_output=True)
        if r.returncode != 0:
            sys.exit(f"Pinned image not local; run: docker pull {JUICE_IMAGE}")

    sha = git_sha()
    files = sorted(CHALLENGES_DIR.glob("*.json"))
    if args.only:
        files = [f for f in files if any(o in f.name for o in args.only)]
    if not files:
        sys.exit(f"No challenge configs matched in {CHALLENGES_DIR}")

    print(f"EVAL | git {sha} | model {MODELS['loop']} | runs/challenge={args.runs}")
    for f in files:
        cfg = json.loads(f.read_text())
        ws = Path(cfg["workspace"])  # single source of truth for the workspace path
        if not ws.is_dir():
            print(f"SKIP {f.name}: workspace does not exist: {ws}")
            continue
        print(f"\n=== {cfg['engagement_name']} (x{args.runs}) ===")
        rows = []
        for run_idx in range(1, args.runs + 1):
            row = run_once(cfg, ws, run_idx, sha)
            append_row(row)
            rows.append(row)
            print(f"   run {run_idx:02d}: solved={row['solved']} "
                  f"finish={row['finished_naturally']} steps={row['steps']} "
                  f"cost=${row['cost_usd']} esc={row['escalations']} "
                  f"ask={row['ask_human']} {row['duration_s']}s"
                  + (f" ERR={row['error']}" if row["error"] else ""))
        summarize(rows)
    print("\nDone. results.csv updated.")
