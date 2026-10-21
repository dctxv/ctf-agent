"""Schema-versioned structured result store (SQLite), with legacy CSV export.

Every trial row carries full provenance (challenge version, agent commit, model
id and config, policy, prompt version, env digest, memory snapshot, verifier
version) so any result is reproducible and traceable. The store is also the
checkpoint: a trial is recorded the moment it finishes, so an interrupted
experiment resumes by skipping rows already present.

results.csv is kept as an export view in the original 14-column format so
compare_runs.py and existing tooling keep working.
"""
import csv
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1

_FIELDS = [
    "experiment_id", "ts_utc", "challenge_id", "challenge_version", "dataset",
    "tier", "category", "config_name", "run_index", "outcome", "failure_reason",
    "detail", "steps", "cost_usd", "tokens_in", "tokens_out", "duration_s",
    "escalations", "ask_human", "budget_hits", "finished_naturally",
    "agent_commit", "model", "model_config", "policy", "prompt_version",
    "env_digest", "memory_snapshot", "verifier_version", "container", "workspace",
]

# legacy results.csv header (unchanged, for compare_runs.py)
_LEGACY = ["timestamp_utc", "git_sha", "model", "challenge", "run_index", "solved",
           "finished_naturally", "steps", "cost_usd", "escalations", "ask_human",
           "budget_hits", "duration_s", "error"]


class Store:
    def __init__(self, path="eval/results.sqlite"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        cols = ",\n  ".join(f"{c} TEXT" for c in _FIELDS)
        self.db.executescript(
            f"CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);\n"
            f"CREATE TABLE IF NOT EXISTS trials (\n"
            f"  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  {cols}\n);")
        self.db.execute("INSERT OR IGNORE INTO meta(k, v) VALUES('schema_version', ?)",
                        (str(SCHEMA_VERSION),))
        self.db.commit()

    def record(self, row: dict):
        r = dict(row)
        r.setdefault("ts_utc", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        if isinstance(r.get("model_config"), (dict, list)):
            r["model_config"] = json.dumps(r["model_config"], default=str)
        vals = [None if r.get(c) is None else str(r.get(c)) for c in _FIELDS]
        ph = ",".join("?" for _ in _FIELDS)
        self.db.execute(f"INSERT INTO trials ({','.join(_FIELDS)}) VALUES ({ph})", vals)
        self.db.commit()

    def completed(self, experiment_id):
        """Set of (config_name, challenge_id, run_index) already recorded for an
        experiment, excluding infra errors (which should be retried)."""
        cur = self.db.execute(
            "SELECT config_name, challenge_id, run_index, outcome FROM trials "
            "WHERE experiment_id = ?", (experiment_id,))
        done = set()
        for row in cur.fetchall():
            if row["outcome"] == "infra_error":
                continue
            done.add((row["config_name"], row["challenge_id"], str(row["run_index"])))
        return done

    def all_rows(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM trials ORDER BY id").fetchall()]

    def export_csv(self, path="results.csv", experiment_id=None):
        q = "SELECT * FROM trials"
        args = ()
        if experiment_id:
            q += " WHERE experiment_id = ?"
            args = (experiment_id,)
        q += " ORDER BY id"
        rows = self.db.execute(q, args).fetchall()
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=_LEGACY)
            w.writeheader()
            for r in rows:
                fn = (r["finished_naturally"] or "")
                w.writerow({
                    "timestamp_utc": r["ts_utc"],
                    "git_sha": r["agent_commit"] or "nogit",
                    "model": r["model"] or "",
                    "challenge": r["challenge_id"],
                    "run_index": r["run_index"],
                    "solved": r["outcome"] == "verified_success",
                    "finished_naturally": fn in ("1", "True", "true"),
                    "steps": r["steps"] or 0,
                    "cost_usd": r["cost_usd"] or 0,
                    "escalations": r["escalations"] or 0,
                    "ask_human": r["ask_human"] or 0,
                    "budget_hits": r["budget_hits"] or 0,
                    "duration_s": r["duration_s"] or 0,
                    "error": (r["detail"] or "")[:200],
                })
        return path

    def close(self):
        self.db.close()
