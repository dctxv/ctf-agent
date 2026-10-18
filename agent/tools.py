import os, re, json, subprocess
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv()

WORKSPACE_HOST = os.environ.get("WORKSPACE_HOST", r"C:\ctf\workspace")
CONTAINER = os.environ.get("AGENT_CONTAINER", "agent-box")

# ---------------- allowlist enforcement ----------------

def extract_hosts(text: str) -> set:
    """Best-effort extraction of hosts a command will touch."""
    hosts = set()
    for m in re.finditer(r'https?://([A-Za-z0-9.\-]+)(?::\d+)?', text):
        hosts.add(m.group(1).lower())
    for m in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        hosts.add(m.group(0))
    return hosts

def host_allowed(host: str, allowed: list) -> bool:
    host = host.lower().strip('.')
    for pat in allowed:
        pat = pat.lower()
        if pat.startswith('*.'):
            if host.endswith(pat[1:]) or host == pat[2:]:
                return True
        elif host == pat:
            return True
    return False

# ---------------- output truncation (protects context & cost) ----------------

def _truncate(s: str, limit=8000) -> str:
    if s is None:
        return ""
    if len(s) <= limit:
        return s
    return (s[: int(limit * 0.6)] +
            f"\n...[truncated {len(s) - limit} chars]...\n" +
            s[-int(limit * 0.4):])

# ---------------- path normalization ----------------
# PATCH v1.2 (Bug B): The model reasons about paths as they appear INSIDE the
# container ("/workspace/poc1.py"), but our file tools treat paths as relative
# to the workspace root. Result last session: files landed in
# /workspace/workspace/ and the model had to mv them out. Now both mental
# models are accepted: "/workspace/reports/x.md", "reports/x.md", and
# "/reports/x.md" all resolve to the same place.

def _normalize(path: str) -> str:
    p = (path or "").lstrip('/\\')
    # also strip a windows-style leading slash pair if doubled
    while p.startswith('workspace/') or p.startswith('workspace\\'):
        p = p[len('workspace/'):] if p.startswith('workspace/') else p[len('workspace\\'):]
    return p or "."

# ---------------- tool implementations ----------------

def run_command(command: str, engagement: dict) -> str:
    hosts = extract_hosts(command)
    bad = [h for h in hosts if not host_allowed(h, engagement["allowed_hosts"])]
    if bad:
        return (f"ALLOWLIST BLOCKED this command: out-of-scope host(s) {bad}. "
                f"Scope: {engagement['allowed_hosts']}. "
                f"Stay in scope or use ask_human.")

    try:
        # PATCH v1.2 (Bug A): the old `text=True` decoded subprocess output with
        # Windows cp1252, which CRASHES on UTF-8 tool output (emojis in Juice
        # Shop responses killed the reader thread last session). Now we decode
        # as UTF-8 with replacement, and force a UTF-8 locale inside the
        # container so tools emit UTF-8 in the first place.
        r = subprocess.run(
            ["docker", "exec", "-e", "LANG=C.UTF-8", CONTAINER, "bash", "-lc", command],
            capture_output=True, timeout=engagement.get("cmd_timeout_s", 180),
            encoding="utf-8", errors="replace",
        )
        out = (f"(exit={r.returncode})\n"
               f"--- stdout ---\n{_truncate(r.stdout)}\n"
               f"--- stderr ---\n{_truncate(r.stderr)}")
        return out
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {engagement.get('cmd_timeout_s', 180)}s — command may still be running."

def read_file(path: str) -> str:
    p = (Path(WORKSPACE_HOST) / _normalize(path)).resolve()   # v1.2
    if WORKSPACE_HOST not in str(p):
        return "ERROR: path escapes workspace."
    if not p.exists():
        return f"ERROR: {p.name} not found. Use list_files to see what exists."
    return _truncate(p.read_text(errors='replace'))

def write_file(path: str, content: str) -> str:
    p = (Path(WORKSPACE_HOST) / _normalize(path)).resolve()   # v1.2
    if WORKSPACE_HOST not in str(p):
        return "ERROR: path escapes workspace."
    p.parent.mkdir(parents=True, exist_ok=True)
    # v1.1 patch: never translate line endings to CRLF on Windows —
    # model-written Linux scripts MUST stay LF or bash breaks.
    p.write_text(content, encoding='utf-8', newline='\n')
    # v1.1 patch: chmod the FULL relative path so files in subdirectories work
    rel = p.relative_to(Path(WORKSPACE_HOST)).as_posix()
    subprocess.run(["docker", "exec", CONTAINER, "chmod", "+x", f"/workspace/{rel}"],
                   capture_output=True)
    return f"Wrote {rel} ({len(content)} chars). Runs in container at /workspace/{rel}"

def list_files(path: str = ".") -> str:
    p = (Path(WORKSPACE_HOST) / _normalize(path or ".")).resolve()   # v1.2
    if WORKSPACE_HOST not in str(p) or not p.exists():
        return "ERROR: bad path."
    items = []
    for f in sorted(p.rglob('*'))[:200]:
        rel = f.relative_to(WORKSPACE_HOST)
        items.append(f"{'DIR ' if f.is_dir() else 'FILE'} {rel}")
    return "\n".join(items) or "(empty)"

def web_search(query: str) -> str:
    key = os.environ.get("TAVILY_API_KEY")
    if not key:
        return "web_search unavailable: set TAVILY_API_KEY in .env"
    try:
        r = requests.post("https://api.tavily.com/search", json={
            "api_key": key, "query": query, "max_results": 5, "search_depth": "basic"
        }, timeout=30)
        results = r.json().get("results", [])
        if not results:
            return "No results found."
        return "\n\n".join(
            f"[{i+1}] {x.get('title','')}\nURL: {x.get('url','')}\n{x.get('content','')[:500]}"
            for i, x in enumerate(results))
    except Exception as e:
        return f"web_search error: {e}"

# ---------------- tool schemas (STAYS BYTE-IDENTICAL across calls -> caching) ----------------

TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "run_command",
        "description": "Run a shell command inside the Linux toolbox container. "
                       "Only in-scope hosts are permitted. nmap/ffuf/nuclei/sqlmap/pwntools available.",
        "parameters": {"type": "object",
            "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "read_file", "description": "Read a file from the shared workspace. Paths are workspace-relative ('pocs/x.py') or '/workspace/pocs/x.py' — both work.",
        "parameters": {"type": "object",
            "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "write_file", "description": "Write a file (e.g. exploit PoCs) to the shared workspace. Paths are workspace-relative ('pocs/x.py') or '/workspace/pocs/x.py' — both work. Use LF line endings.",
        "parameters": {"type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "list_files", "description": "List files in the shared workspace.",
        "parameters": {"type": "object",
            "properties": {"path": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "web_search",
        "description": "Search the web (CVEs, PoCs, writeups, documentation).",
        "parameters": {"type": "object",
            "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "ask_human",
        "description": "Ask the human operator a question. Use when stuck, unsure, "
                       "or when an action needs approval.",
        "parameters": {"type": "object",
            "properties": {"question": {"type": "string"}}, "required": ["question"]}}},
    {"type": "function", "function": {
        "name": "finish",
        "description": "End the session. Call when the goal is met or progress is impossible.",
        "parameters": {"type": "object",
            "properties": {"summary": {"type": "string", "description": "What was done + findings + what was learned"}},
            "required": ["summary"]}}},
]

def execute_tool(name: str, args: dict, engagement: dict, human_input_fn) -> str:
    if name == "run_command":
        return run_command(args["command"], engagement)
    if name == "read_file":
        return read_file(args["path"])
    if name == "write_file":
        return write_file(args["path"], args["content"])
    if name == "list_files":
        return list_files(args.get("path", "."))
    if name == "web_search":
        return web_search(args["query"])
    if name == "ask_human":
        return human_input_fn(args["question"])
    if name == "finish":
        return args["summary"]
    return f"Unknown tool {name}"
