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
        r = requests.post("https://api.tavily.com/search",
            headers={"Authorization": f"Bearer {key}"},
            json={"query": query, "max_results": 5, "search_depth": "basic"},
            timeout=30)
        # Surface auth/quota/server failures instead of masking them as "No results".
        # A 401 here almost always means TAVILY_API_KEY is bad/expired.
        if r.status_code != 200:
            body = r.text.strip().replace("\n", " ")[:200]
            return f"web_search error: HTTP {r.status_code} {body}"
        results = r.json().get("results", [])
        if not results:
            return "No results found."
        return "\n\n".join(
            f"[{i+1}] {x.get('title','')}\nURL: {x.get('url','')}\n{x.get('content','')[:500]}"
            for i, x in enumerate(results))
    except Exception as e:
        return f"web_search error: {e}"

# ---------------- browser tools (Phase 2: headless Chromium in the toolbox) ----------------
# Playwright-driven Chromium runs INSIDE agent-box, the same cage and network
# view as run_command (the target is http://host.docker.internal:3000 there).
# Every URL is scope-checked against the engagement allowlist, exactly like
# run_command. The driver source lives in browser_driver.py and is piped into
# the container's python3 on each call; the command travels as argv.

_BROWSER_DRIVER = (Path(__file__).parent / "browser_driver.py").read_text(encoding="utf-8")


def _scope_check_url(url: str, engagement: dict):
    hosts = extract_hosts(url or "")
    if not hosts:
        return "BLOCKED: no host parsed from URL. Pass a full http(s):// URL."
    bad = [h for h in hosts if not host_allowed(h, engagement["allowed_hosts"])]
    if bad:
        return (f"ALLOWLIST BLOCKED: out-of-scope host(s) {bad}. "
                f"Scope: {engagement['allowed_hosts']}. Stay in scope or use ask_human.")
    return None


def _format_browser(d: dict) -> str:
    lines = [f"HTTP {d.get('status')} | {d.get('title','')}", f"URL: {d.get('url','')}"]
    if d.get("screenshot"):
        lines.append(f"screenshot saved: {d['screenshot']}")
    lines.append("\n--- visible text ---\n" + (d.get("text") or ""))
    if d.get("inputs"):
        lines.append("\n--- inputs ---\n" + "\n".join(
            f"[{i}] name={x.get('name')} type={x.get('type')} placeholder={x.get('placeholder')}"
            for i, x in enumerate(d["inputs"])))
    btns = [b for b in (d.get("buttons") or []) if b]
    if btns:
        lines.append("\n--- buttons ---\n" + "\n".join(f"[{i}] {b}" for i, b in enumerate(btns)))
    if d.get("links"):
        lines.append("\n--- links (first 40) ---\n" + "\n".join(
            f"{l.get('text','')} -> {l.get('href','')}" for l in d["links"]))
    return _truncate("\n".join(lines), 9000)


def _run_browser(cmd: dict, engagement: dict) -> str:
    urls = [cmd.get("url", "")] + [s.get("url", "") for s in cmd.get("actions", [])
                                   if s.get("action") == "goto"]
    for u in urls:
        if not u:
            continue
        blocked = _scope_check_url(u, engagement)
        if blocked:
            return blocked
    try:
        r = subprocess.run(
            ["docker", "exec", "-i", "-e", "LANG=C.UTF-8", CONTAINER, "python3", "-", json.dumps(cmd)],
            input=_BROWSER_DRIVER, capture_output=True,
            encoding="utf-8", errors="replace",
            timeout=engagement.get("browser_timeout_s", 90),
        )
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: browser action exceeded {engagement.get('browser_timeout_s', 90)}s."
    if r.returncode != 0:
        return f"browser error (exit={r.returncode}):\n{_truncate(r.stderr or r.stdout, 1500)}"
    try:
        data = json.loads((r.stdout or "").strip().splitlines()[-1])
    except Exception:
        return f"browser error: could not parse driver output:\n{_truncate(r.stdout, 1500)}"
    if not data.get("ok"):
        return f"browser error: {data.get('error', 'unknown')}"
    return _format_browser(data)


def browser_open(url: str, engagement: dict) -> str:
    return _run_browser({"url": url}, engagement)


def browser_interact(url: str, actions: list, engagement: dict) -> str:
    return _run_browser({"url": url, "actions": actions or []}, engagement)


def browser_screenshot(url: str, path: str, engagement: dict) -> str:
    rel = _normalize(path or "screenshot.png")
    return _run_browser({"url": url, "screenshot": f"/workspace/{rel}"}, engagement)

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
        "name": "browser_open",
        "description": "Open a URL in a headless Chromium browser (renders JavaScript, unlike curl) "
                       "and return the rendered page: title, visible text, and the links, buttons and "
                       "inputs on it. Use for SPAs/JS-heavy apps. Only in-scope hosts are permitted.",
        "parameters": {"type": "object",
            "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "browser_interact",
        "description": "Open a URL then run a sequence of browser actions (fill forms, click, press keys), "
                       "returning the resulting rendered page. Cookies/login persist across calls. "
                       "Only in-scope hosts are permitted.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"},
            "actions": {"type": "array", "items": {"type": "object", "properties": {
                "action": {"type": "string", "enum": ["click", "fill", "press", "wait", "goto"]},
                "selector": {"type": "string", "description": "CSS selector (click/fill)"},
                "value": {"type": "string", "description": "text to fill"},
                "key": {"type": "string", "description": "key to press, e.g. Enter"},
                "ms": {"type": "integer", "description": "wait milliseconds"},
                "url": {"type": "string", "description": "navigate (goto)"},
                "force": {"type": "boolean", "description": "force a click past overlays/animations"}},
                "required": ["action"]}}},
            "required": ["url", "actions"]}}},
    {"type": "function", "function": {
        "name": "browser_screenshot",
        "description": "Open a URL in headless Chromium and save a PNG screenshot to the workspace. "
                       "Only in-scope hosts are permitted.",
        "parameters": {"type": "object",
            "properties": {"url": {"type": "string"},
                           "path": {"type": "string", "description": "workspace-relative output path, e.g. 'shots/home.png'"}},
            "required": ["url", "path"]}}},
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
    if name == "browser_open":
        return browser_open(args["url"], engagement)
    if name == "browser_interact":
        return browser_interact(args["url"], args.get("actions", []), engagement)
    if name == "browser_screenshot":
        return browser_screenshot(args["url"], args.get("path", "screenshot.png"), engagement)
    if name == "ask_human":
        return human_input_fn(args["question"])
    if name == "finish":
        return args["summary"]
    return f"Unknown tool {name}"
