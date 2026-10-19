"""Playwright browser driver. Runs INSIDE the agent-box container.

Invoked by agent/tools.py as:  docker exec -i agent-box python3 - '<json-cmd>'
(the driver source is piped on stdin, the command is argv[1]).

Command JSON:
  {"url": "...",                      # required, first navigation
   "actions": [                       # optional, run in order
       {"action": "click",  "selector": "css"},
       {"action": "fill",   "selector": "css", "value": "text"},
       {"action": "press",  "key": "Enter"},
       {"action": "wait",   "ms": 1000},
       {"action": "goto",   "url": "http://..."}],
   "screenshot": "/workspace/x.png"}  # optional

Scope is checked by the caller BEFORE this runs; this file only drives the
browser. A persistent profile keeps cookies/login across calls within a
container's life.
"""
import sys
import json

from playwright.sync_api import sync_playwright

PROFILE_DIR = "/tmp/.bprofile"


def trim(s, n):
    s = s or ""
    return s if len(s) <= n else s[:n] + "...[truncated]"


def extract(page):
    links = [{"text": trim((e.inner_text() or "").strip(), 60),
              "href": e.get_attribute("href")}
             for e in page.query_selector_all("a[href]")[:40]]
    buttons = [trim((e.inner_text() or "").strip(), 60)
               for e in page.query_selector_all("button")[:40]]
    inputs = [{"name": e.get_attribute("name"),
               "type": e.get_attribute("type"),
               "placeholder": e.get_attribute("placeholder")}
              for e in page.query_selector_all("input, textarea, select")[:40]]
    return {"title": page.title(), "url": page.url,
            "text": trim(page.inner_text("body"), 6000),
            "links": links, "buttons": buttons, "inputs": inputs}


def main():
    cmd = json.loads(sys.argv[1])
    out = {"ok": False}
    try:
        with sync_playwright() as p:
            ctx = p.chromium.launch_persistent_context(
                PROFILE_DIR, headless=True, args=["--no-sandbox"])
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            resp = page.goto(cmd["url"], wait_until="domcontentloaded", timeout=30000)
            status = resp.status if resp else None
            if cmd.get("actions"):
                page.wait_for_timeout(1000)  # let the SPA render/animate before interacting
            for step in cmd.get("actions", []):
                act = step.get("action")
                if act == "click":
                    page.click(step["selector"], timeout=10000,
                               force=bool(step.get("force", False)))
                elif act == "fill":
                    page.fill(step["selector"], step.get("value", ""), timeout=10000)
                elif act == "press":
                    page.keyboard.press(step["key"])
                elif act == "wait":
                    page.wait_for_timeout(min(int(step.get("ms", 1000)), 10000))
                elif act == "goto":
                    r2 = page.goto(step["url"], wait_until="domcontentloaded", timeout=30000)
                    status = r2.status if r2 else status
            page.wait_for_timeout(1200)  # let SPA settle / actions take effect
            shot = cmd.get("screenshot")
            if shot:
                page.screenshot(path=shot, full_page=False)
            out = extract(page)
            out.update({"ok": True, "status": status})
            if shot:
                out["screenshot"] = shot
            ctx.close()
    except Exception as e:
        out = {"ok": False, "error": str(e)[:300]}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
