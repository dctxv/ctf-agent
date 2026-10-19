#!/usr/bin/env python3
"""
c04-find-scoreboard: verify the hidden Score Board SPA route on OWASP Juice Shop.

How the URL was found
---------------------
1. Pulled the Angular bundle (main.js) from the target.
2. Grepped the route table for `path:` entries -> found {path:`score-board`,component:f0}.
3. Confirmed the router is configured with hash routing (`useHash:!0`),
   so the client-side URL is /#/score-board.
4. This script renders the page in headless Chromium to prove the route
   resolves to the real Score Board component (no login needed) and that it
   is NOT referenced by any link in the normal UI.
"""
import json
import sys

from playwright.sync_api import sync_playwright

BASE = "http://host.docker.internal:3000"
CANDIDATE = BASE + "/#/score-board"
OUT_PNG = "/workspace/evidence/c4_scoreboard_page.png"


def main() -> int:
    result = {"candidate_url": CANDIDATE}
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        page = browser.new_page(viewport={"width": 1280, "height": 1400})

        # --- 1. Baseline: does the landing page link to the score board at all? ---
        page.goto(BASE + "/", wait_until="networkidle", timeout=60000)
        hrefs = page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))"
        )
        result["root_page_link_count"] = len(hrefs)
        result["root_page_mentions_scoreboard"] = any(
            "score" in (h or "").lower() for h in hrefs
        )
        result["root_page_links_sample"] = hrefs[:15]

        # --- 2. Navigate straight to the hidden route ---
        resp = page.goto(CANDIDATE, wait_until="networkidle", timeout=60000)
        result["http_status"] = resp.status if resp else None
        page.wait_for_timeout(3000)

        result["final_url"] = page.url
        body_text = page.inner_text("body")
        result["body_has_score_board_strings"] = {
            "Score Board": "Score Board" in body_text,
            "Difficulty": "Difficulty" in body_text,
            "Challenge": "Challenge" in body_text,
        }
        # The score board renders one row per challenge; count them.
        result["scoreboard_row_count"] = page.eval_on_selector_all(
            ".score-row", "els => els.length"
        )
        result["page_title"] = page.title()
        result["body_snippet"] = " | ".join(
            [l.strip() for l in body_text.splitlines() if l.strip()][:25]
        )

        page.screenshot(path=OUT_PNG, full_page=True)
        browser.close()

    print(json.dumps(result, indent=2))
    ok = (
        result["body_has_score_board_strings"]["Score Board"]
        and result["scoreboard_row_count"] > 0
        and result["final_url"].endswith("/#/score-board")
    )
    print("\nVERDICT:", "SUCCESS - hidden Score Board route renders" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
