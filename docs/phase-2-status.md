# Phase 2 - status archive

Snapshot of Phase 2 (browser interaction + platform integration) at the point we
moved on to Phase 2.5. All code committed locally on `master`, ahead of `origin`.

## Done

| Area | Detail | Commit |
|---|---|---|
| Browser tools | Headless Chromium (Playwright) in agent-box: `browser_open`, `browser_interact` (fill/click/press/wait/goto, optional force), `browser_screenshot`. Every URL scope-checked against the allowlist, same as `run_command`. Renders JS SPAs curl can't. Live-verified vs Juice Shop (product list, hidden score-board, login flow, PNG). | `8fcc23c` |
| Toolbox image | Dockerfile installs Playwright + Chromium (`--with-deps`, confirmed on Kali). | `8fcc23c` |
| CTFd adapter | `agent/adapters.py`: `PlatformAdapter` base + `CTFdAdapter` (list / get / `build_engagement` / `download_files` / `submit_flag`) over the CTFd v1 REST API. Scope is operator-controlled (empty by default = nothing runnable); hosts parsed from challenge text are `_suggested_hosts` for review only. Token from `CTFD_TOKEN` env. | `a336401` |
| CTFd validation | 12/12 vs a faithful mock; 7/7 vs a throwaway real CTFd 3.7.7 (token auth, endpoints, response shapes, flag submission all match). | - |
| Runner | `run_ctfd.py`: `--list`, `--dry-run`, optional `--submit`; builds the engagement from a CTFd challenge. | `45d785c` |
| Regression tooling | `compare_runs.py`: per-challenge diff of two eval runs by git SHA, flags solve/step/cost regressions. | `e7aab38` |
| Regression check | 1x suite at `a336401`: 9/10 solved (same as baseline), 0 crashes, ~$0.33, no systematic slowdown from the new tools. | `c4b4cfb` |

## Not done (deferred)

- **Live CTFd run** against a real operator instance - needs instance URL, challenge id(s), authorized target scope, and `CTFD_TOKEN` in `.env`. (Adapter proven against mock + local real CTFd; only the operator's own instance is untested.)
- **picoCTF adapter** - `play.picoctf.org` uses a different API/auth than standard CTFd; needs its own adapter.
- **HTB adapter** - VPN + machine IP model; needs an authorized machine/IP from the operator.
- **PortSwigger adapter** - per-lab URLs tied to the operator's account.
- **Allowlist auto-population from spawned machine IPs** - safety-sensitive (touches scope enforcement); to be designed with the operator so it never widens scope from untrusted data.
- **Headed / supervised browser mode** - needs a display (xvfb/VNC) in the container; really belongs with the Phase 4 dashboard.
- **Browser profile reset per eval run** - eval-cleanliness nicety; only matters once browser-based challenges exist.

## Open operator actions (not code)

- **Rotate the DeepSeek and Tavily API keys** - they were in `.env` on the private remote before the history scrub; rotation is the only real fix.
- **Push** the Phase-2 commits (`8fcc23c` -> `c4b4cfb`) to origin - currently local only.
