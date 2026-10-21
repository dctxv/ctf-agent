"""Bug-bounty scope mode: turn a program's structured scope into a PROPOSED
engagement. The in-scope assets become the proposed allowed_hosts, but the
engagement is written to a config file for the operator to review and launch
manually - scope is never auto-applied and the agent is never auto-started here
(the allowlist stays operator-controlled).
"""
import re

import requests

_DOMAIN = re.compile(r'^(\*\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
_IP = re.compile(r'^(\*\.)?(\d{1,3}\.){3}\d{1,3}')


def _host_from(ident):
    ident = (ident or "").strip()
    m = re.match(r'^https?://([^/]+)', ident)
    if m:
        ident = m.group(1)
    return ident.split('/')[0].strip()


def parse_scope(items):
    """Split structured-scope items into in-scope hosts, out-of-scope, and
    non-host assets. Accepts HackerOne-shaped items ({attributes:{...}}) or flat dicts."""
    in_scope, out_scope, other = [], [], []
    for it in items:
        attrs = it.get("attributes", it) if isinstance(it, dict) else {}
        atype = str(attrs.get("asset_type", "")).upper()
        ident = attrs.get("asset_identifier", "")
        eligible = attrs.get("eligible_for_submission", attrs.get("eligible", True))
        host = _host_from(ident)
        is_host = (atype in ("URL", "DOMAIN", "WILDCARD", "CIDR", "IP_ADDRESS")
                   or bool(_DOMAIN.match(host or "")) or bool(_IP.match(host or "")))
        entry = {"identifier": ident, "type": atype, "host": host}
        if not eligible:
            out_scope.append(entry)
        elif is_host and host:
            in_scope.append(host)
        else:
            other.append(entry)
    seen = set()
    hosts = [h for h in in_scope if not (h in seen or seen.add(h))]
    return {"in_scope_hosts": hosts, "out_of_scope": out_scope, "other_assets": other}


def wildcard_overlaps(in_scope_hosts, out_of_scope_hosts):
    """Out-of-scope hosts that fall UNDER an in-scope wildcard (so a wildcard
    allowlist entry would wrongly permit them). The operator must narrow scope."""
    from agent.tools import host_allowed
    wilds = [h for h in in_scope_hosts if h.startswith("*.")]
    return [h for h in out_of_scope_hosts if h and host_allowed(h, wilds)]


def build_engagement_proposal(program, scope, *, workspace=".", goal=None):
    hosts = scope["in_scope_hosts"]
    return {
        "engagement_name": f"bb-{re.sub(r'[^a-z0-9]+', '-', program.lower()).strip('-') or 'program'}",
        "targets": f"Bug-bounty program '{program}'. In-scope: {', '.join(hosts) or '(none parsed)'}.",
        "allowed_hosts": hosts,  # PROPOSED - the operator must review before running
        "goal": goal or (f"Authorized bug-bounty recon and testing of the in-scope assets for "
                         f"'{program}'. Stay strictly within scope; ask the human before any "
                         f"destructive action."),
        "workspace": str(workspace),
        "max_steps": 40, "max_cost_usd": 1.0, "cmd_timeout_s": 180,
        "_bugbounty": {
            "program": program,
            "out_of_scope": [e["host"] for e in scope["out_of_scope"] if e["host"]],
            "other_assets": [e["identifier"] for e in scope["other_assets"]],
        },
    }


def fetch_hackerone_scope(handle, username, token):
    """HackerOne structured scopes (needs API creds: H1_API_USERNAME + H1_API_TOKEN)."""
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"
    r = requests.get(url, auth=(username, token), headers={"Accept": "application/json"}, timeout=30)
    r.raise_for_status()
    return r.json().get("data", [])
