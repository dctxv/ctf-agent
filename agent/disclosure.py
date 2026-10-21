"""Responsible-disclosure export: render findings.json into advisory / issue
Markdown, and (only for repos the operator can write to) file GitHub issues.

SAFETY: auto-filing is gated on write access. file_issues() is only reached by
run_disclose.py after repo_access() confirms the authenticated token has
push/admin/maintain on the target repo. Third-party repos are never auto-filed;
they get the advisory Markdown for manual, coordinated disclosure.
"""
import requests

API = "https://api.github.com"
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _hdr(token):
    return {"Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


def _sev(f):
    return str(f.get("severity", "info")).lower()


def _loc(f):
    return f"{f.get('file', '')}{':' + str(f.get('line')) if f.get('line') else ''}"


def render_advisory(findings, repo, title=None) -> str:
    counts = {s: sum(1 for f in findings if _sev(f) == s) for s in _SEV_ORDER}
    cstr = ", ".join(f"{counts[s]} {s}" for s in _SEV_ORDER if counts[s])
    lines = [f"# Security advisory: {repo or 'audited project'}", "",
             "## Summary",
             f"{len(findings)} finding(s) ({cstr or 'none'}) from a static security "
             f"audit of `{repo or 'the source tree'}`.", "",
             "## Overview", "",
             "| # | Severity | Title | Location | CWE |",
             "|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | {_sev(f).upper()} | {f.get('title','')} | "
                     f"`{_loc(f)}` | {f.get('cwe','')} |")
    lines += ["", "## Findings"]
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. {f.get('title','')} - {_sev(f).upper()}",
            f"- **Location:** `{_loc(f)}`",
            f"- **CWE:** {f.get('cwe','n/a')}  **Confidence:** {f.get('confidence','?')}",
            f"- **Description:** {f.get('description','')}",
        ]
        if f.get("poc"):
            lines.append(f"- **PoC:** `{f['poc']}`")
        lines.append(f"- **Remediation:** {f.get('remediation','')}")
        lines.append("")
    lines += ["---",
              "_Generated from a static audit; validate each item before disclosure. For a "
              "repository you do not own, report privately via the project's security policy "
              "or GitHub's \"Report a vulnerability\" (a private Security Advisory), not a public issue._"]
    return "\n".join(lines)


def render_issues(findings, repo) -> list:
    out = []
    for i, f in enumerate(findings, 1):
        body = (f"**Severity:** {_sev(f).upper()}  \n"
                f"**Location:** `{_loc(f)}`  \n"
                f"**CWE:** {f.get('cwe','n/a')}  \n"
                f"**Confidence:** {f.get('confidence','?')}\n\n"
                f"{f.get('description','')}\n")
        if f.get("poc"):
            body += f"\n**PoC:** `{f['poc']}`\n"
        body += f"\n**Remediation:** {f.get('remediation','')}\n\n" \
                f"_Filed from an automated static audit; please verify._"
        out.append({"title": f"[{_sev(f).upper()}] {f.get('title','finding '+str(i))}",
                    "body": body, "labels": ["security", _sev(f)]})
    return out


# ---------------- GitHub API (write access gate) ----------------

def whoami(token):
    r = requests.get(f"{API}/user", headers=_hdr(token), timeout=20)
    r.raise_for_status()
    return r.json().get("login")


def repo_access(owner, repo, token):
    """(can_write, http_status). can_write is True only if the token has
    push/admin/maintain on owner/repo - the gate for auto-filing."""
    r = requests.get(f"{API}/repos/{owner}/{repo}", headers=_hdr(token), timeout=20)
    if r.status_code != 200:
        return False, r.status_code
    perms = r.json().get("permissions", {}) or {}
    return bool(perms.get("admin") or perms.get("push") or perms.get("maintain")), 200


def create_issue(owner, repo, title, body, labels, token):
    r = requests.post(f"{API}/repos/{owner}/{repo}/issues", headers=_hdr(token),
                      json={"title": title, "body": body, "labels": labels}, timeout=30)
    r.raise_for_status()
    return r.json().get("html_url")
