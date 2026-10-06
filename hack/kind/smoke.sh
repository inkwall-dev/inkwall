#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Sends benign and attack requests to the demo app and checks the engine's
# verdicts (block mode). PROXY is where requests enter, ADMIN the engine's
# admin listener; the defaults are the reverse-proxy deployment.
set -euo pipefail

NAME=${NAME:-reverse proxy}
PROXY=${PROXY:-http://127.0.0.1:30480}
ADMIN=${ADMIN:-http://127.0.0.1:30481}

echo "== $NAME ($PROXY)"

failures=0

expect() {
  local want=$1 desc=$2
  shift 2
  local got
  got=$(curl -s -o /dev/null -w '%{http_code}' "$@" || true)
  if [[ $got == "$want" ]]; then
    printf 'ok    %s (%s)\n' "$desc" "$got"
  else
    printf 'FAIL  %s: got %s, want %s\n' "$desc" "$got" "$want"
    failures=$((failures + 1))
  fi
}

expect 200 "benign GET" "$PROXY/"
expect 200 "benign query" "$PROXY/search?q=running+shoes"
expect 200 "benign JSON POST" -H 'Content-Type: application/json' -d '{"user":"alice","qty":2}' "$PROXY/api/cart"
expect 200 "benign form POST" -d 'user=alice&comment=great+shoes' "$PROXY/comments"
expect 200 "attack on a skipped path is not inspected" "$PROXY/health?id=1%27%20OR%20%271%27%3D%271"
expect 403 "SQL injection" "$PROXY/?id=1%27%20OR%20%271%27%3D%271"
expect 403 "XSS" "$PROXY/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
expect 403 "path traversal" "$PROXY/?file=../../../../etc/passwd"
expect 403 "command injection" -d 'host=127.0.0.1;cat /etc/passwd' "$PROXY/ping"
expect 403 "XSS in a JSON body" -H 'Content-Type: application/json' -d '{"note":"<script>alert(1)</script>"}' "$PROXY/api/notes"
expect 403 "scanner user agent" -A 'sqlmap/1.7' "$PROXY/"
# forward-auth: the engine must inspect the real URI, not one the client
# claims in the headers the proxy uses to describe the request.
expect 403 "attack behind spoofed X-Forwarded-Uri" -H 'X-Forwarded-Uri: /harmless' -H 'X-Forwarded-Method: GET' "$PROXY/?id=1%27%20OR%20%271%27%3D%271"
expect 200 "healthz" "$ADMIN/healthz"
expect 200 "readyz" "$ADMIN/readyz"

# The demo app echoes the request headers it received.
if curl -s "$PROXY/" | grep -qi '^X-Request-Id: [0-9a-f]'; then
  echo "ok    request ID reaches the app"
else
  echo "FAIL  no X-Request-Id at the app"
  failures=$((failures + 1))
fi

# Read the whole body first: grep -q exiting early would fail curl under pipefail.
metrics=$(curl -s "$ADMIN/metrics" || true)
if grep -q '^inkwall_requests_total' <<<"$metrics"; then
  echo "ok    metrics exported"
else
  echo "FAIL  inkwall_requests_total missing from /metrics"
  failures=$((failures + 1))
fi

if ((failures)); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
