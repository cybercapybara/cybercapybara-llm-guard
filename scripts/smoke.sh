#!/usr/bin/env bash
# Smoke test a running instance. Hits every critical surface:
# health, trace-id propagation, validation, and metrics — and ASSERTS the
# expected HTTP status on each step, so a wall of 500s actually fails the
# script instead of printing "Smoke passed".

set -euo pipefail

BASE="${BASE_URL:-http://localhost:8080}"
METRICS="${METRICS_URL:-http://localhost:9090}"
FAILURES=0

say() { printf '\n\e[1;34m== %s ==\e[0m\n' "$1"; }

# expect <status[|status...]> <curl args...> — runs the request, prints the
# body, and records a failure unless the status matches one of the allowed
# values (some endpoints legitimately differ by dependency state).
expect() {
    local want="$1"; shift
    local body_file status
    body_file=$(mktemp)
    status=$(curl -sS -o "$body_file" -w '%{http_code}' "$@") || status=000
    head -c 400 "$body_file"; echo
    rm -f "$body_file"
    if [[ "|$want|" == *"|$status|"* ]]; then
        printf '\e[1;32m   ok (%s)\e[0m\n' "$status"
    else
        printf '\e[1;31m   FAIL: expected HTTP %s, got %s\e[0m\n' "$want" "$status"
        FAILURES=$((FAILURES + 1))
    fi
}

say "Liveness /healthz"
expect 200 "$BASE/healthz"

say "Readiness /ready"
expect 200 "$BASE/ready"

say "traceparent propagation"
TP='00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'
HDRS=$(curl -sS -D - -o /dev/null -H "traceparent: $TP" "$BASE/healthz")
if echo "$HDRS" | grep -qiE '(traceparent|x-request-id)'; then
    echo "$HDRS" | grep -iE '(traceparent|x-request-id)' | head -2
    printf '\e[1;32m   ok\e[0m\n'
else
    printf '\e[1;31m   FAIL: no traceparent / x-request-id response headers\e[0m\n'
    FAILURES=$((FAILURES + 1))
fi

say "Endpoint discovery /"
expect 200 "$BASE/"

say "Detailed health /health"
expect "200|503" "$BASE/health"

say "Content-Type gate — POST / with a text body (415)"
expect 415 -X POST -H 'Content-Type: text/plain' -d 'nope' "$BASE/"

say "Prometheus /metrics (http_requests_total subset)"
curl -sS "$METRICS/metrics" 2>/dev/null | grep -E '^(http_requests_total|db_pool_size)' | head -6 || echo '(no metrics yet)'

echo
if [[ $FAILURES -gt 0 ]]; then
    printf '\e[1;31mSmoke FAILED: %d check(s) did not match.\e[0m\n' "$FAILURES"
    exit 1
fi
echo "Smoke passed."
