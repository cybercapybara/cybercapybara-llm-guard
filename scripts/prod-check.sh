#!/usr/bin/env bash
# Pre-deployment gate: assert that a config profile + current environment
# describe a PRODUCTION-safe setup. Complements env-check.sh (which only
# finds unset placeholders) with semantic checks: docs UI off, JSON logs,
# secrets non-weak and enforced.
#
# Usage:
#   ./scripts/prod-check.sh [config/config.production.json]
#   make prod-check
#
# Exit: 0 when every check passes, 1 otherwise.

set -euo pipefail

CONFIG="${1:-config/config.production.json}"
FAILURES=0

if [[ ! -f "$CONFIG" ]]; then
    echo "error: $CONFIG not found" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required (brew install jq / apt install jq)" >&2
    exit 2
fi

fail() {
    printf '\e[1;31m✗ %s\e[0m\n' "$1"
    FAILURES=$((FAILURES + 1))
}
pass() { printf '\e[1;32m✓ %s\e[0m\n' "$1"; }

# Resolve a value the way the app does: env var wins, else JSON literal.
# (Placeholders in JSON resolve from env too — we check the env directly.)
resolved() {
    local json_path="$1" env_var="$2"
    if [[ -n "$env_var" && -n "${!env_var:-}" ]]; then
        printf '%s' "${!env_var}"
        return
    fi
    jq -r "$json_path // empty" "$CONFIG"
}

echo "== prod-check: $CONFIG =="

# 1. Swagger UI off.
DOCS=$(resolved '.docs.enabled' 'DOCS_ENABLED')
if [[ "$DOCS" == "false" || -z "$DOCS" ]]; then
    pass "docs.enabled = false"
else
    fail "docs.enabled must be false in production (Swagger UI exposes the surface)"
fi

# 2. Database password enforcement + non-weak value when provided.
if [[ "${DATABASE_REQUIRE_SECURE_PASSWORD:-}" == "true" ]]; then
    pass "DATABASE_REQUIRE_SECURE_PASSWORD=true"
else
    fail "set DATABASE_REQUIRE_SECURE_PASSWORD=true so weak DB passwords abort boot"
fi
case "${DATABASE_PASSWORD:-}" in
'' | postgres | password | changeme | admin | root | 123456)
    fail "DATABASE_PASSWORD is unset or a known-weak default"
    ;;
*) pass "DATABASE_PASSWORD set" ;;
esac

# 3. JSON log format (aggregator-ready).
if [[ "$(jq -r '.logging.format' "$CONFIG")" == "json" ]]; then
    pass "logging.format = json"
else
    fail "logging.format should be json in production"
fi

# 4. Delegate placeholder completeness to env-check.
if ./scripts/env-check.sh "$CONFIG" >/dev/null 2>&1; then
    pass "env-check: all required placeholders satisfied"
else
    fail "env-check found unsatisfied placeholders — run: ./scripts/env-check.sh $CONFIG"
fi

echo
# This gate only sees the JSON app-config. On Kubernetes the deploy-path env is
# rendered by Helm, so a misconfiguration can hide in the chart values where
# this check can't see it. `make helm-validate` (scripts/check-helm-render.sh)
# renders the prod overlay and asserts those — run BOTH before shipping.
echo "NOTE: also run 'make helm-validate' — it checks the rendered Helm deploy-path"
echo "      (APP_ENV, log format, no committed secrets)."
echo
if [[ $FAILURES -gt 0 ]]; then
    printf '\e[1;31mprod-check FAILED: %d issue(s).\e[0m\n' "$FAILURES"
    exit 1
fi
echo "prod-check passed — configuration is production-shaped."
