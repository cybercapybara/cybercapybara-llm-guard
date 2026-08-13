#!/usr/bin/env bash
#
# Render the cpp-env umbrella with CI values and assert semantic properties of
# the rendered manifests. Catches the deploy-path bug CLASS that compilation and
# unit tests can't — and that bit us repeatedly: ingress↔service port drift
# (a service served 8080 but ingress said 80), baseDomain left at example.com,
# and env silently dropped because it sits behind a `{{- if }}` whose flag is
# unset in a given overlay.
#
# It needs no cluster — pure `helm template` smoke test. Run via `make
# helm-validate` or the helm-charts CI job. Re-runs `helm dependency build` so a
# stale vendored subchart (charts/*.tgz are gitignored) can't skew the render.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHART="$ROOT/helm/cpp-env"
VALUES="$CHART/values-ci.yaml"

command -v helm >/dev/null 2>&1 || {
    echo "helm not installed — brew install helm"
    exit 1
}
command -v yq >/dev/null 2>&1 || {
    echo "yq not installed — brew install yq"
    exit 1
}

echo "==> helm dependency build (re-vendor subcharts)"
helm dependency build "$CHART" >/dev/null

echo "==> helm lint (umbrella with CI values)"
helm lint "$CHART" -f "$VALUES" >/dev/null || {
    echo "FAIL: helm lint"
    exit 1
}

echo "==> helm template (CI values) + semantic assertions"
RENDERED="$(helm template ci-smoke "$CHART" -f "$VALUES")"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}
q() { printf '%s' "$RENDERED" | yq "$1"; }

# 1. Ingress backend port must equal the service port (8080). This is the exact
#    80↔8080 drift bug.
[ "$(q 'select(.kind=="Ingress" and .metadata.name=="api") | .spec.rules[0].http.paths[0].backend.service.port.number')" = "8080" ] ||
    fail "api ingress backend port != 8080"

# 2. Probe wiring must survive templating — the readiness path the cluster uses
#    to pull a bad pod out of rotation.
[ "$(q 'select(.kind=="Deployment" and .metadata.name=="api") | .spec.template.spec.containers[0].readinessProbe.httpGet.path')" = "/ready" ] ||
    fail "api readiness probe path != /ready"

# 3. Host templating must expand from baseDomain (catches an un-overridden
#    baseDomain — the values-ci.yaml domain is ci.example.test).
host="$(q 'select(.kind=="Ingress" and .metadata.name=="api") | .spec.rules[0].host')"
[ "$host" = "api.ci.ci.example.test" ] || fail "api ingress host did not expand from baseDomain (got: '$host')"

# 4. No Service may render a null port (a templating slip that 503s the route).
nullports="$(q 'select(.kind=="Service") | .spec.ports[] | select(.port == null) | .name' | grep -c . || true)"
[ "$nullports" = "0" ] || fail "$nullports service port(s) rendered null"

# 5. The minimal preset must stay minimal — render values-minimal.yaml and
#    assert the heavy optional services are gone, so the lighter onboarding
#    preset can't silently rot back into the kitchen sink.
echo "==> helm template (minimal preset)"
MINIMAL="$(helm template ci-smoke "$CHART" -f "$VALUES" -f "$CHART/values-minimal.yaml")"
workloads="$(printf '%s' "$MINIMAL" | yq 'select(.kind=="Deployment" or .kind=="StatefulSet") | .metadata.name')"
printf '%s' "$workloads" | grep -qi jaeger && fail "values-minimal still renders a Jaeger workload"

# 6. Production security floor. prod-check.sh validates the JSON app-config, but
#    the deploy-path env comes from Helm — so a setting that only exists on the
#    deploy path was invisible to it. Render the llm-guard chart with the
#    TRACKED prod example overlay and assert the env the cluster actually runs.
echo "==> helm template (llm-guard prod example) + security assertions"
API_CHART="$ROOT/helm/llm-guard"
PROD_RENDERED="$(helm template prod-smoke "$API_CHART" -f "$API_CHART/values-prod.example.yaml")"
penv() {
    printf '%s' "$PROD_RENDERED" |
        yq "select(.kind==\"Deployment\") | .spec.template.spec.containers[0].env[] | select(.name==\"$1\") | .value"
}

# APP_ENV=production arms the binary's boot-time prod-safety warnings.
[ "$(penv APP_ENV)" = "production" ] || fail "prod overlay: APP_ENV != production (boot-time safety checks stay disarmed)"
# Structured logs are a hard requirement for the aggregator in prod.
[ "$(penv LOG_FORMAT)" = "json" ] || fail "prod overlay: LOG_FORMAT != json"

# No plaintext secret may be baked into a TRACKED overlay — the DB password must
# arrive via --set or external-secrets (rendered as secretKeyRef), so its plain
# .value is empty here. A non-empty value = a committed secret.
for s in DATABASE_PASSWORD REDIS_PASSWORD; do
    [ -z "$(penv "$s")" ] || fail "prod overlay: $s carries a plaintext value — pass it via --set / external-secrets, never a tracked overlay"
done

echo "==> helm-render: all assertions passed"
