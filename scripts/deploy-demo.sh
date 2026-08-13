#!/usr/bin/env bash
#
# Deploy / update the public demo environment at *.demo.example.com.
#
# Stands up the cpp-env umbrella (API + worker + frontend + Postgres + Redis +
# Mailpit + Jaeger) in its own namespace, with external-dns publishing the
# *.demo.example.com records and cert-manager issuing TLS. Idempotent — re-run to
# update. Secrets are generated once into a gitignored file and reused, so the
# Postgres password stays stable across re-deploys.
#
# Usage:
#   ./scripts/deploy-demo.sh
#
# Env overrides: KUBE_CONTEXT, DEMO_NAMESPACE, DEMO_RELEASE, DEMO_ADMIN_EMAIL.
set -euo pipefail

CTX="${KUBE_CONTEXT:-YOUR_KUBE_CONTEXT}"
NS="${DEMO_NAMESPACE:-env-demo}"
RELEASE="${DEMO_RELEASE:-demo}"
ADMIN_EMAIL="${DEMO_ADMIN_EMAIL:-admin@demo.example.com}"
# Fixed (not random) so it can be documented in the README; override if you fork.
ADMIN_PASS="${DEMO_ADMIN_PASS:-change-me-demo-pass}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHART="$ROOT/helm/cpp-env"
SECRETS="$CHART/.demo-secrets.env" # gitignored — generated once, reused

for bin in helm kubectl openssl; do
    command -v "$bin" >/dev/null 2>&1 || {
        echo "ERROR: '$bin' not found" >&2
        exit 2
    }
done

# ── Secrets: generate once, reuse afterwards (stable DB password) ──
if [[ -f "$SECRETS" ]]; then
    echo "==> Reusing demo secrets ($SECRETS)"
    # shellcheck source=/dev/null
    source "$SECRETS"
else
    echo "==> Generating fresh demo secrets → $SECRETS"
    DB_PASS="$(openssl rand -hex 24)"
    REDIS_PASS="$(openssl rand -hex 24)"
    JWT_SECRET="$(openssl rand -hex 32)"
    (
        umask 177
        cat >"$SECRETS" <<EOF
DB_PASS=$DB_PASS
REDIS_PASS=$REDIS_PASS
JWT_SECRET=$JWT_SECRET
EOF
    )
fi

echo "==> helm dependency build"
helm dependency build "$CHART" >/dev/null

echo "==> helm upgrade --install $RELEASE → ns/$NS (context $CTX)"
helm --kube-context "$CTX" upgrade --install "$RELEASE" "$CHART" \
    -n "$NS" --create-namespace \
    -f "$CHART/values-demo.yaml" \
    --set credentials.dbPassword="$DB_PASS" \
    --set credentials.redisPassword="$REDIS_PASS" \
    --set credentials.jwtSecret="$JWT_SECRET" \
    --set llm-guard.externalDatabase.password="$DB_PASS" \
    --set llm-guard.externalRedis.password="$REDIS_PASS" \
    --set llm-guard.auth.jwtSecret="$JWT_SECRET" \
    --set llm-guard-worker.externalDatabase.password="$DB_PASS" \
    --set llm-guard-worker.externalRedis.password="$REDIS_PASS" \
    --set llm-guard-worker.auth.jwtSecret="$JWT_SECRET" \
    --wait --timeout 10m

echo "==> Waiting for the API rollout"
kubectl --context "$CTX" -n "$NS" rollout status deploy/api --timeout=5m

# ── Demo admin + sample data (idempotent: create-admin is a no-op if it exists) ──
echo "==> Ensuring demo admin ($ADMIN_EMAIL) + seeding sample users"
POD="$(kubectl --context "$CTX" -n "$NS" get pod -l app.kubernetes.io/name=llm-guard \
    -o jsonpath='{.items[0].metadata.name}')"
# config path is positional and must precede the mode flag.
kubectl --context "$CTX" -n "$NS" exec "$POD" -- \
    /app/llm_guard config/config.json --create-admin "$ADMIN_EMAIL" "$ADMIN_PASS" || true
kubectl --context "$CTX" -n "$NS" exec "$POD" -- \
    /app/llm_guard config/config.json --seed-fake 8 || true

cat <<EOF

============================================================
  Demo is live (give DNS + TLS a minute on first deploy):

    App      https://app.demo.example.com
    API      https://api.demo.example.com/healthz
    Mailbox  https://mail.demo.example.com
    Traces   https://jaeger.demo.example.com

    Demo admin:  $ADMIN_EMAIL
    Password:    $ADMIN_PASS
============================================================
EOF
