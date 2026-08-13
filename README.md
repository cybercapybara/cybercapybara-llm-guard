# llm-guard

A C++20 LLM-guardrails masking proxy: it sits between your application and an
upstream LLM provider, masks sensitive values on the way out, and restores them
on the way back.

[![CI](https://github.com/cybercapybara/llm-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/cybercapybara/llm-guard/actions/workflows/ci.yml)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)
![Drogon](https://img.shields.io/badge/Drogon-HTTP%20Framework-green.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791.svg)
![Redis](https://img.shields.io/badge/Redis-7-DC382D.svg)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**Status:** early. The service currently exposes only the health/meta routes —
the masking engine and the proxy surface land in later phases. Everything below
describes the infrastructure that is already in place.

## Contents

- [What's in the box](#whats-in-the-box)
- [Quick start](#quick-start)
- [Adding an endpoint](#adding-an-endpoint)
- [Ops CLI](#ops-cli) · [Configuration](#configuration) · [Observability](#observability-quickstart)
- [Kubernetes](#kubernetes)
- [Repo layout](#repo-layout) · [Dev workflow](#dev-workflow)
- [Contributing](#contributing) · [Security](#security) · [License](#license)

## What's in the box

**HTTP layer**
- Drogon async HTTP server, multi-threaded event loops.
- Unified JSON error body (`{error, status, message, ...extras}`) across every
  controller and middleware — no five-shape drift.
- Composable request validators (`Api::Validation::*`) that accumulate errors
  and return a single 400 with a structured `errors` array.
- One-line JSON responses (`Response::ok` / `Response::created`) and
  `Validation::parse_body` — no hand-rolled HttpResponse boilerplate per
  endpoint.
- Middleware chain: content-type gate (415 on a non-JSON mutation body) → CORS
  → baseline security headers → tracing → access log + HTTP metrics.

**Data**
- Postgres connection pool (libpqxx) with optional read replicas, a per-call
  statement timeout, and pool-saturation / replica-lag gauges.
- Redis client (standalone or Sentinel HA). Cache-aside reads go through
  `Cache::get()` and are fail-open by convention — a Redis hiccup never blocks
  a request.
- Migration runner: numbered `.sql` files applied at boot under an advisory
  lock, safe with multiple replicas.

**Reliability**
- Retry-with-backoff wrapper (`Retry::run`) transparently applied to
  `Database::execute_read/write` with pqxx / redis transient-error classifiers,
  reported as a `retries_total` counter.
- Graceful shutdown: SIGTERM flips `/ready` to 503, then Drogon drains after a
  configurable pre-stop delay.

**Observability**
- Prometheus metrics with cardinality-safe path normalisation.
- OpenTelemetry traces (OTLP HTTP exporter).
- W3C Trace Context: incoming `traceparent` parsed (or generated) and echoed
  back as `X-Request-Id` + `traceparent` on every response.
- Structured logs via spdlog with the trace-id in each access log line.

**Testing**
- Four buckets by directory — unit (sidecar-free), integration and api (real
  Postgres + Redis), and e2e (a real Drogon server + client on the wire).
  See [`docs/TESTING.md`](docs/TESTING.md).

**Ops**
- Helm chart for the service plus a `cpp-env` umbrella that deploys it with
  in-cluster Postgres / Redis / Jaeger as one environment. `preStop` hook +
  `terminationGracePeriodSeconds`, `ServiceMonitor`, opt-in `PrometheusRule`
  with baseline SLO alerts, opt-in `ExternalSecret` skeleton for Vault / AWS /
  GCP secret stores.
- GitHub Actions: build + unit/integration tests, gitleaks secret scan, Trivy
  image scan, clang-format / clang-tidy lints, ASan + UBSan + TSan builds,
  helm-render and OpenAPI-drift gates.
- Production config profile (`config/config.production.json`) gated by
  `make prod-check` before anything ships.
- Prometheus alert rules out of the box (5xx rate, p99 latency, scrape-down,
  retry exhaustion, pool saturation, replica lag).
- Renovate config: docker tags, GitHub-Action SHAs and the vcpkg baseline stay
  current instead of fossilizing.
- `make warm-cache` pulls the CI-built dependency image — first build in
  minutes instead of the ~30-minute cold vcpkg compile.

**Docs**
- [`docs/INDEX.md`](docs/INDEX.md) — the map of every doc in the repo.
- [`docs/openapi.yaml`](docs/openapi.yaml) — OpenAPI 3.1 for every registered route.
- [`docs/CONFIG.md`](docs/CONFIG.md) — one table with every env var, JSON key,
  and default.
- [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) — the add-an-endpoint checklist
  and the hard-won gotchas.

## Quick start

**Prerequisites:** Docker + Docker Compose v2. On macOS the build runs in a
Linux VM (Docker Desktop or Colima) — **give it ≥ 8 GiB of memory**. The first
build compiles the C++ dependency set from source via vcpkg; under-provisioned
VMs (the Colima default is 2 GiB) OOM the builder and surface it as a cryptic
`EOF` / `rpc error: Unavailable`, which reads like a code bug but isn't. With
Colima: `colima start --cpu 4 --memory 8`. Run `make doctor` to check the
toolchain and the VM's memory, and `make warm-cache` to pull a prebuilt
dependency layer so the first build is minutes, not ~30.

```bash
make doctor        # verify Docker + VM memory before the first (cold) build
make warm-cache    # optional: prime the vcpkg dependency layer (~30 min -> ~3)

# Build + run Postgres + Redis + the API, wait for ready, hit /healthz
make quickstart

# Sanity check the endpoints
make smoke

# Tail logs
make logs
```

The service listens on `:8080` (HTTP) and `:9090` (Prometheus `/metrics`).

### Run the tests

| Command | When to use |
|---|---|
| `make test` | Cold run — rebuilds the test image, full suite, ~2 min |
| `make test-quick` | Fast TDD loop — reuses cached image, ~5 s |
| `make test-unit` | Only unit tests; skips anything needing Postgres/Redis |
| `make test-e2e` | HTTP end-to-end binary: real Drogon server + client on the wire |

### Stack variants

| Command | Adds |
|---|---|
| `make up-monitoring` | Prometheus + Grafana + Jaeger + exporters |
| `make up-build` | Same, but builds the app image from your working tree |

All profiles share the same `make down` / `make down-v`.

## Adding an endpoint

`./scripts/new-endpoint.sh FooController Get /api/v1/foo [--with-test]
[--patch-openapi]` does all of this for you. By hand:

1. Add the route to a controller (existing or new) under `src/api/`:
   ```cpp
   METHOD_LIST_BEGIN
   ADD_METHOD_TO(MyController::listThings, "/api/v1/things", Get);
   METHOD_LIST_END
   ```
2. Register the new route in `Api::get_endpoints()` in `src/api/Endpoints.hpp`
   (the route registry, surfaced at `/`), and add the `#include` to
   `src/api/Api.hpp`.
3. Update `docs/openapi.yaml` — manually, and CI holds you to it:
   `scripts/check-openapi-drift.sh` fails the pipeline on any (method, path)
   mismatch between spec and `Api::get_endpoints()`.
4. If the endpoint mutates, validate inputs through `Api::Validation::*` and
   return errors via `Api::Validation::response_400(errs)` for bulk errors or
   `ErrorResponse::{bad_request,not_found,...}()` for single-shot.
5. Add a test in `tests/api/` (controller methods via
   `TestHelpers::make_request`), `tests/integration/` (real Postgres/Redis), or
   `tests/e2e/` (the full Drogon server over real HTTP).

[`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) is the long form.

## Ops CLI

Run the binary with any of these to bypass the server loop:

| Flag | Effect |
|---|---|
| `--print-routes` | Print the registered endpoint table and exit. No DB/Redis required. |
| `--dump-config` | Resolve config (JSON + env overrides) and print as JSON. No subsystems. |
| `--verify-migrations` | Connect to the DB and list migrations not yet applied. Exits 1 if any are pending — handy as a CI gate. |
| `--run-migrations` | Apply all pending migrations and exit. Same effect as `RUN_MIGRATIONS_ONLY=1` env, surfaced as a flag for native dev / `make migrate-local`. |
| `--help` / `-h` | Show usage. |

The positional arg (if present, before flags) is the config path, same as the
default boot mode.

## Configuration

See the full table in [`docs/CONFIG.md`](docs/CONFIG.md). Short version:

- Defaults live in `config/config.json` with `${VAR}` placeholders.
- Env vars override everything.
- Per-deployment overlay: drop a `config/local.json`, point `CONFIG_FILE` at it.
  `config/local.json` is git-ignored.

## Observability quickstart

With `make up-monitoring`:

- Metrics: http://localhost:9094 (Prometheus), http://localhost:3000 (Grafana)
- Traces: http://localhost:16686 (Jaeger UI)
- Every HTTP response carries `X-Request-Id` — use that to correlate logs/traces.

The app emits `OTLP_ENDPOINT`-tuned OTLP HTTP to whatever you configure; default
`http://jaeger:4318/v1/traces` in the `with-monitoring` profile.

## Kubernetes

Two charts:

- `helm/llm-guard` — the HTTP service
- `helm/cpp-env` — umbrella that deploys it as one environment (plus
  in-cluster Postgres / Redis / Jaeger); see `make helm-validate`

Render locally:

```bash
helm template api helm/llm-guard --set image.repository=my-registry/llm-guard
```

**First prod deploy — start from the example overlay.** The chart ships a
tracked, secret-free `values-prod.example.yaml`. Copy it, fill in the TODOs
(hosts, image, datastore endpoints), and deploy:

```bash
cp helm/llm-guard/values-prod.example.yaml helm/llm-guard/values-prod.yaml   # gitignored
helm upgrade --install api ./helm/llm-guard -n prod -f helm/llm-guard/values-prod.yaml \
  --set externalDatabase.password="$DB_PASSWORD" \
  --set externalRedis.password="$REDIS_PASSWORD"
```

**Image architecture — match it to your nodes.** CI builds the image only to run
tests (no publish); the `release.yml` tag job publishes a linux/amd64 image on
`v*` tags. If your cluster is arm64, build for it yourself:

```bash
docker buildx build --platform linux/arm64 --target runtime \
  -t your-registry/llm-guard:$(git rev-parse --short HEAD)-arm64 --push .
```

A mismatch shows up as `exec format error` / `CrashLoopBackOff` on first roll-out.

Per-cluster secrets and overrides go in untracked files — `helm/**/values-prod.yaml`,
`helm/values.*.yaml`, and `helm/*.local.yaml` are all gitignored. Either pass
real secrets via `--set` / a private values file, or wire `externalSecrets`
to Vault / AWS Secrets Manager / etc. **Never** put a real secret in a tracked
`*.example.yaml`.

Opt-ins you'll almost certainly want in prod:

- `autoscaling.enabled=true` (HPA)
- `pdb.enabled=true` (PodDisruptionBudget)
- `networkPolicy.enabled=true` — tune the selectors for YOUR cluster namespaces first
- `serviceMonitor.enabled=true` + `monitoring.alertsEnabled=true` (Prometheus-operator CRDs)
- `externalSecrets.enabled=true` — pull DB/Redis secrets from Vault or similar

The [SECURITY.md](SECURITY.md) hardening checklist walks through every one.

## Repo layout

```
src/
  api/           HTTP controllers + endpoint registry + middleware pipeline
    Api.hpp           controller includes + middleware wiring (register_controllers)
    Endpoints.hpp     get_endpoints() — the route registry (drift-checked vs openapi.yaml)
    Middleware.hpp    middleware bodies (content-type -> cors -> headers -> trace -> access log)
    RequestUtils.hpp  parse_int, clamp_int, parse_page_params, is_valid_uuid, normalize_path_for_metrics
    Validation.hpp    composable request-body validators
    HealthController.hpp  /healthz, /ready, /health + the / endpoint-discovery route
  cache/         Redis client (standalone or Sentinel HA)
  core/          Application lifecycle (init, health, shutdown)
  database/      Postgres pool + migrations
  observability/ Logger, Prometheus, OpenTelemetry tracer, W3C Trace Context
  tasks/         Drogon-timer-based task scheduler
  utils/         Config (JSON + env), Retry, Crypto, Base64, Strings, ErrorResponse

tests/
  unit/          Pure C++ tests (no external services)
  integration/   Tests that need real Postgres / Redis
  api/           Controller-method tests via TestHelpers::make_request
  e2e/           Real Drogon server + HTTP client (separate binary)

docker/          Dockerfile + docker-compose.yml + prometheus/grafana config
helm/            Helm charts (llm-guard + cpp-env umbrella), values documented
scripts/         smoke.sh, init-project.sh, bench.sh, new-endpoint.sh,
                 new-migration.sh, check-openapi-drift.sh,
                 check-routes-registered.sh, check-test-buckets.sh,
                 check-helm-render.sh, lint-openapi.sh, env-check.sh,
                 prod-check.sh
docs/            openapi.yaml, CONFIG.md, CONVENTIONS.md, INDEX.md, adr/, Doxyfile
```

## Dev workflow

| Command | What it does |
|---|---|
| `make up` | Start base stack (app + Postgres + Redis) |
| `make doctor` | Sanity-check the local toolchain (cmake, ninja, jq, vcpkg, …) |
| `make env-check` | Report `${VAR}` placeholders in `config/config.json` that are unset and have no default |
| `make prod-check` | Semantic production gate: docs UI off, JSON logs, strong + enforced secrets |
| `make warm-cache` | Pull the CI-built builder image — skip the cold vcpkg compile |
| `make build-local` | Native cmake build via the `dev` preset, no Docker |
| `make compile-commands` | Generate `compile_commands.json` for clangd |
| `make test` / `make test-quick` | Full / cached suite in Docker |
| `make test-local NAME=Retry*` | Native gtest run with a `--gtest_filter` |
| `make test-watch` | Re-run unit tests on src/ or tests/ change (watchexec or entr) |
| `make watch` | Rebuild + restart on `src/` change (entr or watchexec) |
| `make coverage` | gcovr HTML report in `coverage/index.html`; fails under `COVERAGE_MIN`% line coverage |
| `make ci-local` | Reproduce CI locally: format check + drift + spectral + tidy + tests |
| `make helm-lint` / `make helm-validate` | `helm lint` + template render / deploy-path assertions |
| `make routes` / `make health` | Print endpoint table / hit health probes |
| `make psql` / `make redis-cli` | Open a shell against the running stack |
| `make migrate` / `make migrate-local` / `make migrate-status` / `make migrate-reset` | Run (Docker or native) / inspect / nuke-and-reapply migrations |
| `make init NAME=… [REGISTRY=…]` | Rebrand the project via `scripts/init-project.sh` |
| `make new-endpoint NAME=… METHOD=… PATH_=… [WITH_TEST=1] [PATCH_OPENAPI=1]` | Scaffold a controller via `scripts/new-endpoint.sh` |
| `make new-migration SLUG=…` | Generate the next `migrations/NNN_<slug>.sql` |
| `make logs` / `make logs-pretty` | Tail logs (json-pretty via jq) |
| `make tail-trace TID=<id>` | Filter app logs by a specific trace id |
| `make fmt` / `make lint` / `make tidy` / `make lint-openapi` | clang-format / format-check / clang-tidy / spectral |
| `make smoke` | curl through the health/meta endpoints |
| `make clean` / `make dist-clean` | Wipe build/, logs, Doxygen output (+vcpkg_installed for dist-clean) |
| `make down` / `make down-v` | Stop everything (and wipe volumes with `down-v`) |

`make help` prints this table at any time.

### Faster local builds

**Docker path (recommended):** `make warm-cache` pulls the dependency image
your CI already built, so `make build` / `make test` reuse those layers and
skip the ~30-minute cold vcpkg compile entirely.

**Native path — vcpkg binary cache:**

A cold local build pulls and compiles every dependency once. Wire up vcpkg's
binary cache so subsequent builds (and CI clones) reuse the artefacts:

```bash
mkdir -p ~/.vcpkg-bincache
export VCPKG_BINARY_SOURCES='clear;files,~/.vcpkg-bincache,readwrite'
make build-local        # first run populates the cache
make dist-clean && make build-local   # second run is near-instant
```

Persist this in your `~/.zshrc` / `~/.bashrc`. The dev container already
mounts a vcpkg buildtrees + downloads volume, so no extra setup there.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). TL;DR: conventional commits, clang-format
clean, tests passing, don't break the error-response shape without updating
`docs/openapi.yaml`.

## Security

See [SECURITY.md](SECURITY.md) — private disclosure via `security@example.com`,
plus a production-hardening checklist.

## License

MIT. See [LICENSE](LICENSE). Third-party dependencies and their licenses are
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
