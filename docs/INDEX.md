# Documentation index

One-line navigator across every doc, ADR, and config in the repo. Use this
as the entry point when you need to find the right file for a
question instead of grepping the tree.

## Top-level guides

| File | What's there |
|---|---|
| [`../README.md`](../README.md) | Getting started, what's in the box, quickstart, repo layout |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Pre-commit setup, dev workflow, commit-message convention, release flow |
| [`../SECURITY.md`](../SECURITY.md) | Disclosure policy + production-hardening checklist |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Versioned change log (semver, edited under `## [Unreleased]`) |

## Worked examples & deep-dives

| File | What's there |
|---|---|
| [`CONVENTIONS.md`](CONVENTIONS.md) | Canonical "add an endpoint" checklist + what NOT to abstract |
| [`CONFIG.md`](CONFIG.md) | Single table mapping every JSON key ↔ env var ↔ default |
| [`TESTING.md`](TESTING.md) | Test buckets (unit/integration/api/e2e), what's covered vs not, coverage, the disabled-race note |
| [`BENCHMARKS.md`](BENCHMARKS.md) | How to measure latency/throughput/footprint (`make bench` + presets) + a results template |
| [`openapi.yaml`](openapi.yaml) | OpenAPI 3.1 spec for every registered route. `scripts/check-openapi-drift.sh` keeps it honest |
| [`Doxyfile`](Doxyfile) | `make docs` configuration; output goes to `docs/html/` (gitignored) |

## Architecture decision records (`adr/`)

| ADR | Decision |
|---|---|
| [`adr/0001-drogon-http-framework.md`](adr/0001-drogon-http-framework.md) | Why Drogon over Crow / Pistache / cpp-httplib |
| [`adr/0002-nlohmann-json.md`](adr/0002-nlohmann-json.md) | nlohmann::json end-to-end (Drogon's jsoncpp is internal-only) |
| [`adr/0003-header-only-modules.md`](adr/0003-header-only-modules.md) | All `src/` modules are `.hpp`; only `main.cpp` is a TU |
| [`adr/0005-spa-split.md`](adr/0005-spa-split.md) | Historic: why the console shipped as a separate SPA (the SPA is gone; kept as history) |
| [`adr/0006-api-versioning.md`](adr/0006-api-versioning.md) | Business routes live under `/api/v1`; probes stay unversioned |
| [`adr/0004-global-singletons.md`](adr/0004-global-singletons.md) | Module init/get/shutdown singleton pattern + ordering rationale |
| [`adr/README.md`](adr/README.md) | ADR conventions + how to add a new one |

## Migrations

| File | What's there |
|---|---|
| [`../migrations/README.md`](../migrations/README.md) | Migration conventions, NNN_*.sql naming, runner behaviour |
| [`../scripts/new-migration.sh`](../scripts/new-migration.sh) | Generate the next numbered migration (NO BEGIN/COMMIT — the runner wraps each file in one advisory-locked transaction) |

## Build & test

| File | What's there |
|---|---|
| [`../CMakeLists.txt`](../CMakeLists.txt) | Build graph, common libs, ASan/coverage/Werror options |
| [`../CMakePresets.json`](../CMakePresets.json) | `dev`, `dev-asan`, `release`, `coverage` presets (vcpkg toolchain) |
| [`../vcpkg.json`](../vcpkg.json) | Manifest-mode dependency list with pinned baseline |
| [`../Makefile`](../Makefile) | Single entry point — `make help` lists every target |
| [`../envrc.sample`](../envrc.sample) | Sample direnv config for native build (VCPKG_ROOT, TEST_PG_HOST, etc.) |

## CI / Ops

| File | What's there |
|---|---|
| [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml) | GitHub Actions CI: build + test + format + secret-scan |
| [`../.github/workflows/release.yml`](../.github/workflows/release.yml) | Tag-driven multi-arch image build + draft release |
| [`../helm/llm-guard/`](../helm/llm-guard/) | API Helm chart |
| [`../helm/cpp-env/`](../helm/cpp-env/) | Umbrella chart: one namespace = API + Postgres + Redis (+ optional Jaeger) |

## Scripts (`scripts/`)

| Script | Purpose |
|---|---|
| `init-project.sh` | One-shot rename of project identity (project name, registry, helm charts) |
| `new-endpoint.sh` | Scaffold a single controller + registry row + optional test + optional OpenAPI patch |
| `new-migration.sh` | Generate the next `NNN_<slug>.sql` |
| `check-openapi-drift.sh` | Verify `Api::get_endpoints()` (src/api/Endpoints.hpp) ↔ `docs/openapi.yaml` (method, path) |
| `check-routes-registered.sh` | Verify every controller ADD_METHOD_TO route is in `Api::get_endpoints()` (symmetric to the OpenAPI drift check) |
| `check-test-buckets.sh` | Verify test suites sit in the right bucket — classified by DIRECTORY, fails on a suite-name clash across unit/integration |
| `prod-check.sh` | Pre-deploy assertions on a production config (docs off, JSON logs, secrets enforced) |
| `check-helm-render.sh` | Render the Helm charts and assert deploy-path invariants (no cluster needed) |
| `lint-openapi.sh` | Spectral lint with project ruleset |
| `smoke.sh` | curl through critical endpoints (health, traceparent, content-type gate, metrics) |
| `bench.sh` | wrk benchmark with config presets |
| `env-check.sh` | Report unset `${VAR}` placeholders in config without defaults |
