# Conventions — how to add an endpoint

This is the canonical, copy-this checklist for adding a route end to end.

> Fast path: `./scripts/new-endpoint.sh FooController Get /api/v1/foo
> [--with-test] [--patch-openapi]` scaffolds the controller, the registry row,
> the test and the OpenAPI block following every rule below.

The friction this guards against: a route name lives in three places
(controller `ADD_METHOD_TO`, `Api::get_endpoints()`, `docs/openapi.yaml`) and
they drift **silently** — the build stays green. Follow the order below and run
the drift checkers.

---

## 1. Migration — `migrations/NNN_<slug>.sql`

`./scripts/new-migration.sh add_products` writes a numbered, idempotent
skeleton. Inside: `CREATE TABLE IF NOT EXISTS`, indexes, and any `updated_at`
trigger. Applied at boot in numeric order by `MigrationRunner` under an advisory
lock (safe with multiple replicas). No `BEGIN`/`COMMIT` — the runner wraps each
file; use the `-- migrate:no-transaction` marker for `CREATE INDEX
CONCURRENTLY`.

## 2. Controller — `src/api/<Entity>Controller.hpp`

Includes: `api/RequestUtils.hpp`, `api/Validation.hpp`,
`utils/ErrorResponse.hpp` — **never** `api/Api.hpp` (include cycle).

Per handler:
1. Parse + validate: `Validation::parse_body(req, body, callback)` then
   `Validation::require/email/string_length`, accumulate into
   `Validation::Errors`, bail with `Validation::response_400(errs)`.
2. List endpoints: `parse_page_params(req, default, max)` →
   `{data, total, limit, offset}`.
3. Success: `Response::ok(...)` / `Response::created(...)` — never build the
   `HttpResponse` by hand.
4. Errors: `ErrorResponse::*`. One error shape everywhere —
   `{error, status, message, ...}`. Never hand-roll error JSON.
5. **`callback(...)` exactly once on every path**, including early returns.

## 3. Route registry + OpenAPI

- Add the route to `Api::get_endpoints()` in **`src/api/Endpoints.hpp`** (NOT
  `Api.hpp`) for every `ADD_METHOD_TO`.
- Add the `#include "api/<Entity>Controller.hpp"` to `src/api/Api.hpp`.
- Add the path block + `components/schemas/<Entity>` to `docs/openapi.yaml`
  (hand-edited). Run `./scripts/check-openapi-drift.sh` — it verifies
  `(method, path)` parity (it does **not** check schema bodies, so review
  those by eye).
- Business routes live under `/api/v1` (ADR 0006). Probe routes (`/healthz`,
  `/ready`, `/health`, `/metrics`) stay unversioned.

## 4. Tests

- Integration suite `tests/integration/test_<entity>.cpp` extending
  `TestHelpers::CoreBackedTest` (`config_overrides`, `requires_postgres`,
  `post_init`); use `TestHelpers::make_request(...)`.
- Buckets are classified by DIRECTORY, not a filter list: a file in
  `tests/integration/` (or `tests/api/`) is compiled into the integration
  binary by CMake's `CONFIGURE_DEPENDS` glob with no registration step.
  `./scripts/check-test-buckets.sh` (run in CI) just guards placement — it
  fails on a suite-name clash across buckets, so a DB-dependent suite can't
  silently shadow a unit suite.

## What NOT to reach for

These were considered and rejected as overengineering: a generic
`Repository<T>` (the `execute_*` lambdas already are the base layer), a service
layer everywhere, and an `IDatabase` interface for mocking (data access is
tested integration-style against real Postgres). Keep handlers readable and the
flow visible in one file.

## Gotchas — hard-won rules

These don't fall out of reading the code; they were learned the hard way.

1. **All modules are header-only.** Never add a `.cpp` under `src/`. CMake compiles `src/main.cpp` explicitly; `file(GLOB tests/...)` only picks up tests — a new `src/foo.cpp` silently never links. The only `.cpp` under `src/` is `main.cpp`.
2. **`Api::get_endpoints()` (`src/api/Endpoints.hpp`) is the single source of truth for routes.** After an `ADD_METHOD_TO(...)`, add the matching line there, or `scripts/check-openapi-drift.sh` fails CI and `--print-routes` won't show it. Controllers include `api/RequestUtils.hpp` but NOT `api/Api.hpp` (cycle).
3. **JSON: nlohmann::json only, never jsoncpp.** Drogon uses jsoncpp internally, but project code is all nlohmann. Parse with `json::parse(req->body())`, respond with `data.dump()` + `CT_APPLICATION_JSON`. **Never call `req->getJsonObject()`.**
4. **`Core::initialize()` has a strict init order:** Config → Observability → validate → Database → Migrations → Cache → Tasks → health checks; shutdown is the reverse. Don't reorder (Cache uses Observability metrics; Database depends on Config).
5. **`req->attributes()->get<T>(key)` on a miss returns a default-constructed `T`** (older Drogon threw `std::out_of_range` — both exist). Never rely on the throw: `find(key)` first, then `get<T>`.
6. **Every Redis call is fail-open.** `CacheManager` methods swallow `sw::redis::Error` and log a warn; wrap direct `get_client()` calls in try/catch. See `docs/adr/`.
7. **Drogon's log level is hardcoded in `main.cpp` (`Logger::kInfo`).** `LOG_LEVEL` only affects spdlog. For Drogon debug, edit `setLogLevel` in `main.cpp`.
8. **`callback(...)` exactly once on every path** — including exceptions and early returns — or the client hangs until timeout.
9. **Tests don't call controller methods directly with a fake `req`** — use `tests/test_helpers.hpp` (`make_request(...)`).
10. **`docs/openapi.yaml` is edited by hand.** The drift checker compares `(method, path)`; update the spec on any route change.
11. **`make migrate-reset` / `make down-v` / `make dist-clean` are destructive** (drop data) — don't run them casually.
12. **Validate Helm before pushing chart changes: `make helm-validate`.** It renders the umbrella with `values-ci.yaml` and asserts deploy invariants (ingress port == service port, probe paths, `baseDomain` expanded). Vendored `helm/*/charts/*.tgz` are gitignored — run `helm dependency build` (which `helm-validate` does) before rendering/deploying.
13. **PCH `REUSE_FROM` is a single fragile build point.** integration/e2e tests `REUSE_FROM` the unit PCH; flag drift (esp. sanitizer defines) silently breaks reuse or forces a full rebuild — which is why the ASan build lives in a separate `build-san` tree. Changing the `HEAVY_PCH` set or flags → rebuild all test buckets AND the sanitizer build.

### Where to look (question → file)

The scaffolding scripts are the entry points:

| Want to… | Look at / run |
|---|---|
| Add an endpoint | `./scripts/new-endpoint.sh` |
| Add a migration | `./scripts/new-migration.sh` |
| Bring up the whole stack | `make up` |
| Debug routes / health / traces | `make routes` / `make health` / `make tail-trace TID=<id>` |
| Run "like CI" locally | `make ci-local` |
| Check spec ↔ code drift | `./scripts/check-openapi-drift.sh` |
| Validate Helm render | `make helm-validate` |
| ADRs / architecture decisions | `docs/adr/` |
