# CLAUDE.md — agent guide for this repo

llm-guard — a C++20 LLM-guardrails masking proxy built on Drogon +
PostgreSQL + Redis, vcpkg/CMake, Helm charts in `helm/`. `docs/INDEX.md` is
the map of all documentation; `docs/CONVENTIONS.md` is the pattern reference.

The service is currently a lean base: only the health/meta routes exist. The
masking-proxy surface lands in later phases.

## Prime directive: scaffold, don't hand-roll

- Single endpoint: `./scripts/new-endpoint.sh FooController Get /api/v1/foo
  [--with-test] [--patch-openapi]`
- Migration: `make new-migration SLUG=<slug>`

The generators encode the invariants below — their output passes the CI
gates by construction. Hand-rolled versions usually don't.

## Invariants the CI gates enforce

1. **Route triple-sync:** every `ADD_METHOD_TO` in a controller must also
   appear in `Api::get_endpoints()` (`src/api/Endpoints.hpp`) **and** in
   `docs/openapi.yaml`. `scripts/check-openapi-drift.sh` and
   `scripts/check-routes-registered.sh` fail CI on any mismatch.
2. **API versioning (ADR 0006):** business routes live under `/api/v1`;
   `new-endpoint.sh` rejects unversioned paths. Probe routes (`/healthz`,
   `/ready`, `/health`, `/metrics`) stay unversioned.
3. **Header-only src/ (ADR 0003):** implementation lives in `.hpp`; don't
   add `.cpp` files except the existing binary entry point (`src/main.cpp`).
4. **One error shape:** `{error, status, message, ...}` everywhere — use
   `ErrorResponse::*` / `Api::Validation::*`, never hand-rolled error JSON.
5. **Test buckets by directory** (`scripts/check-test-buckets.sh`):
   `tests/unit` (no services), `tests/integration` (real Postgres/Redis),
   `tests/api` (controller via `TestHelpers::make_request`), `tests/e2e`
   (real HTTP server, separate binary).
6. **Migrations:** `migrations/NNN_slug.sql`, sequential numbering, no
   `BEGIN`/`COMMIT` (the runner wraps them; use the
   `-- migrate:no-transaction` marker for `CREATE INDEX CONCURRENTLY`).
7. **No secrets in tracked files:** `config/config.json` holds `${VAR}`
   placeholders, env overrides everything (`docs/CONFIG.md` is the full
   table). gitleaks gates CI; `make prod-check` gates the prod profile.
8. **Commits:** conventional commits, no AI-attribution trailers.

## Gate sequence — run cheapest-first before pushing

1. `make fmt` — clang-format in place
2. `./scripts/check-openapi-drift.sh && ./scripts/check-routes-registered.sh
   && ./scripts/check-test-buckets.sh` — seconds, no build
3. `make lint-openapi` — spectral over `docs/openapi.yaml`
4. `make test-quick` — cached test image, ~5 s
5. `make test` — full rebuild + suite, ~2 min; what CI runs
6. `make helm-lint` — only if `helm/` was touched
7. `make ci-local` — full local reproduction of CI

CI additionally runs clang-tidy, ASan+UBSan (+TSAN), gitleaks,
helm-render and the OpenAPI-drift gate. Trivy runs in release.yml on tags.

## Don'ts

- Don't edit the `builtin-baseline` in `vcpkg.json` or `ARG VCPKG_REF` in
  `docker/Dockerfile` by hand — Renovate owns them, and a baseline bump
  rebuilds the entire dependency world (now twice: plain + TSan tree).
- Don't point the `tsan` job back at `build/vcpkg_installed`. TSan is only
  sound against dependencies compiled with `-fsanitize=thread` — it can't see
  Abseil/RE2 synchronising through raw atomics and reports phantom races in
  `absl::synchronization_internal`. The job builds the `tsan-builder` stage,
  which links the separate instrumented tree produced by `tsan-deps` from
  `triplets/x64-linux-tsan.cmake`. ASan/UBSan reusing the plain tree is fine
  and intentional.
- Don't weaken `config/config.production.json` — `make prod-check` gates it.
- Don't change the error-response shape without updating `docs/openapi.yaml`.

## Self-maintenance

When a PR adds or changes a CI gate, scaffolding script, or invariant,
update this file in the same PR.
