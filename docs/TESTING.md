# Testing

What the test suite does and does not cover, and how to run each part. The goal
is that "the suite is green" means something specific — not "N passed, most of
them skipped."

## Buckets

| Bucket | Count | Needs | Runs with | What it covers |
|---|---:|---|---|---|
| **unit** | — | nothing (sidecar-free) | `make test-unit` | Pure logic: config resolution, validation, base64, path normalization, retry/backoff, trace-context parsing, the health registry, metrics wiring. |
| **integration** | — | Postgres + Redis | `make test` | The connection pool against a real Postgres, the cache against a real Redis, the migration runner, Core boot/shutdown. |
| **api** | — | Postgres + Redis | `make test` | Controller request/response behavior wired through the real handler stack (health + endpoint discovery). |
| **e2e** | 1 | Postgres + Redis | `make test-e2e` | A real Drogon server + client on the wire: `GET /healthz` end to end. Kept alive as the harness the proxy suites plug into. |

`make test-unit` is the fast, dependency-free loop;
`make test` brings up sidecars and runs unit + integration + api; `make test-e2e`
runs the wire-level suite. `make ci-local` runs the lot the way CI does.

## Coverage

`make coverage` builds with instrumentation and runs **all** buckets, so the
number reflects the DB/cache code too — not just unit-reachable lines.
The integration and e2e buckets need Postgres + Redis (`make up` first); without
them those buckets are skipped and the reported coverage drops accordingly.

## Known gaps (be honest about these before you rely on them)

- **No behavioral coverage** for Postgres streaming replication or Redis
  Sentinel failover. These have lifecycle/health guards only — wiring, not
  behavior.
- **Sanitizers (ASan/UBSan)** currently cover the **unit** bucket only. Compiling
  the integration TUs under ASan OOM'd an 8 GB build VM (heavy header-only TUs,
  no shared object file); extending it is deferred until the bodies are extracted
  into a single compiled `app_core` object (see `docs/adr/0003-header-only-modules.md`).
