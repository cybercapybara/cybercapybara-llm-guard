# Configuration reference

Every knob has three ways in, tried in order:

1. **Environment variable** (highest priority — for containers).
2. **`config/config.json`** value, with `${VAR}` / `${VAR:-default}` expansion.
3. **Built-in default** baked into the code.

Set `CONFIG_FILE` to point at a different JSON file (e.g. a per-environment
profile).

---

## App

| Env | JSON key | Type | Default | Notes |
|---|---|---|---|---|
| `APP_ENV` | `app.env` | string | `development` | `production` / `prod` arms the boot-time production-safety warnings in `Core::validate_config` |

## Server

| Env | JSON key | Type | Default | Notes |
|---|---|---|---|---|
| `SERVER_HOST` | `server.host` | string | `0.0.0.0` | Listen address |
| `SERVER_PORT` | `server.port` | int | `8080` | |
| `SERVER_THREADS` | `server.threads` | int | `0` (auto = #cores) | Drogon event-loop threads. Under the **synchronous** pqxx model the in-flight DB-call count is capped by THIS, not by `database.pool_size` — it's the real concurrency knob. `0`/unset auto-sizes to the CPU count; keep `database.pool_size` ≥ threads (the app warns at boot if not). |
| `SERVER_MAX_BODY_BYTES` | `server.max_body_bytes` | int | `10485760` | 10 MB cap on request bodies — prevents memory blow-up from a single client. Bump for file uploads. |
| `SERVER_SSL_ENABLED` | `server.ssl.enabled` | bool | `false` | Off by default — production terminates TLS at the ingress/reverse proxy (the Helm chart assumes this). Exposing the app directly (bare-metal, no proxy)? set `true` + cert/key, else traffic is plain HTTP. |
| `SSL_CERT_FILE` | `server.ssl.cert` | string | — | PEM cert path when SSL on |
| `SSL_KEY_FILE` | `server.ssl.key` | string | — | PEM key path when SSL on |
| `SHUTDOWN_PRE_STOP_DELAY_SEC` | `shutdown.pre_stop_delay_sec` | int | `5` | Seconds between "readiness = 503" and Drogon quit |

## API & middleware

| Env | JSON key | Type | Default | Notes |
|---|---|---|---|---|
| `CORS_ALLOWED_ORIGINS` | `cors.allowed_origins` | csv | — | Empty disables CORS |
| `SECURITY_HSTS` | `security.hsts` | bool | `false` | Emit `Strict-Transport-Security`. Only meaningful over HTTPS |
| `SECURITY_HSTS_MAX_AGE` | `security.hsts_max_age` | int | `31536000` | HSTS `max-age`, in seconds |

## Docs / Swagger UI

| Env | JSON key | Type | Default | Notes |
|---|---|---|---|---|
| `DOCS_ENABLED` | `docs.enabled` | bool | `false` | Mount `/api/docs` + `/api/openapi.yaml` — dev only |
| `DOCS_OPENAPI_PATH` | `docs.openapi_path` | string | `docs/openapi.yaml` | Path served at `/api/openapi.yaml` |

## Observability

| Env | JSON key | Type | Default | Notes |
|---|---|---|---|---|
| `LOG_NAME` | `logging.name` | string | `llm_guard` | |
| `LOG_FILE` | `logging.file` | string | `logs/app.log` | |
| `LOG_LEVEL` | `logging.level` | enum | `info` | trace/debug/info/warn/error/critical |
| `LOG_FORMAT` | `logging.format` | enum | `text` | `text` (human) or `json` (one JSON object per line for Loki/ELK) |
| `METRICS_ADDRESS` | `observability.metrics_address` | string | `0.0.0.0:9090` | |
| `SERVICE_NAME` | `observability.service_name` | string | `llm_guard_service` | Also emitted as `service` field in JSON logs |
| `OTLP_ENDPOINT` | `observability.otlp_endpoint` | string | — | OTLP HTTP traces endpoint. Empty + `trace_stdout=false` → no-op tracer |
| `TRACE_STDOUT` | `observability.trace_stdout` | bool | `false` | Synchronous stdout span exporter for debugging. When `OTLP_ENDPOINT` is empty and this is off, tracing is a no-op |

## Database

| Env | JSON key | Type | Default | Notes |
|---|---|---|---|---|
| `DATABASE_PRIMARY_URL` | `database.primary` | string | `postgresql://localhost:5432/appdb` | Connection string |
| `DATABASE_REPLICA_URLS` | `database.replicas` | csv | — | Read replicas |
| `DB_POOL_SIZE` | `database.pool_size` | int | `10` | Per-pool connections (primary + each replica). Keep ≥ `server.threads`: a smaller pool makes IO threads queue on `acquire()`; a much larger pool leaves the extra connections inert (and the `db_pool` saturation gauge under-reports). |
| `DB_ACQUIRE_TIMEOUT_MS` | `database.acquire_timeout_ms` | int | `5000` | |
| `DB_STATEMENT_TIMEOUT_MS` | `database.statement_timeout_ms` | int | `30000` | Per-connection PostgreSQL `statement_timeout`. `0` disables. |
| `DB_MIGRATIONS_ENABLED` | `database.migrations_enabled` | bool | `true` | Set `false` when init-container runs them |
| `DB_MIGRATIONS_DIR` | `database.migrations_dir` | string | `migrations` | |
| `DB_RETRY_MAX_ATTEMPTS` | `database.retry.max_attempts` | int | `3` | |
| `DB_RETRY_BASE_DELAY_MS` | `database.retry.base_delay_ms` | int | `100` | |
| `DB_RETRY_MAX_DELAY_MS` | `database.retry.max_delay_ms` | int | `2000` | |
| `DB_RETRY_JITTER` | `database.retry.jitter` | bool | `true` | Full-jitter backoff |
| `DB_REPLICA_LAG_METRIC_REFRESH_SEC` | `database.replica_lag_metric_refresh_sec` | int | `15` | Refresh interval for the `db_replica_lag_seconds` gauge. Only registered when read replicas are configured (primary has no replay timestamp). |

For individual Postgres URL components used by the sample config:
`DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`.

### Read replicas and `DB_POOL_SIZE`

Setting `DATABASE_REPLICA_URLS` routes most reads to a replica, but some paths
deliberately read from the **primary** to get read-after-write consistency (via
`Database::execute_read_primary`) regardless of the replica config — a
read-back after a mutation, and `--verify-migrations`. Budget the primary
`DB_POOL_SIZE` for request handlers **plus** any off-loop work, even when
replicas absorb the bulk of reads.

## Cache (Redis)

| Env | JSON key | Type | Default | Notes |
|---|---|---|---|---|
| `REDIS_URL` | `cache.url` | string | `tcp://127.0.0.1:6379` | Standalone mode |
| `REDIS_PASSWORD` | `cache.password` | string | — | |
| `CACHE_POOL_SIZE` | `cache.pool_size` | int | `10` | |
| `REDIS_USE_SENTINEL` | `cache.use_sentinel` | bool | `false` | |
| `REDIS_MASTER_NAME` | `cache.sentinel.master_name` | string | `mymaster` | |
| `REDIS_SENTINEL_NODES` | `cache.sentinel.nodes` | csv | — | `host:port,host:port,...` |
| `REDIS_SENTINEL_PASSWORD` | `cache.sentinel.password` | string | falls back to `REDIS_PASSWORD` | |
| `REDIS_SOCKET_TIMEOUT_MS` | `cache.socket_timeout_ms` | int | `500` | Per-command timeout; tighten under low-latency hot paths, loosen for large values / EVAL. |
| `REDIS_POOL_WAIT_TIMEOUT_MS` | `cache.pool_wait_timeout_ms` | int | `500` | Max wait for a free connection from the pool. |

For URL components: `REDIS_HOST`, `REDIS_PORT`.

## Conventions

- `csv`: comma-separated values, no spaces around commas. Empty components dropped.
- `enum`: invalid values fall back to the default, never throw.
- Passwords and secrets must never be committed to `config/*.json` — use `${VAR}`
  placeholders so the checked-in file stays safe.
- Config files live under `/app/config` in the Docker image; mount a volume or
  set `CONFIG_FILE` to point at something else.

## Local override pattern

```bash
# config/local.json (gitignored)
{
  "server":   { "port": 8081 },
  "database": { "pool_size": 4 }
}

CONFIG_FILE=config/local.json ./llm_guard
```
