# Cybercapybara LLM Guard — design specification

Date: 2026-08-14
Status: approved

## 1. What we are building

**Cybercapybara LLM Guard** (`llm-guard`) is a C++20 rewrite of
[cloud-ru-tech/guardrails-llm-filter](https://github.com/cloud-ru-tech/guardrails-llm-filter)
(Go, Apache-2.0, v0.1.2) on the stack of
[moveeeax/cpp-rapid-rest-template](https://github.com/moveeeax/cpp-rapid-rest-template)
(Drogon / C++20). Full functional parity with the original, own branding,
MIT license with third-party attribution.

It is a transparent reverse proxy between LLM clients and an LLM provider.
Clients change only their base URL. On the way to the model, ~265 RE2 regex
rules plus checksum validators replace detected sensitive values (PII, credentials,
API keys, tokens, IPs) with placeholders like `<EMAIL_1>`; on the way back —
including SSE streaming token-by-token and tool-call arguments — placeholders
are replaced with the originals. The model never sees sensitive data; the
client never sees placeholders.

Two hard invariants, preserved verbatim from the original:

1. **Mask or pass — never block.** There is no reject verdict anywhere in the
   pipeline.
2. **Fail-open on the data path.** Any internal error (parse failure, mask
   error, unknown format, store error, bad rule) forwards/relays traffic
   unchanged rather than breaking it.

### Approved decisions

| Decision | Choice |
|---|---|
| Scope | Full parity: proxy + SSE demasking + rules engine + config API + web console + audit + in-memory/Redis/Postgres stores |
| Branding | Own: binary `llm-guard`, env prefix `LLMGUARD_`, metrics namespace `llmguard`, image `ghcr.io/cybercapybara/cybercapybara-llm-guard` |
| Rules catalog | Ported from the original with Apache-2.0/MIT attribution (`THIRD_PARTY_NOTICES.md`, `NOTICE`); project license MIT |
| Management API | REST only (no gRPC), OpenAPI 3.1 spec, template error shape |
| Process model | One binary, three listeners (8080 data / 9080 management+console / 9090 metrics) |
| Management auth | None by default (in-cluster API); `LLMGUARD_API_TOKEN` enables a static bearer check on the management port |
| Console | Template frontend stack (Vite + React + TS + Tailwind + shadcn/ui + TanStack Query + openapi-typescript), 6 pages of the original |
| Upstream client | libcurl on a dedicated worker pool (thread per in-flight upstream request), one code path for JSON and SSE |

## 2. Template instantiation and cleanup

Instantiate with `./scripts/init-project.sh --no-demo`, then strip the
template's demo domain aggressively — dead code is the enemy of a quality
codebase:

**Removed:** account/auth domain (users, roles, admin, sessions, cookies,
CSRF, API keys, email/Mailer/inja, libsodium), jobs/DLQ/worker, Kafka
(librdkafka), webhooks, storage (S3/local), posts/uploads/content pages,
idempotency, rate limiter, and their migrations, tests, Helm values, compose
services, and OpenAPI blocks.

**Kept:** Config (JSON + env override + `${VAR}` interpolation), observability
(spdlog, prometheus-cpp, OTel optional), health registry + graceful shutdown,
Retry, Database (libpqxx pool + migrations runner), Cache (redis-plus-plus),
error shape `{error, status, message}`, `Api::Validation`, Endpoints registry +
OpenAPI drift gates, CI workflows (build/test, clang-format/tidy, sanitizers,
gitleaks, Trivy, helm-render), Helm charts (api + frontend, adapted), release
pipeline, frontend scaffolding, Makefile dev workflow.

Template invariants that continue to apply: header-only `src/` (only
`main.cpp`), route triple-sync (controller ↔ `Endpoints.hpp` ↔
`docs/openapi.yaml`), test buckets by directory, conventional commits, no
secrets in tracked files.

**Adaptation:** the template initializes Postgres and Redis unconditionally;
here only the selected store backend is initialized (`in_memory` needs
neither).

New vcpkg dependencies: `re2`, `yaml-cpp`; later `toml11` (rulesgen).

## 3. Process architecture

One Drogon process, three ports:

| Port | Env | Surface |
|---|---|---|
| `:8080` | `LLMGUARD_LISTEN_ADDR` | data plane: gateway catch-all + `GET /healthz`, `GET /readyz` |
| `:9080` | `LLMGUARD_API_ADDR` | management REST `/v1/*` + embedded SPA console at `/` |
| `:9090` | `LLMGUARD_METRICS_PORT` | Prometheus `/metrics` (prometheus-cpp exposer) |

Drogon's routing table is global across listeners, so a port-guard
middleware dispatches by local port: management routes 404 on the data port
and vice versa. Empty `LLMGUARD_API_ADDR` disables the management listener.

The masking core is a pure header-only library `src/guard/` with zero HTTP
dependencies; the gateway and the API are thin adapters over it.

### Upstream client

libcurl (already an OS dependency of the template) on a dedicated worker
pool — one thread per in-flight upstream request, pool size configurable.
Rationale: `drogon::HttpClient` buffers whole responses and cannot deliver
the body incrementally, which SSE demasking requires; curl's write callback
gives byte-level streaming with one code path for buffered JSON and SSE.
LLM streams are long-lived but number in the hundreds, not tens of
thousands — thread-per-request is honest and simple. Connection pooling via
curl share/handle reuse; response-header timeout (`LLMGUARD_UPSTREAM_TIMEOUT`,
default 120s) deliberately does not bound streaming bodies, whose lifetime
follows the client connection. TLS verification on by default;
`LLMGUARD_UPSTREAM_INSECURE_SKIP_VERIFY` opt-out for local testing only.
Chunks flow to the client through Drogon's async stream response with a
flush per SSE frame.

## 4. Rules engine (`src/guard/`)

Direct port of the Go engine preserving every security-relevant behavior.

### 4.1 Rule model and YAML

```
rule_id, name, group (inherited), data_type (inherited),
regex (RE2, compiled with "(?m)" prefix),
keywords[] (lowercased at load), validators[], min_length, entropy,
banlist[] (lowercased), default_on,
masking { capture_groups []int (1-based; empty = full match), placeholder }
```

YAML catalogs (ported as-is, with attribution):

- `configs/rules.yaml` — 46 hand-written rules in 5 groups: CREDENTIALS (13),
  API_KEYS (2), ACCESS_TOKENS (6), IP_ADDRESSES (8), PERSONAL_DATA (17 —
  Russian FIO ×3, phone, email, SNILS, passport, KPP, address, INN ×2,
  OGRN, OGRNIP, credit card ×2, IBAN, CVC).
- `configs/rules.gitleaks.generated.yaml` — 220 generated rules in 3 groups
  (CREDENTIALS 42, API_KEYS ~78, ACCESS_TOKENS ~100), derived from the
  vendored `configs/gitleaks.toml`.

Loader dedupes file paths and errors on duplicate `rule_id` across files.

Data types: `1 CREDENTIALS, 2 API_KEYS, 3 ACCESS_TOKENS, 4 IP_ADDRESSES,
5 PERSONAL_DATA, 6 CUSTOM`. Names accepted case-insensitively wherever
numbers are.

### 4.2 Registry

- `CompileRule` is the **single validation path** shared by file loading and
  API create/update: non-empty id (`^[a-z0-9_.-]{1,128}$`), no duplicate id,
  known validators, regex compiles under RE2 with `(?m)`, capture-group
  indices ≤ group count, and a derived **placeholder recognition regex**.
- Placeholder recognition regex: for `EMAIL` →
  `(?i)<\s{0,3}EMAIL[\s_-]{0,3}([0-9]{1,9})\s{0,3}>` (tolerant of model
  drift: case, spacing, `-` vs `_`; multi-token names split on `_`). Must be
  length-bounded; the bound (computed by walking the RE2 parse tree) becomes
  `placeholder_len` and sizes the SSE demasker's pending buffer.
- Indexes: `by_id`, `by_data_type`. Snapshot type is immutable; reload swaps
  an `std::atomic<std::shared_ptr<const Registry>>`. `ResolveForDataTypes`
  pins one snapshot for rule IDs and compiled rules together, so a
  concurrent swap can never drop a rule mid-request.
- **RE2 is load-bearing**: the catalog is written for RE2 semantics
  (ASCII-only `\b`, no lookaround — Cyrillic rules use explicit
  `[^ЁА-Яёа-я]` guards) and RE2's linear-time guarantee structurally
  excludes ReDoS. A backtracking engine is not an acceptable substitute.

### 4.3 Validators (16)

`luhn, snils, inn_person, inn_org, ogrn, ogrnip, iban_mod97, email_ascii,
payment_card, payment_card_no_luhn, entropy, banlist, ip_v4, ip_v6,
ip_public, ip_private`. All configured validators must pass (AND). Digits
stripped of non-digits before numeric checks. Ported with the original's
exact weight tables (SNILS mod-101, INN weights, OGRN/OGRNIP mod-11/13,
IBAN mod-97), payment-card brand/length table, RFC-ish ASCII email shape,
Shannon entropy with ASCII fast path, private/local IP classification
(private ∪ loopback ∪ multicast ∪ link-local ∪ unspecified).

### 4.4 Scanner

1. Optional recall-preserving keyword prefilter (see 4.6).
2. Per rule: find all matches; semantic span = first valid configured
   capture group, else full match; drop if empty, shorter than
   `min_length`, or failing validators.
3. Parallel fan-out across hardware threads only when text ≥ 4096 bytes and
   rules > 4; a worker failure converts to an error → caller fails open.
4. **Overlap coalescing into the union span** `[minStart, maxEnd)`
   attributed to the longest constituent. Deliberate: dropping the shorter
   match would emit its non-overlapping bytes verbatim and leak part of a
   detected secret. Output sorted, non-overlapping.

### 4.5 Masker

- Phase A: scan all texts against the pinned snapshot (text-level fan-out
  when combined size ≥ `LLMGUARD_MASK_PARALLEL_MIN_BYTES`, default 8192).
  First error aborts → fail open.
- Phase B: mask **sequentially in text order** through one masker so
  placeholder numbering and cross-text dedup are deterministic.
- Same original → same placeholder across all texts (recorded once in
  `replacements`). Per-type counters.
- **Collision guard**: pre-scan input for literal `<[A-Za-z0-9_]+_[0-9]+>`
  tokens; the counter skips any value whose rendered placeholder collides,
  so demasking can never corrupt a user-supplied lookalike.
- Output `MaskingState { triggered_rule_ids (sorted), triggered_data_types
  (sorted), replacements[{rule_id, original, placeholder}], format }`.

### 4.6 Keyword prefilter (recall-preserving, off by default)

A rule's keywords may skip the scan **only if the regex provably guarantees
at least one keyword in every match** — proven by walking the RE2 parse
tree (literal contains keyword; concat: any child; alternate: all branches;
plus/repeat(min≥1)/capture: recurse; star/quest/charclass/anchors: false).
Case-folded literals whose Unicode fold orbit doesn't round-trip through
lowercasing (ς, ſ) are refused. Anything not provable is always scanned —
degradation is safe by construction. Ineligible rule IDs logged at startup.

### 4.7 Demasker

Request-scoped factory built from `MaskingState`: exact replacement pass
(verbatim + JSON-escaped originals), then tolerant placeholder-regex pass
applied left-to-right by byte offsets. `max_pending = max(longest
placeholder literal, max placeholder-regex bound over triggered rules)`.

`DemaskChunk(chunk, flush)`: prepend pending; replace; if not flushing,
hold back the last `max_pending` bytes trimmed to a UTF-8 rune boundary
(a placeholder straddling a chunk boundary is never split); **on error
return the un-emitted buffer together with the error** — every caller must
emit it as the lossless fail-open fallback. A JSON variant escapes restored
originals for insertion into JSON-string contexts (tool-call fragments),
with HTML escaping disabled so `<EMAIL_1>` survives.

## 5. JSON handling (`src/guard/json/`)

**Surgical byte-splicing, not parse/re-serialize.** A minimal streaming
JSON scanner that, for the needed paths, returns **byte spans** of values
inside the raw body; patching splices replacement bytes in place. This is
the C++ equivalent of gjson/sjson and preserves the original guarantee: all
unmodeled fields, key order, number formatting, and `<`/`>` in placeholders
survive byte-for-byte. Utilities: JSON string escape/unescape (no HTML
escaping), validity check.

Tool-call arguments (`.arguments` — a JSON string holding an object;
`.input` — a raw object): naive raw substitution first; if the result is
not valid JSON, a **structural fallback** — parse, demask each string leaf,
re-marshal without HTML escaping, numbers preserved verbatim. If even that
fails, keep the masked value (never emit an unescaped original that breaks
the JSON).

### Content extraction (three wire formats)

Extraction returns `{path/span, decoded string}`; sentinel "unsupported
body schema" triggers fail-open + counter.

- **`chat_completions`** (OpenAI): requires `messages[]` (else unsupported).
  Request: `messages[i].content` (string), `messages[i].content[j].text`
  (`type=="text"`), `messages[i].function_call.arguments`,
  `messages[i].tool_calls[j].function.arguments`. Response: per
  `choices[i].message`: `content`, `reasoning`, `reasoning_content`,
  `refusal`, `function_call.arguments`, `tool_calls[j].function.arguments`.
- **`messages`** (Anthropic): top-level `system` (string or text blocks),
  `messages[i].content` (string or blocks): `text` → `.text`; `tool_use` →
  every **string leaf** inside `input` (depth-first, path-escaped keys,
  non-string leaves skipped); `tool_result` → content string or nested text
  parts. Response: `text` → `.text`, `thinking` → `.thinking` (signature
  untouched), `tool_use` → raw `input` object; `redacted_thinking` and
  unknown block types pass through byte-identical. Never errors — malformed
  bodies yield nothing.
- **`responses`** (OpenAI Responses): requires `input` or `instructions`.
  Request: `instructions`, `input` (string), `input[i].content[j].text`
  (`input_text|output_text|text`), `input[i].arguments` (`function_call`),
  `input[i].output` string / `output[j].text` (`function_call_output`);
  skips `input_image`/`input_file`, `item_reference`, `reasoning` items.
  Response: `message` → `content[j].text` (`output_text`); `function_call`
  → `arguments`; `reasoning` → `summary[j].text` + `content[j].text`;
  `encrypted_content` never touched.

Streaming intent = top-level `"stream": true` (same field in all three).

## 6. SSE processing (`src/guard/sse/`)

Response is SSE if `Content-Type` contains `text/event-stream`, **or** the
request had `"stream": true` and the response is not `application/json`
(mislabeled upstreams). Read in 32 KiB chunks; every client write is
followed by a flush.

Shared machinery: frame splitting on `\n\n` / `\r\n\r\n` with carried tail;
line classification (`data:` with/without space, multi-line `data:` joins;
event/done/passthrough); frame building; JSON marshal without HTML
escaping; `JSONCloseTracker` — a brace-depth tracker carrying
string-literal and escape state across fragments so an in-string `}` never
triggers a premature flush.

Three dialect processors implementing `process_chunk(body, end_of_stream)`:

- **chat_completions** — the hardest piece (761 lines Go, 3823 lines of
  tests). Demaskers keyed by `(choice_index, tool_call_index, field)`,
  field ∈ `content|reasoning|tool_arguments`, `tool_call_index = -1` for
  legacy `function_call`. Aggregator holds merged chunk metadata (id,
  model, created, fingerprint) so re-emitted frames stay well-formed.
  First content delta flushes the reasoning demasker. Tool-call fragments
  use the JSON demasker, flushed when `JSONCloseTracker` closes. A combined
  content+finish frame is split into demasked content frames (finish/usage
  nulled) plus a metadata-only frame. Role-only / refusal / audio /
  keepalive deltas pass verbatim and **must not** flush demaskers. `[DONE]`
  flushes everything; end-of-stream without `[DONE]` also flushes.
- **messages** — `content_block_start` records block type
  (`text|thinking|tool_use|redacted_thinking`); `content_block_delta`
  handles `text_delta.text`, `thinking_delta.thinking`,
  `input_json_delta.partial_json` (JSON demasker); `content_block_stop`
  flushes. `message_start`/`ping`/`message_delta`/`message_stop` pass
  byte-for-byte.
- **responses** — handles `response.output_text.delta/.done`,
  `response.content_part.done`, `response.reasoning_text.delta/.done`,
  `response.reasoning_part.done`,
  `response.function_call_arguments.delta/.done`,
  `response.output_item.done`, `response.completed/.incomplete/.failed`.
  Snapshot events re-send full accumulated text → demasked with a fresh
  one-shot demasker. The processor owns the outgoing `sequence_number`
  space (it inserts synthetic frames) and tracks `item_id` per key.

Unknown/empty format → byte-identical passthrough + counter. Each
processor optionally records pre-demask text per stream key (first-seen
order, tool fragments excluded) for the audit trail.

**Porting order: test corpus first, implementation second.**

## 7. Data plane gateway (`src/gateway/`)

Per request: resolve path → format; read body (cap
`LLMGUARD_MAX_REQUEST_BYTES`, default 32 MiB, 413 on overflow, 0 disables);
extract; scan+mask; patch; forward; demask response (full body, or
frame-by-frame for SSE); optional audit record. The placeholder→original
table lives in process memory for the request lifetime — no store on the
data path.

- Path matching: query stripped; exact match first, then longest suffix
  over configured keys (keys start with `/`, so suffix matches are
  segment-anchored: `/openai/v1/chat/completions` works with zero config).
  Defaults: `/v1/chat/completions → chat_completions`, `/v1/messages →
  messages`, `/v1/responses → responses`. `LLMGUARD_PATHS` merges **on top
  of** defaults (a partial override can never disable a core path). Only
  POST/PUT/PATCH bodies are masked. Any other path → transparent
  passthrough + counter.
- Headers: client `Authorization` forwarded verbatim; hop-by-hop headers
  stripped both directions (`Connection`, `Proxy-Connection`, `Keep-Alive`,
  `Proxy-Authenticate`, `Proxy-Authorization`, `Te`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`, plus anything named in `Connection`);
  `Accept-Encoding: identity` forced upstream when demasking is active;
  `Content-Length` dropped when demasking.
- Trusted narrowing header `x-llmguard-data-types`
  (`LLMGUARD_OVERRIDE_HEADER`): consumed, never forwarded; **narrow-only**
  (intersection with global types; can never widen); `none` → skip masking;
  unparsable → ignored entirely (full protection); empty intersection →
  skip. Documented as trusted — strip it at a fronting gateway if exposed
  to untrusted clients.
- `X-Request-Id` keys the audit record (UUID fallback); model from body
  `model`, fallback header `X-Gateway-Model-Name`.
- Modes: **enforce** (mask, forward, demask) and **detect** (shadow: scan +
  metrics + audit, traffic untouched). Everything else (unguarded path,
  unparsable body, mask error, zero findings, disabled, empty data types,
  empty body) forwards verbatim.
- Upstream base URL: `LLMGUARD_UPSTREAM_BASE_URL` (required); per-path
  overrides `LLMGUARD_UPSTREAM_PATH_BASE_URLS` (`path=url` pairs,
  comma-separated).
- Health: `/healthz`, `/readyz` — two atomic flags set at end of startup;
  readiness flips 503 on SIGTERM (template graceful-drain machinery).
  Readiness never probes the upstream; forward failures surface as
  per-request 502.

## 8. Management REST API (`:9080`)

Same contract as the original's REST surface (snake_case JSON, numeric
enums), errors in the template shape `{error, status, message}`:

| Endpoint | Semantics |
|---|---|
| `GET /v1/rules?source=all\|builtin\|custom` | invalid source → 400 |
| `POST /v1/rules` | 409 duplicate id (builtin or custom); 429 over `LLMGUARD_RULES_MAX_CUSTOM` |
| `GET /v1/rules/{rule_id}` | 404 unknown |
| `PUT /v1/rules/{rule_id}` | path id wins; builtin → 400 |
| `PATCH /v1/rules/{rule_id}` | `{"enabled": bool}` — the only mutation allowed on builtins |
| `PATCH /v1/rules` | bulk enable/disable, 1..1000 ids, best-effort per-item results |
| `DELETE /v1/rules/{rule_id}` | also clears the disabled flag |
| `GET/PUT /v1/settings` | `{enabled, data_types[], mode}` |
| `GET /v1/data-types` | groups from YAML (deduped) + synthetic CUSTOM |
| `POST /v1/scan` | sandbox dry-run: `{texts[]\|text, data_types[], candidate_rule}` → masked texts, triggered ids/types, placeholders, total_ms |
| `GET /v1/audit/records` | filters `model,path,ruleId,dataType,since,until,limit,cursor`; keyset pagination |
| `GET /v1/audit/records/{request_id}` | 404 unknown; 400 when audit disabled |
| `GET /v1/version` | `{version, commit, date, mode, store_backend, topology:"standalone"}` |
| `GET /v1/health` | `{status, mode, store_backend}` |
| `GET /v1/metrics/summary` | console aggregates: masked totals, top-20 rule/type triggers, passthrough counters, p50/p95 latency interpolated from histograms |

Error semantics: validation → 400, not found → 404, duplicate → 409, too
many rules → 429, builtin mutation → 400, audit disabled → 400, internal →
500 with a generic message (store internals never leak). Custom rules are
validated through the same `CompileRule` path as builtins and take effect
without restart (reload tick). Custom rule ids shadowing a builtin are
skipped with a warning at merge.

Auth: none by default; `LLMGUARD_API_TOKEN` set → require
`Authorization: Bearer <token>` on `/v1/*` (constant-time compare); the
SPA static assets stay public.

OpenAPI 3.1 in `docs/openapi.yaml`, held by the template's drift gate; the
console generates its TS types from it.

## 9. Stores and settings

Store interface covers: custom rules (CRUD + disabled flags), settings
(singleton), audit records (put/get/list with keyset cursor). Backends:

- **in_memory** — mutex-guarded maps + a 1-minute janitor evicting expired
  audit entries; `LLMGUARD_AUDIT_MAX_ENTRIES` (default 10000) evicts oldest.
- **redis** — template Cache client; keys `llmguard:rules` (hash),
  `llmguard:rules:disabled` (set), `llmguard:settings`,
  `llmguard:audit:rec:<id>`, `llmguard:audit:idx` (sorted set);
  client-side audit filtering with a bounded index scan.
- **postgres** — template Database + migrations runner (replacing the
  original's bootstrap DDL): tables `rules`, `disabled_rules`, `settings`
  (singleton row `CHECK (id = 1)`), `audit` (denormalized ts/model/path/
  rule_ids[]/data_types[] + JSONB record; GIN on rule_ids;
  `(ts DESC, request_id DESC)` index).

Only the selected backend is initialized. Audit pagination: cursor =
`base64url("<unixNano>:<request_id>")`, order `(ts DESC, request_id DESC)`,
page default 50 max 500.

Optional encryption at rest (`LLMGUARD_STORE_ENCRYPTION_ENABLED` +
base64 32-byte `LLMGUARD_STORE_ENCRYPTION_KEY`): AES-256-GCM (OpenSSL)
JSON envelope `{"_enc":"aes256gcm","v":1,"data":"<base64(nonce||ct)>"}`.
Envelope detection by the `_enc` key (JSONB-reorder safe); rolling enable
(AES codec accepts legacy plaintext; plain codec seeing an envelope returns
a distinct undecryptable error, not a silent 404).

**Settings service**: env values seed the store once
(`SaveSettingsIfAbsent` with race re-read); thereafter the store is the
source of truth, cached in an atomic pointer, re-read every
`LLMGUARD_SETTINGS_REFRESH_INTERVAL` (30s). **Rules reload**: builtins +
stored custom − disabled → build → atomic swap every
`LLMGUARD_RULES_REFRESH_INTERVAL` (30s); on failure keep the last good
snapshot. Both tickers on the template's task scheduler.

**Audit recorder**: async and bounded — 128 in-flight, 5s per-write
timeout, 64 KiB text cap, drain on shutdown, drop + counter on saturation.
Optional storage of masked request/response texts and of originals
(`off|plain|encrypted`; `encrypted` requires store encryption). Retention
`LLMGUARD_AUDIT_RETENTION` (24h) via janitor.

**Deliberately not ported** (dead code in the standalone original,
documented in `docs/`): the masking-state store + TTL (`STORE_MASKING_TTL`)
— the standalone gateway never reads or writes it; the three `HEADERS_*`
triggered-rules response-header vars — parsed but never emitted.

## 10. Observability

- Metrics namespace `llmguard`, prometheus-cpp. All counters the original
  actually emits: `requests_masked_total{mode}`,
  `rule_triggers_total{rule_id}`, `data_type_triggers_total{data_type}`,
  `mask_failures_total`, `demask_failures_total{mode=full|sse}`,
  `audit_store_failures_total{op}`, `audit_records_dropped_total`,
  `unknown_format_passthrough_total`, `unguarded_path_passthrough_total`,
  `unsupported_body_schema_total`; histograms `mask_scan_duration_seconds`,
  `scan_duration_seconds`, `mask_texts_count`, `mask_scan_text_bytes`,
  `mask_scan_total_bytes`, `triggered_rules_count` (original bucket sets).
- **Improvement over the original**: actually observe
  `pipeline_duration_seconds`, `mask_duration_seconds`,
  `demask_duration_seconds` (declared but never written in Go, so its
  `/v1/metrics/summary` latency block is always zeros — ours will be live).
- Logging: spdlog, `LLMGUARD_LOG_LEVEL` / `LLMGUARD_LOG_FORMAT`
  (json|text). Log call metadata, never payloads or originals.
- Tracing: template OTel optional, off by default.
- Alerts + Grafana dashboard ported to `deploy/` (masking failures,
  demask failures, audit write failures/drops, masked-traffic spike,
  pipeline p99, scrape down).

## 11. Web console

6 pages — Overview, Rules, Tester, Settings, Audit, Monitoring — rebuilt on
the template's frontend stack (Vite + React 18 + TS + Tailwind + shadcn/ui +
TanStack Query + openapi-typescript from `docs/openapi.yaml`). Light/dark
theme. Same-origin: served by Drogon on the management port with SPA
fallback; built as a Docker stage and embedded in the single image (parity
with the original's `go:embed`); `LLMGUARD_UI_ENABLED=false` disables.
Vite dev server proxies `/v1` to `:9080`.

## 12. Rules generator (`rulesgen`)

Port of `pkg/gitleaksgen` as a CLI subcommand of the main binary
(`llm-guard --rules-gen --in configs/gitleaks.toml --out …`), using toml11:
skip empty/excluded (`generic-api-key`), per-rule regex overrides, RE2
compile check, capture-group override table, **boundary normalization**
(gitleaks' code-boundary class rewritten to the prompt-token class
`(?:[\x60'"\s,;:!?()\[\]{}]|\\[nr]|$)`), group classification
(credentials/api/access-keys heuristics), id scheme
`{type}.{gitleaks-id}.gl` with `_2` disambiguation, placeholder =
sanitized uppercase id, keywords + entropy carried over, sorted output.
Until the port lands (phase 8), the committed generated YAML is the
artifact of record with provenance documented. A CI test re-runs the
generator and asserts the committed file is current (as the original does).

## 13. Configuration reference

Env-first (`LLMGUARD_` prefix) over the template's JSON config file.
Mapping is 1:1 with the original's `GUARDRAILS_*` table:

Core: `LISTEN_ADDR :8080` · `UPSTREAM_BASE_URL` (required) ·
`UPSTREAM_TIMEOUT 120s` · `UPSTREAM_MAX_IDLE_CONNS 100` ·
`UPSTREAM_MAX_IDLE_CONNS_PER_HOST 100` · `UPSTREAM_IDLE_CONN_TIMEOUT 90s` ·
`UPSTREAM_PATH_BASE_URLS` · `UPSTREAM_INSECURE_SKIP_VERIFY false` ·
`MAX_REQUEST_BYTES 33554432` · `UPSTREAM_THREADS` (pool size, new).

Servers/logs: `LOG_LEVEL info` · `LOG_FORMAT json` · `METRICS_PORT 9090` ·
`API_ADDR :9080` (empty disables) · `UI_ENABLED true` · `API_TOKEN` (new,
optional bearer).

Policy seeds: `ENABLED true` · `MODE enforce|detect` ·
`DATA_TYPES 1,2,3,4,5,6` · `KEYWORD_PREFILTER_ENABLED false` ·
`MASK_PARALLEL_MIN_BYTES 8192` · `PATHS` (path:format pairs merged over
defaults) · `OVERRIDE_HEADER x-llmguard-data-types` ·
`SETTINGS_REFRESH_INTERVAL 30s` · `RULES_REFRESH_INTERVAL 30s`.

Rules: `RULES_REGEX_RULES_FILE ./configs/rules.yaml` ·
`RULES_GITLEAKS_REGEX_RULES_FILE ./configs/rules.gitleaks.generated.yaml` ·
`RULES_MAX_CUSTOM 500` · `RULES_MAX_PATTERN_LEN 4096`.

Store: `STORE_BACKEND in_memory|redis|postgres` · `STORE_REDIS_ADDR` ·
`STORE_REDIS_PASSWORD` · `STORE_REDIS_DB 0` · `STORE_POSTGRES_DSN` ·
`STORE_ENCRYPTION_ENABLED false` · `STORE_ENCRYPTION_KEY`.

Audit: `AUDIT_ENABLED false` · `AUDIT_STORE_MASKED_TEXTS false` ·
`AUDIT_STORE_MASKED_RESPONSE_TEXTS false` ·
`AUDIT_STORE_ORIGINAL_TEXTS off|plain|encrypted` · `AUDIT_RETENTION 24h` ·
`AUDIT_MAX_ENTRIES 10000`.

Dropped vs the original: `GRPC_ADDR`, `GRPC_SECURE` (no gRPC),
`STORE_MASKING_TTL`, `HEADERS_*` (dead code).

Boot validation (ported): non-empty path map, every path starts with `/`,
no whitespace, known formats; `MASK_PARALLEL_MIN_BYTES >= 0`;
`AUDIT_STORE_ORIGINAL_TEXTS` enum and `encrypted` ⇒ store encryption;
upstream URLs absolute http/https with host; unparsable `DATA_TYPES`/`MODE`
or duplicate rule ids fail startup.

## 14. Testing

Port the original's corpora rather than inventing new ones:

- **Rule corpus**: per-rule positive/negative cases (2142 lines in Go) →
  data-driven GoogleTest; generator-freshness test for the gitleaks file.
- **Engine units**: scanner (overlap coalescing, spans, validators,
  parallel), masker (dedup, collision guard, determinism), demasker
  (chunk-boundary placeholders, tolerant matching, error contract),
  prefilter fold-safety unicode edges, JSON span scanner/splicer.
- **SSE corpora**: chat_completions (the 3823-line corpus — frame splits at
  arbitrary boundaries, split placeholders, tool calls, metadata frames,
  fallbacks), messages, responses. Ported before the processors are
  written.
- **Gateway**: handler-level tests against a local mock upstream (Drogon
  test client), including 413, passthrough, detect mode, header hygiene.
- **Store conformance**: one shared suite run against all three backends
  (redis/postgres via the template's test sidecars; skipped without
  Docker).
- **E2E**: reuse the original's Python black-box harness (round-trip
  `demask(mask(x)) == x` across 3 APIs × {stream, non-stream}, no secret
  reaching upstream, no placeholder reaching the client, tool-argument
  JSON validity, 1-rune SSE fragmentation, mislabeled Content-Type, 413,
  override narrowing, detect mode, audit defaults); mock upstream
  rewritten as a small Python server with capture.
- **Benchmarks**: template bench harness for scan/mask throughput and
  parallel thresholds.

Test buckets per template convention (`tests/unit`, `tests/integration`,
`tests/api`, `tests/e2e`); `make ci-local` green is the merge gate.

## 15. Licensing

- Project: **MIT** (`LICENSE`).
- `NOTICE` + `THIRD_PARTY_NOTICES.md`: rules catalogs derived from
  cloud-ru-tech/guardrails-llm-filter (Apache-2.0) — include its NOTICE;
  gitleaks.toml from gitleaks (MIT); template third-party C++/npm tables
  updated for the final dependency set (re2 BSD-3, yaml-cpp MIT, toml11
  MIT, drogon MIT, etc.).
- The C++ code is a clean-room reimplementation informed by the original's
  behavior; the YAML/TOML rule content is ported verbatim under its
  original licenses.

## 16. Delivery phases

Each phase lands as a reviewed unit with tests green:

0. Template instantiation, cleanup, rebrand, LICENSE/NOTICES, first push.
1. Engine core: rule model, YAML loading, RE2 registry, validators,
   scanner, masker + rule corpus tests.
2. JSON spans, three format extractors, demasker.
3. SSE machinery + three processors (corpora first).
4. Gateway + upstream client + streaming relay + health.
5. Stores + settings/rules-reload services + audit.
6. Management REST + scan sandbox + metrics summary + bearer.
7. Web console.
8. Ops: Dockerfile, Helm, CI polish, alerts/dashboard, README + docs,
   benchmarks, rulesgen, e2e harness.

Risks called out for the implementation plans: the chat_completions SSE
processor is the single hardest piece (port its corpus first); RE2
parse-tree walking (placeholder-regex length bound, prefilter guarantee
proof) has no off-the-shelf equivalent; byte-span JSON patching must be
fuzzed against escape/unicode edges; Drogon async-stream responses and the
port-guard middleware are the template's least-exercised territory.
