# LLM Guard — Phase 0 (bootstrap) + Phase 1 (engine core) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Instantiate the C++ template as `llm-guard`, strip it to a lean base, and build the masking engine core (rules model, YAML loading, RE2 registry, validators, scanner, masker) with the ported rule corpus green in CI.

**Architecture:** The repo starts from `cpp-rapid-rest-template` (Drogon/C++20, header-only `src/`), stripped of its demo account/admin domain. The engine is a pure header-only library `src/guard/` with no HTTP dependencies, exercised by GoogleTest unit tests. Verification is **CI-only** (GitHub Actions on `cybercapybara/cybercapybara-llm-guard`) — no local builds.

**Tech Stack:** C++20, CMake + vcpkg, Drogon, nlohmann-json, **re2** (new), **yaml-cpp** (new), spdlog, prometheus-cpp, GoogleTest.

**Spec:** `docs/superpowers/specs/2026-08-14-llm-guard-design.md`

## Global Constraints

- **No local builds.** Every build/test verification happens in GitHub Actions. The dev loop is: write code + tests → commit → push branch → open/update PR → wait for CI → fix forward. Group commits so CI runs on meaningful checkpoints (per task or small task groups).
- Reference sources (read-only, NOT inside the repo):
  - Go original: `/Users/moveeeax/Public/cybercapybara/_reference/guardrails-llm-filter`
  - Template pristine copy: `/Users/moveeeax/Public/cybercapybara/_reference/cpp-rapid-rest-template`
- Header-only `src/` — the only `.cpp` is `src/main.cpp` (worker binary is removed).
- Route triple-sync: any route change touches controller + `src/api/Endpoints.hpp` + `docs/openapi.yaml` (CI drift gate).
- Test buckets by directory: `tests/unit/`, `tests/integration/`, `tests/api/`, `tests/e2e/`.
- Regex engine is **RE2 only** — never a backtracking engine. All rules compile with a `(?m)` prefix.
- Env prefix `LLMGUARD_`, metrics namespace `llmguard`, binary `llm-guard` (CMake/snake name `llm_guard`).
- Conventional commits; **no AI-attribution trailers** of any kind.
- License MIT; ported rule catalogs keep Apache-2.0/MIT attribution (NOTICE + THIRD_PARTY_NOTICES.md).
- Namespaces `Guard::` for the engine (template convention: CamelCase namespaces, lower_case functions, `_`-suffix private members, 120-col clang-format 17).
- All engine headers are self-contained (`#pragma once`, include what you use) and live under `src/guard/`.

## CI verification protocol

- Work happens on feature branches; merge to `main` only with green CI (`gh pr checks --watch`).
- Phase 0 branch: `chore/bootstrap` (Tasks 0.1–0.7, one PR). Phase 1 branches per task: `feat/guard-<topic>`.
- First CI run after touching `vcpkg.json` recompiles the dependency set (~30–40 min); later runs reuse the builder image published by `builder-cache.yml`. Do not panic at the first slow run.
- A CI failure on a merged-to-branch commit is fixed forward on the same branch (no force pushes after review starts).

---

# Phase 0 — bootstrap

### Task 0.1: Import the template tree

**Files:**
- Create: entire template tree copied into repo root (everything except `.git/`, `_reference/`).

**Steps:**

- [ ] **Step 1: Copy template into the repo**

```bash
cd /Users/moveeeax/Public/cybercapybara/cybercapybara-llm-guard
git checkout -b chore/bootstrap
rsync -a --exclude '.git' --exclude '_reference' \
  /Users/moveeeax/Public/cybercapybara/_reference/cpp-rapid-rest-template/ ./
git add -A && git status --short | head -30
```

- [ ] **Step 2: Sanity-check nothing collided**

`docs/superpowers/` (spec + this plan) must still exist alongside the template's `docs/`. Verify: `ls docs/ docs/superpowers/`.

- [ ] **Step 3: Commit**

```bash
git commit -m "chore: import cpp-rapid-rest-template v1.4.0"
```

### Task 0.2: Rebrand via init-project.sh

**Steps:**

- [ ] **Step 1: Run the rebrand script**

```bash
./scripts/init-project.sh --force --no-demo llm-guard ghcr.io/cybercapybara example.com
```

This renames `cpp-rapid-rest-template`→`llm-guard`, `cpp_api_template`→`llm_guard` (CMake project, binary, test target names), rebrands registry org to `cybercapybara`, host to `example.com`, renames Helm chart dirs, rewrites `project.env`, and fails loudly if any template/author token survived. `--no-demo` also strips `docs/PATTERNS-FROM-FLASK-BASE.md` and the README live-demo block.

- [ ] **Step 2: Verify zero surviving tokens**

```bash
grep -ri --exclude-dir=.git -l 'cpp-rapid-rest-template\|cpp_api_template\|tarassov\|moveeeax' . || echo CLEAN
```
Expected: `CLEAN` (the script self-checks, this is belt-and-braces). `docs/superpowers/` mentions of the template in prose are acceptable — exclude those two files from the check.

- [ ] **Step 3: Point SECURITY.md at GitHub advisories**

Edit `SECURITY.md`: replace the `security@example.com` contact with "Report vulnerabilities privately via GitHub Security Advisories on this repository."

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "chore: rebrand template as llm-guard"
```

### Task 0.3: Strip the demo domain — source tree

**Files:**
- Delete: `src/api/{Auth,Account,Admin,Audit,ApiKey,Posts,Upload,ContentPages}Controller.hpp`, `src/api/Guards.hpp`
- Delete: `src/security/` (whole dir: Auth, Jwt, ApiKeys, Password, Tokens, SessionStore, SessionCookies, Csrf, RateLimit, Idempotency, Audit)
- Delete: `src/email/`, `src/storage/`, `src/webhooks/`, `src/jobs/`, `src/messaging/`, `src/domain/`, `src/repositories/`
- Delete: `src/worker_main.cpp`
- Delete: `migrations/0*.sql` (all numbered migrations; keep `migrations/README.md`)
- Modify: `src/api/Api.hpp` (drop deleted controller includes; middleware chain keeps only: content-type check → cors → security headers → tracing-pre → access-log-post)
- Modify: `src/api/Endpoints.hpp` (registry keeps only `/`, `/healthz`, `/ready`, `/health`)
- Modify: `src/api/Middleware.hpp` (remove auth/csrf/rate-limit/idempotency middleware bodies)
- Modify: `src/core/Core.hpp` (init order drops security/jobs/email/messaging/storage; keep config → observability → validate → database → migrations → cache → tasks → health checks; `InitMode::Worker` removed)
- Modify: `src/main.cpp` (drop `--create-admin`; keep `--print-routes`, `--dump-config`, `--verify-migrations`, `--run-migrations`, `--help`)
- Modify: `CMakeLists.txt` (remove worker target and its PCH reuse; remove librdkafka/libsodium/inja/CURL-SMTP wiring; keep CURL linked — the upstream client will need it in phase 4)
- Modify: `vcpkg.json` (remove `librdkafka`; keep the rest)
- Modify: `docs/openapi.yaml` (only `/`, `/healthz`, `/ready`, `/health` remain)

**Interfaces:**
- Produces: a booting service exposing only health/meta routes; `Core::Application` with the trimmed init order; middleware chain without auth. Later phases add controllers back through the normal template flow.

**Steps:**

- [ ] **Step 1: Delete the listed files/dirs; make the listed modifications.** When editing `Api.hpp`/`Middleware.hpp`/`Core.hpp`, delete whole blocks — do not leave commented-out code. `utils/`, `cache/`, `database/`, `observability/`, `tasks/`, `api/{Api,Endpoints,Middleware,HandlerSupport,RequestUtils,Validation,HealthController}` stay.

- [ ] **Step 2: Strip tests of deleted modules.** Delete `tests/unit`, `tests/integration`, `tests/api`, `tests/e2e` files covering auth/jwt/sessions/cookies/csrf/rate-limit/idempotency/api-keys/jobs/dlq/kafka/email/webhooks/storage/posts/uploads/content/users/roles/admin/audit-log/password/tokens. Keep: config, strings, retry, error-response, request-utils, validation, health, observability/metrics/trace, database pool, migrations runner, cache, module guards (edit to reference only surviving modules), plus `tests/test_main.cpp`, `tests/test_helpers.hpp` (strip JWT/fixture helpers from `tests/test_fixtures.hpp` or delete it if empty), `tests/InMemoryCache.hpp`. Reduce `tests/e2e/` to one test: boot the server, `GET /healthz` over real HTTP → 200 `ok` (keeps the e2e harness alive for phase 4).

- [ ] **Step 3: Strip ops surface.** `docker/docker-compose.yml`: keep `app`, `postgres`, `redis`, monitoring profile services, `test-runner`/`test-postgres`/`test-redis`; delete worker/kafka/zookeeper/mailpit/replica/sentinel/frontend services and their `.env.*` presets. `Makefile`: remove targets referencing removed pieces (worker, kafka, frontend, jwt/dev-token, seed, new-resource/new-job scaffolding that targets the deleted domain — keep new-endpoint/new-migration). Helm: delete `helm/*-worker`, `helm/*-frontend`; keep the api chart + umbrella trimmed to api/postgres/redis/monitoring. CI: in `ci.yml` delete the `frontend` job; keep the rest. Delete `frontend/` entirely (console returns in phase 7 embedded via Drogon).

- [ ] **Step 4: Sweep for dangling references**

```bash
grep -rn --exclude-dir=.git --exclude-dir=docs -i \
  'jobs\|kafka\|webhook\|mailpit\|sodium\|inja\|argon\|worker' \
  src/ tests/ CMakeLists.txt vcpkg.json Makefile docker/ helm/ .github/ | grep -vi 'network\|framework' | head -40
```
Investigate every hit; delete or fix. Also run `scripts/check-routes-registered.sh`, `scripts/check-openapi-drift.sh`, `scripts/check-test-buckets.sh` mentally against the new tree (they are pure text checks — actually run them, they need no build).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "chore: strip template demo domain to lean base"
```

### Task 0.4: License, NOTICE, third-party attribution

**Files:**
- Modify: `LICENSE` (MIT, copyright holder: `Cybercapybara contributors`)
- Create: `NOTICE`
- Modify: `THIRD_PARTY_NOTICES.md`
- Modify: `README.md` (temporary skeleton), `CHANGELOG.md` (reset to `## [Unreleased]`)

**Steps:**

- [ ] **Step 1: Update LICENSE holder line** to `Copyright (c) 2026 Cybercapybara contributors` (keep MIT text).

- [ ] **Step 2: Create `NOTICE`:**

```
Cybercapybara LLM Guard
Copyright (c) 2026 Cybercapybara contributors

This product includes detection rule catalogs derived from
guardrails-llm-filter (https://github.com/cloud-ru-tech/guardrails-llm-filter),
Copyright Cloud.ru, licensed under the Apache License, Version 2.0.
Files: configs/rules.yaml, configs/rules.gitleaks.generated.yaml.

The generated catalog is additionally derived from gitleaks
(https://github.com/gitleaks/gitleaks), Copyright Zachary Rice,
licensed under the MIT License. File: configs/gitleaks.toml.
```

- [ ] **Step 3: Update `THIRD_PARTY_NOTICES.md`:** remove rows for deleted deps (librdkafka, libsodium, inja, flask-base attribution section); add rows: `re2` (BSD-3-Clause), `yaml-cpp` (MIT), and a "Rule catalogs" section repeating the NOTICE attribution with license texts.

- [ ] **Step 4: Reset `README.md`** to a short skeleton: project name, one-paragraph description (transparent masking proxy for LLM traffic, C++/Drogon), "Status: under active development — see docs/superpowers/specs/ for the design", license section (MIT + attribution pointer). The full README lands in phase 8.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "docs: MIT license, NOTICE and third-party attribution"
```

### Task 0.5: Port rule catalogs

**Files:**
- Create: `configs/rules.yaml` (from `_reference/guardrails-llm-filter/configs/guardrails_regex_rules.yaml`)
- Create: `configs/rules.gitleaks.generated.yaml` (from `.../guardrails_regex_rules.gitleaks.generated.yaml`)
- Create: `configs/gitleaks.toml` (from `.../configs/gitleaks.toml`)

**Steps:**

- [ ] **Step 1: Copy the three files byte-identical**, then add a 4-line comment header to each YAML: provenance URL, upstream commit (from `_reference` clone: `git -C _reference/guardrails-llm-filter rev-parse HEAD`), license (Apache-2.0 / MIT for gitleaks.toml), and "do not hand-edit the generated file". Keep the original top-level YAML key `guardrails_regex_rules:` — the loader reads it as-is (parity beats renaming).

- [ ] **Step 2: Confirm rule counts** (46 hand-written + 220 generated):

```bash
grep -c 'rule_id:' configs/rules.yaml            # expect 46
grep -c 'rule_id:' configs/rules.gitleaks.generated.yaml  # expect 220
```

- [ ] **Step 3: Check `.gitleaks.toml`** (the repo's own secret-scan config) doesn't flag the catalogs: add an allowlist entry for `configs/*` paths (they contain example-shaped patterns, not secrets).

- [ ] **Step 4: Commit**

```bash
git add configs && git commit -m "feat: port detection rule catalogs with attribution"
```

### Task 0.6: Add re2 + yaml-cpp dependencies

**Files:**
- Modify: `vcpkg.json` (add `"re2"`, `"yaml-cpp"`)
- Modify: `CMakeLists.txt` (find_package + link into the `app_core` interface lib: `re2::re2`, `yaml-cpp::yaml-cpp`)

**Steps:**

- [ ] **Step 1: Edit `vcpkg.json`** — add the two deps to `dependencies` (alphabetical position, no version pins — the baseline is the pin).

- [ ] **Step 2: Edit `CMakeLists.txt`** — `find_package(re2 CONFIG REQUIRED)`, `find_package(yaml-cpp CONFIG REQUIRED)`, append `re2::re2 yaml-cpp::yaml-cpp` to `COMMON_LIBS`.

- [ ] **Step 3: Commit**

```bash
git add vcpkg.json CMakeLists.txt && git commit -m "build: add re2 and yaml-cpp dependencies"
```

### Task 0.7: Push, open PR, drive CI green

**Steps:**

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin chore/bootstrap
gh pr create --title "chore: bootstrap llm-guard from cpp-rapid-rest-template" \
  --body "Phase 0 of docs/superpowers/plans/2026-08-14-phase0-phase1-bootstrap-and-engine.md: template import, rebrand, demo-domain strip, MIT+NOTICE, rule catalogs, re2/yaml-cpp deps."
```

- [ ] **Step 2: Watch CI** — `gh pr checks --watch`. The first build compiles vcpkg deps cold (~30–40 min). Expected failures to fix forward: dangling references missed in Task 0.3 (compile errors name them), openapi-drift (fix `docs/openapi.yaml` or `Endpoints.hpp`), helm-render (values referencing deleted services), gitleaks on catalogs (extend allowlist from Task 0.5 Step 3).

- [ ] **Step 3: Merge on green**

```bash
gh pr merge --merge
git checkout main && git pull
```

---

# Phase 1 — engine core (`src/guard/`)

All engine code is in `namespace Guard`, header-only, no Drogon/HTTP includes. Tests are plain unit tests (no Postgres/Redis) in `tests/unit/`, named `test_guard_*.cpp` so the template's directory glob picks them up.

**Shared interfaces produced by this phase** (later tasks and phases rely on these exact names):

```cpp
// src/guard/Rule.hpp
namespace Guard {
enum class DataType : int { Unspecified = 0, Credentials = 1, ApiKeys = 2,
                            AccessTokens = 3, IpAddresses = 4, PersonalData = 5, Custom = 6 };
std::optional<DataType> data_type_from_string(std::string_view s); // "1" or "credentials" (any case)
std::string data_type_name(DataType t);                            // "CREDENTIALS"

struct Masking {
    std::vector<int> capture_groups;  // 1-based; empty = full match
    std::string placeholder;          // e.g. "EMAIL"
};
struct Rule {
    std::string id;                   // ^[a-z0-9_.-]{1,128}$
    std::string name;
    std::string group;                // inherited from YAML group
    DataType data_type{DataType::Unspecified};
    std::string regex;                // RE2 source, compiled with "(?m)" prefix
    std::vector<std::string> keywords;   // lowercased at load
    std::vector<std::string> validators;
    std::size_t min_length{0};
    double entropy{0.0};
    std::vector<std::string> banlist;    // lowercased at load
    bool default_on{true};
    Masking masking;
};
struct DataTypeGroup {
    DataType data_type; int priority;
    std::string name, display_name, description;
};
}
```

```cpp
// src/guard/Errors.hpp
namespace Guard {
struct RuleError : std::runtime_error {   // thrown by loader/compiler
    enum class Code { InvalidId, DuplicateId, UnknownValidator, BadRegex,
                      BadCaptureGroup, UnboundedPlaceholder, ParseError };
    Code code;
    RuleError(Code c, const std::string& msg);
};
}
```

```cpp
// src/guard/RulesYaml.hpp
namespace Guard {
struct LoadedRules { std::vector<DataTypeGroup> groups; std::vector<Rule> rules; };
LoadedRules load_rules_files(const std::vector<std::string>& paths); // throws RuleError; dedupes paths; duplicate rule_id across files -> DuplicateId
}
```

```cpp
// src/guard/Validators.hpp
namespace Guard {
bool is_known_validator(std::string_view name);       // the 16 spec names
bool passes_validators(std::string_view value, const Rule& rule); // AND over rule.validators (+ entropy/banlist params from rule)
// individual primitives, unit-tested directly:
bool luhn_valid(std::string_view);        bool snils_valid(std::string_view);
bool inn_person_valid(std::string_view);  bool inn_org_valid(std::string_view);
bool ogrn_valid(std::string_view);        bool ogrnip_valid(std::string_view);
bool iban_valid(std::string_view);        bool email_ascii_valid(std::string_view);
bool payment_card_shape(std::string_view);// brand/length table, no Luhn
bool payment_card_valid(std::string_view);// shape + Luhn
double shannon_entropy(std::string_view); // bits per char
bool ip_v4(std::string_view); bool ip_v6(std::string_view);
bool ip_public(std::string_view); bool ip_private(std::string_view);
}
```

```cpp
// src/guard/PlaceholderRegex.hpp
namespace Guard {
struct PlaceholderPattern { std::string pattern; std::size_t max_len; };
// "EMAIL" -> (?i)<\s{0,3}EMAIL[\s_-]{0,3}([0-9]{1,9})\s{0,3}> ; multi-token names
// split on '_' joined by [\s_-]{0,3}. max_len computed from the RE2 parse tree;
// throws RuleError{UnboundedPlaceholder} if unbounded.
PlaceholderPattern build_placeholder_pattern(std::string_view placeholder_name);
std::size_t regex_max_len(const std::string& pattern); // RE2 parse-tree walk; SIZE_MAX if unbounded
}
```

```cpp
// src/guard/Registry.hpp
namespace Guard {
struct CompiledRule {
    Rule rule;
    std::shared_ptr<const RE2> re;             // "(?m)" + rule.regex
    std::shared_ptr<const RE2> placeholder_re; // tolerant recognizer, capture 1 = number
    std::size_t placeholder_len;               // bound for SSE pending buffer
    bool prefilter_eligible{false};
};
class Registry {
  public:
    static std::shared_ptr<const Registry> build(const std::vector<Rule>& rules); // throws RuleError
    static CompiledRule compile_rule(const Rule& r);                              // single validation path, throws RuleError
    const CompiledRule* by_id(std::string_view id) const;                         // nullptr if absent
    std::vector<const CompiledRule*> for_data_types(const std::vector<DataType>&) const;
    std::size_t size() const;
    const std::vector<CompiledRule>& all() const;
};
class ReloadableRegistry {                     // lock-free swap
  public:
    std::shared_ptr<const Registry> get() const;      // never null after init
    void swap(std::shared_ptr<const Registry> next);
};
}
```

```cpp
// src/guard/Scanner.hpp
namespace Guard {
struct ScanMatch { std::size_t start, end; const CompiledRule* rule; };
struct ScanOptions { bool prefilter_enabled = false; unsigned max_workers = 0 /*auto*/; };
// Throws std::runtime_error on internal failure (caller fails open).
// Returns sorted, non-overlapping matches; overlaps coalesced to the union span
// attributed to the longest constituent.
std::vector<ScanMatch> scan_rules(std::string_view text,
                                  const std::vector<const CompiledRule*>& rules,
                                  const ScanOptions& opts = {});
}
```

```cpp
// src/guard/Masker.hpp
namespace Guard {
struct Replacement { std::string rule_id; DataType data_type;
                     std::string original, placeholder; };
struct MaskingState {
    std::vector<std::string> triggered_rule_ids;   // sorted unique
    std::vector<DataType> triggered_data_types;    // sorted unique
    std::vector<Replacement> replacements;
    std::string format;                            // set by caller (gateway)
};
struct MaskOptions { ScanOptions scan; std::size_t parallel_min_bytes = 8192; };
struct MaskResult { std::vector<std::string> masked_texts; MaskingState state; };
MaskResult mask_texts(const std::vector<std::string>& texts,
                      const std::vector<const CompiledRule*>& rules,
                      const MaskOptions& opts = {});   // throws -> caller fails open
}
```

```cpp
// src/guard/Prefilter.hpp
namespace Guard {
// True only if every match of `pattern` provably contains >= 1 of `keywords`
// (RE2 parse-tree walk; fold-unsafe literals refused). Safe default: false.
bool regex_guarantees_keyword(const std::string& pattern,
                              const std::vector<std::string>& keywords);
}
```

CMake note (first Phase-1 task to land adds it): tests need the repo root to
load `configs/*.yaml` — add to the unit test target:
`target_compile_definitions(llm_guard_tests_unit PRIVATE LLMGUARD_REPO_ROOT="${CMAKE_SOURCE_DIR}")`.

### Task 1.1: Rule model + YAML loader

**Files:**
- Create: `src/guard/Rule.hpp`, `src/guard/Errors.hpp`, `src/guard/RulesYaml.hpp`
- Test: `tests/unit/test_guard_rules_yaml.cpp`
- Modify: `CMakeLists.txt` (the `LLMGUARD_REPO_ROOT` define above)

**Interfaces:** Produces `Guard::Rule`, `Guard::DataType`, `Guard::RuleError`, `Guard::load_rules_files` exactly as declared above.

**Go reference:** `pkg/guardrails/regex/rule/rule.go`, `pkg/guardrails/regex/rule/load.go` (YAML top-level key `guardrails_regex_rules:`, group field inheritance, keyword/banlist lowercasing, duplicate-id error).

**Steps:**

- [ ] **Step 1: Write failing tests** covering: (a) load an inline two-group YAML fixture (write it to a temp file) — group/data_type inheritance, keywords lowercased, capture_groups parsed, placeholder read from `masking`; (b) duplicate `rule_id` across two files throws `RuleError` with `Code::DuplicateId`; (c) `data_type_from_string("credentials") == DataType::Credentials`, `data_type_from_string("5")`, case-insensitive, garbage → `nullopt`; (d) loading the real catalogs:

```cpp
TEST(GuardRulesYaml, LoadsPortedCatalogs) {
    auto loaded = Guard::load_rules_files(
        {std::string(LLMGUARD_REPO_ROOT) + "/configs/rules.yaml",
         std::string(LLMGUARD_REPO_ROOT) + "/configs/rules.gitleaks.generated.yaml"});
    EXPECT_EQ(loaded.rules.size(), 266u);   // 46 + 220
    EXPECT_GE(loaded.groups.size(), 8u);
}
```

- [ ] **Step 2: Implement** `Rule.hpp`, `Errors.hpp`, `RulesYaml.hpp` (yaml-cpp). Mirror the Go loader's semantics exactly; unknown YAML keys are ignored (forward compat), missing `rules:` in a group is an empty group.

- [ ] **Step 3: Commit, push branch `feat/guard-rules-yaml`, open PR, CI green, merge.**

```bash
git add -A && git commit -m "feat(guard): rule model and yaml catalog loader"
```

### Task 1.2: Checksum validators

**Files:**
- Create: `src/guard/Validators.hpp` (checksum half + the dispatch skeleton)
- Test: `tests/unit/test_guard_validators_checksums.cpp`

**Interfaces:** Produces the checksum primitives + `is_known_validator` + `passes_validators` dispatch (format validators added in Task 1.3 — until then dispatch knows them by name but their entries are added incrementally).

**Go reference:** `pkg/guardrails/regex/validation/checksums.go` and its `_test.go` — **port the Go test vectors verbatim**; they are the authority. Algorithms (from the spec): Luhn; SNILS (weights 9..1, sum mod 101, >99→0, compare to 2-digit check); INN person (12 digits, weights `7,2,4,10,3,5,9,4,6,8` then `3,7,2,4,10,3,5,9,4,6,8`); INN org (10 digits, weights `2,4,10,3,5,9,4,6,8`); OGRN (13: 12-digit prefix mod 11 mod 10 == digit 13); OGRNIP (15: 14-digit prefix mod 13 mod 10 == digit 15); IBAN mod-97 (rearrange, letters → value−'A'+10, remainder 1). All strip non-digits first (IBAN strips spaces, uppercases).

**Steps:**

- [ ] **Step 1: Write failing tests.** Port every vector from the Go test file. Spot-check anchors (also keep these):

```cpp
EXPECT_TRUE(Guard::luhn_valid("4111111111111111"));
EXPECT_FALSE(Guard::luhn_valid("4111111111111112"));
EXPECT_TRUE(Guard::snils_valid("112-233-445 95"));
EXPECT_TRUE(Guard::inn_person_valid("500100732259"));
EXPECT_TRUE(Guard::inn_org_valid("7707083893"));
EXPECT_TRUE(Guard::ogrn_valid("1027700132195"));
EXPECT_TRUE(Guard::iban_valid("GB82WEST12345698765432"));
EXPECT_FALSE(Guard::iban_valid("GB82WEST12345698765431"));
```

- [ ] **Step 2: Implement the primitives + dispatch table.** `passes_validators` looks up each name in a static map `name -> fn(value, rule)`; unknown name returns false (compile-time rejection happens in `Registry::compile_rule`).

- [ ] **Step 3: Commit on branch `feat/guard-validators`** (`feat(guard): checksum validators`) — same branch continues in Task 1.3; one PR for both.

### Task 1.3: Format validators, entropy, banlist

**Files:**
- Modify: `src/guard/Validators.hpp`
- Test: `tests/unit/test_guard_validators_formats.cpp`

**Go reference:** `pkg/guardrails/regex/validation/formats.go`, `entropy.go` + tests (port vectors verbatim).

**Steps:**

- [ ] **Step 1: Write failing tests.** Email (≤254 total, local ≤64, no leading/trailing/double dots, domain labels 1..63 no edge hyphens, ≥2 labels, alpha TLD): `a@b.co` true, `a..b@c.co` false, `a@b` false. Payment card brand/length table: Visa `4` (13/16/19), Amex `34|37` (15), MC `51–55|2221–2720` (16), Discover `6011|644–649|65` (16–19), UnionPay `62` (16–19), Mir `2200–2204` (16–19); `payment_card_valid` = shape && Luhn. IPs: parse v4/v6 incl. CIDR and bracket stripping; `ip_private` = private ∪ loopback ∪ multicast ∪ link-local ∪ unspecified; `ip_public` = parses && !private. Entropy: `shannon_entropy("aaaa") == 0.0`, `shannon_entropy("abcd") == 2.0` (exact — uniform 4 symbols), and via `passes_validators` a rule with `entropy: 3.0` rejects `"aaaaaaaa"`. Banlist: rule with `banlist: ["example"]` rejects value containing `example` case-insensitively.

- [ ] **Step 2: Implement.** IP parsing by hand or `inet_pton` (no new deps). Entropy: ASCII fast path with a 256-table, `std::unordered_map<char32_t,…>` fallback for non-ASCII (UTF-8 decode).

- [ ] **Step 3: Push `feat/guard-validators`, PR, CI green, merge.**

```bash
git add -A && git commit -m "feat(guard): format validators, entropy, banlist"
```

### Task 1.4: Placeholder recognition regex + length bound

**Files:**
- Create: `src/guard/PlaceholderRegex.hpp`
- Test: `tests/unit/test_guard_placeholder_regex.cpp`

**Go reference:** `pkg/guardrails/regex/registry/registry.go` (`buildDefaultPlaceholderRegexp`, `regexpMaxLen`).

**Steps:**

- [ ] **Step 1: Write failing tests:**

```cpp
auto p = Guard::build_placeholder_pattern("EMAIL");
RE2 re(p.pattern);
EXPECT_TRUE(RE2::PartialMatch("<EMAIL_1>", re));
EXPECT_TRUE(RE2::PartialMatch("< email - 12 >", re));   // tolerant: case, space, - vs _
EXPECT_TRUE(RE2::PartialMatch("<DB_DSN_3>", Guard::build_placeholder_pattern("DB_DSN").pattern_re));
EXPECT_FALSE(RE2::PartialMatch("<EMAIL>", re));          // no number
EXPECT_GT(p.max_len, 0u); EXPECT_LT(p.max_len, 100u);
EXPECT_EQ(Guard::regex_max_len("a{2,5}b"), 6u);
EXPECT_EQ(Guard::regex_max_len("a+"), SIZE_MAX);         // unbounded
```

- [ ] **Step 2: Implement.** Pattern template per spec §4.2. `regex_max_len` walks the parse tree via `re2::Regexp::Parse` (header `re2/regexp.h`; call `->Decref()` when done) summing/maxing per op (Literal/CharClass=rune len, Concat=sum, Alternate=max, Repeat/Star/Plus=SIZE_MAX unless max bounded, Capture=child). Saturating arithmetic — never overflow.

- [ ] **Step 3: Commit, push `feat/guard-placeholder-regex`, PR, CI green, merge.**

```bash
git add -A && git commit -m "feat(guard): tolerant placeholder recognizer with length bound"
```

### Task 1.5: Registry + compile path + reloadable snapshot

**Files:**
- Create: `src/guard/Registry.hpp`
- Test: `tests/unit/test_guard_registry.cpp`

**Interfaces:** Consumes Tasks 1.1–1.4. Produces `Registry`, `CompiledRule`, `ReloadableRegistry` as declared.

**Go reference:** `pkg/guardrails/regex/registry/registry.go`, `reloadable.go`.

**Steps:**

- [ ] **Step 1: Write failing tests:** compile_rule rejects: bad id (`"UPPER"` → `InvalidId`), unknown validator (`UnknownValidator`), regex that doesn't compile under RE2 e.g. `"(?<=x)y"` (`BadRegex`), capture group index 2 on a 1-group regex (`BadCaptureGroup`). `build` rejects duplicate ids (`DuplicateId`). `for_data_types` returns only matching rules; `by_id` finds; `ReloadableRegistry::swap` visible to a subsequent `get()` while an old snapshot pointer stays valid. **Catalog smoke test** (the phase-1 exit criterion):

```cpp
TEST(GuardRegistry, FullCatalogCompiles) {
    auto loaded = Guard::load_rules_files({... both catalogs ...});
    auto reg = Guard::Registry::build(loaded.rules);   // must not throw
    EXPECT_EQ(reg->size(), 266u);
    for (const auto& cr : reg->all()) EXPECT_GT(cr.placeholder_len, 0u);
}
```

- [ ] **Step 2: Implement.** `compile_rule`: id regex check → validator names known → `RE2("(?m)" + rule.regex)` ok → capture groups ≤ `re->NumberOfCapturingGroups()` → `build_placeholder_pattern(masking.placeholder empty ? derived-from-id : placeholder)`; on placeholder absence the Go code falls back to the uppercased rule id tail — mirror `registry.go` exactly (read it, don't guess). `prefilter_eligible` stays false until Task 1.8 wires the prover in.

- [ ] **Step 3: Commit, push `feat/guard-registry`, PR, CI green, merge.**

```bash
git add -A && git commit -m "feat(guard): compiled rule registry with atomic reload"
```

### Task 1.6: Scanner

**Files:**
- Create: `src/guard/Scanner.hpp`
- Test: `tests/unit/test_guard_scanner.cpp`

**Go reference:** `pkg/guardrails/regex/scanners/sensitive/scan.go` + its 837-line test (port the behavioral cases: span selection, min_length, validator drop, overlap coalescing, parallel equivalence).

**Steps:**

- [ ] **Step 1: Write failing tests:** (a) semantic span = first configured capture group with content, else full match; (b) match shorter than `min_length` dropped; (c) match failing `passes_validators` dropped (rule with `luhn` + a non-Luhn 16-digit number); (d) **overlap coalescing**: two rules matching `[5,15)` and `[10,25)` produce one `[5,25)` attributed to the longer; identical spans produce one; (e) result sorted by start, non-overlapping; (f) `max_workers=4` output identical to serial on a 100 KiB text with 20 rules; (g) empty text / empty rules → empty.

- [ ] **Step 2: Implement.** Serial path first: per rule, iterate `RE2::Match` (or `FindAndConsume` loop with position advance) collecting submatch positions via `re->Match(text, pos, text.size(), RE2::UNANCHORED, groups, ngroups)`. Then bucket-parallel via `std::async` when `text.size() >= 4096 && rules.size() > 4` (rules split across `std::thread::hardware_concurrency()` buckets; exceptions propagate as the scan error). Coalesce: sort candidate matches by start; sweep, merging any overlap into union span, keeping the longest constituent's rule.

- [ ] **Step 3: Commit, push `feat/guard-scanner`, PR, CI green, merge.**

```bash
git add -A && git commit -m "feat(guard): rule scanner with union-span overlap coalescing"
```

### Task 1.7: Masker

**Files:**
- Create: `src/guard/Masker.hpp`, `src/guard/MaskingState.hpp` (split `Replacement`/`MaskingState` out of the declaration block if cleaner — keep names)
- Test: `tests/unit/test_guard_masker.cpp`

**Go reference:** `internal/usecases/guardrails/mask/` (`handle.go`, `masker.go`, `masker_test.go`).

**Steps:**

- [ ] **Step 1: Write failing tests:** (a) two texts, same email in both → same `<EMAIL_1>` in both, one `Replacement` entry; (b) two different emails → `<EMAIL_1>`, `<EMAIL_2>` in encounter order (text order then offset order — deterministic); (c) different types get independent counters (`<EMAIL_1>` + `<CREDIT_CARD_1>`); (d) **collision guard**: input text containing literal `<EMAIL_1>` — a newly masked email becomes `<EMAIL_2>`, and the pre-existing `<EMAIL_1>` is untouched and absent from `replacements`; (e) `triggered_rule_ids` and `triggered_data_types` sorted unique; (f) parallel path (`texts` totalling > `parallel_min_bytes`) equals serial output; (g) masking replaces the exact spans — text around them byte-identical.

- [ ] **Step 2: Implement.** Phase A: scan texts (fan out only when ≥2 texts and combined bytes ≥ `opts.parallel_min_bytes`; first error (lowest text index) wins and propagates). Phase B: sequential in text order — reserved-placeholder pre-scan with RE2 `<[A-Za-z0-9_]+_[0-9]+>` over all texts; per-type counters skipping reserved values; dedup map original→placeholder; build masked strings by splicing spans right-to-left (offsets stay valid).

- [ ] **Step 3: Commit, push `feat/guard-masker`, PR, CI green, merge.**

```bash
git add -A && git commit -m "feat(guard): deterministic masker with placeholder collision guard"
```

### Task 1.8: Keyword prefilter prover

**Files:**
- Create: `src/guard/Prefilter.hpp`
- Modify: `src/guard/Registry.hpp` (set `prefilter_eligible` in `compile_rule` when rule has keywords and the prover returns true)
- Modify: `src/guard/Scanner.hpp` (when `opts.prefilter_enabled`: lowercase the text once lazily; skip rules whose `prefilter_eligible` && no keyword is a substring)
- Test: `tests/unit/test_guard_prefilter.cpp`

**Go reference:** `pkg/guardrails/regex/registry/registry.go` (`regexGuaranteesKeyword`, `foldSafeForToLower`) and `tests/rules/prefilter_unicode_test.go`.

**Steps:**

- [ ] **Step 1: Write failing tests:** `regex_guarantees_keyword("stripe_[a-z0-9]{24}", {"stripe"})` true; alternation where only one branch has it → false; `(?:aws|amzn)key` with `{"key"}` true (concat child); star/optional wrapping the literal → false; case-folded Greek `ς`/`ſ` cases → false (port the unicode test); scanner with prefilter on skips a non-matching eligible rule but still scans an ineligible one (behavioral equivalence test: prefilter on == off for a corpus of texts).

- [ ] **Step 2: Implement** with `re2::Regexp::Parse(pattern, re2::Regexp::LikePerl, …)` tree walk per spec §4.6; every op not on the proven list returns false (safe default).

- [ ] **Step 3: Commit, push `feat/guard-prefilter`, PR, CI green, merge.**

```bash
git add -A && git commit -m "feat(guard): recall-preserving keyword prefilter"
```

### Task 1.9: Rule corpus port

**Files:**
- Create: `tests/data/guard_rule_cases.yaml`
- Test: `tests/unit/test_guard_rule_corpus.cpp`

**Go reference:** `tests/rules/rules_cases_test.go` (2142 lines) — the authoritative positive/negative corpus per rule.

**Steps:**

- [ ] **Step 1: Convert the Go table to YAML** (mechanical port, keep every case; do not invent or drop cases). Schema:

```yaml
cases:
  - rule_id: pii.email
    positives: ["contact me at john.doe@example.com", ...]
    negatives: ["not-an-email at example dot com", ...]
  - rule_id: pii.fin.credit-card
    positives: ["4111 1111 1111 1111", ...]
    negatives: ["4111 1111 1111 1112", ...]   # fails Luhn
```

Where the Go test asserts a specific matched substring or placeholder type, add optional keys `expect_span: "john.doe@example.com"` / `expect_placeholder: "EMAIL"` and assert them.

- [ ] **Step 2: Write the runner:** load both catalogs → `Registry::build` → for each case: scan the text with the full registry restricted to that rule's data type; positives must produce ≥1 match attributed to `rule_id` (or coalesced with it as constituent — assert the span covers `expect_span` when present); negatives must produce zero matches for that `rule_id`. Failures print rule id + text for triage.

- [ ] **Step 3: Fix discrepancies.** Any corpus failure is a porting bug in Tasks 1.1–1.8 — fix the engine, never the corpus (unless diffing against the Go behavior proves the corpus transcription wrong).

- [ ] **Step 4: Commit, push `feat/guard-rule-corpus`, PR, CI green, merge.**

```bash
git add -A && git commit -m "test(guard): port per-rule positive/negative corpus"
```

---

## Phase exit criteria

- `main` green in CI: build, unit bucket (all `test_guard_*`), sanitizers job, format/tidy, gitleaks, drift gates.
- Catalog smoke test proves all 266 rules compile under RE2 with bounded placeholder recognizers.
- Rule corpus passes 100%.
- No local builds were required at any point.

## Self-review notes (done at write time)

- Spec coverage: this plan implements spec §2 (instantiation/cleanup), §4 (engine), §13 partially (only engine-relevant seeds), §15 (licensing). §§5–12,14 land in later phase plans (JSON/extractors/demasker → phase 2 plan, SSE → phase 3, gateway → phase 4, stores/API/console/ops → phases 5–8).
- Type consistency: interface block at the top of Phase 1 is the single source; tasks reference it.
- Placeholder scan: no TBDs; where implementation detail is deliberately delegated (`registry.go` placeholder fallback), the step names the exact Go file to mirror rather than guessing.
