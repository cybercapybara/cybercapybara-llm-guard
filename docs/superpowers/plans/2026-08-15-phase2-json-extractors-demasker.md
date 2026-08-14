# LLM Guard — Phase 2 (JSON spans, format extractors, demasker) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Byte-surgical JSON value extraction/patching, the three LLM wire-format extractors (chat_completions / messages / responses), and the streaming-safe demasker — the pieces that turn the Phase-1 engine into a request/response transformer.

**Architecture:** `src/guard/json/` implements a gjson/sjson equivalent: a streaming JSON scanner returning byte spans of values in the raw body, plus splice-patching that preserves every untouched byte. Format extractors walk documents via those spans. The demasker inverts `MaskingState` with an exact pass + tolerant placeholder-regex pass and a pending-buffer contract for chunked (SSE) input. All header-only `Guard::`, no HTTP deps; CI-only verification (no local builds).

**Tech Stack:** existing deps only (re2, yaml-cpp for tests, nlohmann-json ONLY inside the structural fallback), GoogleTest.

**Spec:** `docs/superpowers/specs/2026-08-14-llm-guard-design.md` (§4.7 demasker, §5 JSON handling/extraction)

## Global Constraints

- All Phase-1 constraints hold: NO local builds (CI only; no Docker/colima), header-only `src/`, RE2 only, clang-format 17 / 120 cols, conventional commits, NO AI trailers, branch-per-task + PR + 8/8 green + controller review before merge.
- Go authority: `/Users/moveeeax/Public/cybercapybara/_reference/guardrails-llm-filter` — `pkg/llmutils/**` (extractors), `internal/guardrails/demask/**` (demasker), `internal/sseproc/common/json.go` (MarshalNoEscape, DemaskJSONArguments). Port test corpora with the code; Go semantics win over this plan's prose.
- Byte-surgery invariant (spec §5): unmodeled fields, key order, number formatting, and `<`/`>` survive byte-for-byte. Parse-and-reserialize appears ONLY in the sanctioned structural fallback for tool arguments.
- The demasker's error contract (spec §4.7): on error, return the un-emitted buffer WITH the error; callers emit it (lossless fail-open). An under-hold of the pending buffer is a security bug (split placeholder leaks); over-hold is latency.
- Phase-1 interfaces are frozen; Phase 2 additions live in `phase2-interfaces.md` in the SDD workspace (controller-owned).

## Phase-2 shared interfaces

```cpp
// src/guard/json/Json.hpp
namespace Guard::Json {
struct ValueSpan {              // byte range of a JSON value inside a raw document
    std::size_t start, end;     // [start,end) — for strings: INCLUDING quotes
    bool is_string;             // value kind (string vs raw token/object/array)
};
// Path-addressed span lookup over the raw bytes. Paths are pre-split segments
// (object keys / array indices), NOT dotted strings — no escaping ambiguity.
struct PathSeg { std::string key; std::size_t index; bool is_index; };
std::optional<ValueSpan> find_value(std::string_view doc, const std::vector<PathSeg>& path);
// Decode a JSON string literal span (unescape) / encode a replacement for splicing.
std::string decode_string(std::string_view quoted);              // input includes quotes
std::string encode_string(std::string_view raw, bool with_quotes); // NO HTML escaping; \u only where JSON requires
bool valid(std::string_view doc);                                // strict RFC 8259 validity
// Splice: replace [span.start, span.end) with replacement bytes (already encoded).
std::string splice(std::string_view doc, const ValueSpan& span, std::string_view replacement);
// Multi-splice: non-overlapping spans, applied so offsets never invalidate.
std::string splice_all(std::string_view doc,
                       const std::vector<std::pair<ValueSpan, std::string>>& edits);
// Walk every STRING LEAF under a value (for tool_use.input) in document order.
struct StringLeaf { std::vector<PathSeg> path; ValueSpan span; };
std::vector<StringLeaf> string_leaves(std::string_view doc, const std::vector<PathSeg>& root);
}
```

```cpp
// src/guard/extract/Extract.hpp (+ ChatCompletions.hpp, Messages.hpp, Responses.hpp)
namespace Guard::Extract {
struct ContentField {
    std::vector<Guard::Json::PathSeg> path;  // patchable location
    Guard::Json::ValueSpan span;             // in the ORIGINAL body bytes
    std::string text;                        // decoded string value
    bool is_raw_object{false};               // true for messages tool_use `.input` (patch raw)
};
struct Unsupported {};                        // sentinel: fail-open + counter (spec §5)
using ExtractResult = std::variant<std::vector<ContentField>, Unsupported>;
ExtractResult extract_request(std::string_view body, Guard::ApiFormat format);
ExtractResult extract_response(std::string_view body, Guard::ApiFormat format);
enum class ApiFormat { ChatCompletions, Messages, Responses };  // lives in Guard::
bool wants_stream(std::string_view body);     // top-level "stream": true
}
```

```cpp
// src/guard/demask/Demasker.hpp
namespace Guard::Demask {
struct Config {                 // request-scoped, built once from MaskingState
    // exact replacer tables (verbatim + JSON-escaped originals), lookup maps,
    // max_pending = max(longest placeholder literal, max placeholder_len of triggered rules)
};
Config make_config(const Guard::MaskingState& state,
                   const std::shared_ptr<const Guard::Registry>& pinned);
struct ChunkResult { std::string out; };      // emitted bytes
class Demasker {
  public:
    explicit Demasker(const Config& cfg, bool json_escape_originals);
    // On success: emitted bytes (holds back <= max_pending unless flush).
    // On error: throws DemaskError carrying the un-emitted buffer — caller MUST emit it.
    ChunkResult demask_chunk(std::string_view chunk, bool flush);
    std::string pending() const;              // introspection for tests
};
struct DemaskError : std::runtime_error { std::string unemitted; ... };
std::string demask_all(const Config&, std::string_view text, bool json_escape); // one-shot
// Structural fallback for tool arguments (spec §5): naive raw substitution; if
// result !valid → parse, demask string leaves, re-marshal without HTML escaping,
// numbers preserved verbatim; if still failing → keep masked value.
std::string demask_json_arguments(const Config&, std::string_view raw_json);
}
```

## Tasks

### Task 2.1: JSON span scanner + splicing (`src/guard/json/Json.hpp`)
Port target: gjson/sjson behavioral subset the Go code uses (`gjson.GetBytes` paths, `sjson.SetBytes`/`SetRawBytes`). Steps: write tests first from Go usage sites (llmutils extract/patch paths + common/json.go), incl.: span lookup through nested objects/arrays, escaped keys, unicode escapes, string decode/encode round-trip (NO `<`/`>` escaping — pin it), splice byte-identity outside the span, multi-splice ordering, `string_leaves` document-order walk skipping non-strings, malformed docs → nullopt/empty (never throw on lookup). Fuzz-style test: 200 generated docs, splice(find(x)) round-trips. Branch `feat/guard-json`, commit `feat(guard): byte-surgical json span scanner and splicer`.

### Task 2.2: chat_completions extractor
Port `pkg/llmutils/chatcompletions/extract.go` + `extract_response.go` (+ tests): request requires `messages[]` else Unsupported; `messages[i].content` string, `content[j].text` for `type=="text"`, `function_call.arguments`, `tool_calls[j].function.arguments`; response per `choices[i].message`: `content`, `reasoning`, `reasoning_content`, `refusal`, `function_call.arguments`, `tool_calls[j].function.arguments`. Branch `feat/guard-extract-cc`.

### Task 2.3: messages (Anthropic) extractor
Port `pkg/llmutils/messages/extract.go` + `extract_response.go` (+ tests): `system` string/blocks; `messages[i].content` string/blocks (`text`→`.text`; `tool_use`→string leaves of `input` with `is_raw_object` for response `.input`; `tool_result` content); response blocks `text`/`thinking` (signature untouched)/`tool_use` raw input; `redacted_thinking` + unknown → skipped byte-identical. NEVER errors (malformed yields nothing) — pin with tests. Branch `feat/guard-extract-msg`.

### Task 2.4: responses (OpenAI Responses) extractor
Port `pkg/llmutils/responses/extract.go` + `extract_response.go` (+ tests): request requires `input` or `instructions` else Unsupported; `instructions`, `input` string, `input[i].content[j].text` (`input_text|output_text|text`), `input[i].arguments` (`function_call`), `input[i].output` string / `output[j].text` (`function_call_output`); skips `input_image`/`input_file`/`item_reference`/`reasoning` items. Response: ExtractOutputFields with basePath (for `response.completed`-embedded objects) + ExtractItemFields; `encrypted_content` untouched. Also `wants_stream`. Branch `feat/guard-extract-resp`.

### Task 2.5: demasker
Port `internal/guardrails/demask/**` (+ tests, which are extensive): Config build (exact replacer verbatim + JSON-escaped, max_pending from placeholder literals + placeholder_len of triggered rules via pinned registry snapshot), chunk pass order (pending+chunk → exact pass → tolerant regex pass left-to-right by byte offsets → hold back max_pending trimmed to UTF-8 rune boundary unless flush), the DemaskError un-emitted-buffer contract, JSON-escaping variant, demask_all, demask_json_arguments with structural fallback (parse → demask leaves → re-marshal no-HTML-escape, numbers verbatim via raw-span copy — use Json.hpp, not nlohmann, for number preservation; nlohmann allowed only if numbers round-trip byte-identically — verify, else marshal manually). Chunk-boundary torture tests: placeholder split at every byte position (loop), 1-byte chunks, flush-at-every-position, multi-byte UTF-8 at the hold boundary. Branch `feat/guard-demasker`.

### Task 2.6: integration round-trip
New test file: full pipeline mask→patch→demask round-trip per format: build bodies with PII (email/card/Cyrillic), extract → mask_texts → splice_all → extract again (masked body must parse + placeholders present) → demask_all → byte-identical to original body. SSE-chunked variant: demask via demask_chunk with 1..64-byte chunk sizes → identical output. Branch `feat/guard-roundtrip`.

## Execution notes
- 2.2/2.3/2.4 are parallelizable in worktrees after 2.1 merges (all consume Json.hpp; disjoint files). 2.5 parallel with 2.2-2.4 (depends only on Phase 1 + Json.hpp for the fallback). 2.6 after all merge.
- Reviewer lens per task: byte-identity adversarial cases (unicode escapes, huge numbers, duplicate keys, key order), Go-parity of path semantics, demasker hold-back under-estimate hunting.

## Self-review notes
- Spec coverage: implements spec §5 fully and §4.7; §6 (SSE) is Phase 3 and consumes Demasker + Json + extractors as-is.
- Type consistency: interface block above is the single source; ApiFormat placement (Guard:: vs Guard::Extract::) fixed as Guard:: per gateway needs.
- No placeholders: each task names its Go files and test-porting obligations; exact code lives in the Go authority per project convention (ported, not invented).
