/**
 * @file Masker.hpp
 * @brief Deterministic placeholder substitution: scans every input text
 *        against a pinned rule set, then masks them sequentially through one
 *        shared masking state so placeholder numbering and cross-text dedup
 *        stay reproducible.
 * @details Ports `internal/usecases/guardrails/mask/{handle,masker}.go`,
 *          read directly, not assumed:
 *
 *          **Phase A -- scan** (`detail::scan_texts` ports `Handle`'s call
 *          into `scanTexts` + `scanWorkers`, handle.go:120-200): every text is
 *          scanned against `rules` via `Scanner.hpp`'s `scan_rules`. Text-level
 *          fan-out (one `scan_rules` call per text, concurrently) triggers
 *          only when BOTH `texts.size() >= 2` AND the combined byte size of
 *          every text is `>= opts.parallel_min_bytes` -- read verbatim off
 *          `scanWorkers` (handle.go:179-200): `if len(texts) < 2 { return 1 }`,
 *          then (absent an explicit override) `if total < minBytes { return 1
 *          }`. Go's `scanWorkers` has a THIRD branch -- `WithScanConcurrency`,
 *          an explicit worker-count override that bypasses the size gate
 *          entirely (used by its tuning/benchmark tests, e.g.
 *          `TestUseCase_Handle_ParallelScannerError`,
 *          `TestUseCase_Handle_ParallelEqualsSequential`, which force the
 *          parallel path on tiny bodies via `mask.WithScanConcurrency(n)`) --
 *          `MaskOptions` (phase1-interfaces.md) carries no equivalent field,
 *          so this port only mirrors the auto (size-gated) branch; there is
 *          no bypass here. `parallel_min_bytes == 0` is treated the same way
 *          Go treats a non-positive `parallelMinBytes` (`if minBytes <= 0 {
 *          minBytes = defaultParallelMinBytes }`, handle.go:187-190): falls
 *          back to the 8192 default rather than parallelizing unconditionally.
 *
 *          Error propagation (handle.go:52-56, `scanTexts`'
 *          `for i, text := range texts { ... if err != nil { return results
 *          } }` for the sequential branch, `wg.Wait()` then a lowest-index
 *          scan for the parallel branch): the FIRST error by lowest TEXT
 *          INDEX wins and propagates as a thrown exception (the caller fails
 *          open, per the interface contract). The sequential branch here
 *          stops scanning at the first failing index (mirrors Go exactly --
 *          "no point scanning the remaining texts" once the whole result is
 *          going to be discarded); the parallel branch waits for every
 *          in-flight scan to finish first (mirrors Go's `wg.Wait()` -- it
 *          cannot cheaply cancel in-flight work either), then reports the
 *          lowest-index failure regardless of which one finished first. This
 *          port launches exactly `text_scan_worker_count(texts, opts)`
 *          `std::async` tasks once fan-out is chosen -- NOT one task per
 *          text -- each covering its own contiguous, non-overlapping index
 *          range of `texts` and scanning that range serially into its own
 *          slice of `results` (disjoint element writes to a pre-sized
 *          `std::vector` are data-race-free even without synchronization).
 *          This bounds in-flight OS threads to the same worker count Go's
 *          semaphore bounds concurrent goroutines to (`scanWorkers`'s return
 *          value there only bounds concurrent in-flight goroutines via a
 *          buffered channel, handle.go:147-168) -- a request with thousands
 *          of texts no longer spawns one thread per text (nor, since each
 *          per-text scan can itself fan out inside `scan_rules`, thousands
 *          of NESTED thread pools). Chunking rather than a literal semaphore
 *          is a deliberate simplification of Go's exact mechanism: the
 *          OUTPUT this port is contracted to match only depends on the
 *          bound on concurrency, not on how it's enforced (results are still
 *          collected in index order, all-or-nothing, lowest-index-error-wins);
 *          a chunk that hits a scan failure partway through still finishes
 *          scanning the REST of its own range (mirrors this port's prior,
 *          and Go's, "the parallel path cannot cheaply cancel in-flight
 *          work either" stance -- only the fully-SEQUENTIAL branch above
 *          stops early, since there nothing is "in flight" to let finish).
 *          Each worker's chunk scans its whole texts against the FULL,
 *          SHARED `rules` (unchanged `scan_rules` per text -- Go parity:
 *          `handle.go`'s `scanTexts` also runs one full scan per text,
 *          goroutine-per-text), so multiple worker threads DO call `RE2::
 *          Match` concurrently on the same compiled rule set. An earlier
 *          revision of this file avoided that on purpose (partitioning
 *          `rules` across workers instead) after CI's `tsan` job reported a
 *          data race inside `re2::DFA::CachedState` -- root-caused not to
 *          this port's own concurrency, but to CI's `tsan` job at the time
 *          linking non-instrumented, prebuilt vcpkg RE2/Abseil into an
 *          otherwise-`-fsanitize=thread`-instrumented test binary (a TSan
 *          false-positive: it cannot see synchronization happening inside
 *          code it never instrumented). That gap is fixed at the CI-infra
 *          level (`docker/Dockerfile`'s `tsan-builder` stage now links a
 *          separately-built, TSan-instrumented RE2/Abseil tree via
 *          `triplets/x64-linux-tsan.cmake` -- see this repo's `CLAUDE.md`,
 *          "Don't point the `tsan` job back at `build/vcpkg_installed`"),
 *          confirmed sound by `test_guard_scanner_concurrency.cpp`'s direct
 *          concurrent-`Match`-on-shared-`CompiledRule` test. With that fix
 *          in place, concurrent `RE2::Match` on a shared, already-compiled
 *          rule set is exactly what RE2 documents itself as safe for, and
 *          this file reverts to the simpler, Go-parity TEXT partitioning.
 *
 *          **Phase B -- mask** (`detail::MaskerState` ports `masker`,
 *          masker.go, in full): runs SEQUENTIALLY in text order through one
 *          shared state so numbering is deterministic, even though Phase A
 *          may have scanned out of order:
 *            - Per-placeholder-TYPE counters (`rule.masking.placeholder`,
 *              e.g. "EMAIL"), 1-based, incremented on every `nextPlaceholder`
 *              call for that type (masker.go:135-145) -- including calls
 *              whose rendered value turns out to be reserved and gets
 *              skipped (the counter is NOT rolled back for a skip; it simply
 *              keeps incrementing until an unreserved value is found).
 *            - Cross-text dedup: `originalToPlaceholder` (masker.go:22,
 *              `placeholderForOriginal`, masker.go:125-133) maps the exact
 *              matched original substring to its placeholder; the SAME
 *              original anywhere in ANY text reuses the same placeholder
 *              without incrementing the counter or adding a second
 *              `Replacement`. A `Replacement` is recorded once, at first
 *              encounter, in encounter order (text order, then within a
 *              text, span-start order, since `scan_rules` already returns
 *              matches sorted).
 *            - `seenRules`/`seenDataTypes` (masker.go:87-91) accumulate
 *              across every masked match in every text; `triggered_rules`/
 *              `triggered_data_types` (masker.go:107-123) sort-and-dedup on
 *              read -- ported here as `std::set` members instead (see
 *              `MaskerState`), which keeps the same sorted-unique invariant
 *              without a separate sort step. A `DataType` is only added to
 *              `seenDataTypes` when it's a genuine non-Unspecified data type
 *              -- masker.go:88-91's `dataType.IsValid() && dataType !=
 *              models.DataTypeUNSPECIFIED` (Go's generated `IsValid` is true
 *              for every declared value 0-6; the second half of that
 *              condition is what actually excludes Unspecified) -- ported as
 *              `detail::is_triggerable_data_type` below: `Credentials
 *              <= dt <= Custom` (i.e. 1-6), which excludes both
 *              `Unspecified` (0) and any raw out-of-range value a
 *              hand-constructed `CompiledRule` might carry (mirrors
 *              `TestMaskerTriggeredDataTypesFiltersInvalidValues`'s
 *              `DataType(999)` case).
 *
 *          **Placeholder rendering** (`detail::render_placeholder` ports
 *          `placeholderfmt.Format`, read verbatim: `fmt.Sprintf("<%s_%d>",
 *          placeholderType, index)`): `"<" + type + "_" + counter + ">"`,
 *          where `type` is the RAW (untrimmed) `rule.masking.placeholder`
 *          string -- never derived from the rule id.
 *
 *          **BLANK PLACEHOLDER -- what Go actually does** (read from
 *          `masker.go`'s `maskText`, line 72, not guessed): `if match.Start <
 *          pos || match.FullText == "" || match.Placeholder == "" { continue
 *          }`. A match whose rule has a blank `masking.placeholder` is
 *          SKIPPED ENTIRELY -- not masked (its original bytes are copied
 *          through verbatim, exactly like the surrounding untouched text),
 *          NOT added to `seenRules`/`seenDataTypes`, and NOT recorded as a
 *          `Replacement`. This is consistent with `Registry.hpp`'s own
 *          blank-placeholder guard (`compile_rule` builds no
 *          `placeholder_re` at all when `masking.placeholder` is blank) --
 *          together the two confirm a blank-placeholder rule can DETECT
 *          (contribute a `ScanMatch`) but never MASK, never trigger, and
 *          never demask (no recognizer exists for the empty-string case
 *          anyway). This port's `MaskerState::mask_text` reproduces the exact
 *          same three-way skip condition, in the same order.
 *
 *          **Collision guard -- reserved placeholders**
 *          (`detail::reserved_placeholders` ports `reservedPlaceholders`,
 *          masker.go:34-50, and the module-level `placeholderLiteralRe`,
 *          masker.go:16): every input text (ALL of them, scanned up front,
 *          before any masking happens) is searched for literal tokens
 *          matching `<[A-Za-z0-9_]+_[0-9]+>` -- read verbatim off the Go
 *          regex source, not paraphrased. Every such literal is added to a
 *          `reserved` set. `MaskerState::next_placeholder` (ports
 *          `nextPlaceholder`, masker.go:135-145) then skips any counter value
 *          whose RENDERED placeholder string is in that set, trying the next
 *          counter value instead, so a generated placeholder can never
 *          collide with (and thus corrupt, on demask) a placeholder-shaped
 *          token the user's own text already contained. Reservation is
 *          orthogonal to matching: a placeholder-shaped literal is NOT
 *          exempt from a rule that happens to match it (nothing here
 *          special-cases the text `<EMAIL_1>` against, say, an overly broad
 *          email regex) -- if a rule DOES match it, that match is masked
 *          exactly like any other, just with a freshly minted, guaranteed
 *          non-colliding placeholder (the counter skips every reserved
 *          value), so the round trip stays safe either way: an untouched
 *          reserved literal is never corrupted by demasking a DIFFERENT
 *          occurrence of the same rendered text, and a reserved literal that
 *          DOES get matched is masked and later demasked like any other
 *          value, never conflated with the pre-existing literal.
 *
 *          Splicing (`MaskerState::mask_text` ports `maskText`, masker.go:
 *          62-100): a single left-to-right walk with a `pos` cursor, exactly
 *          like Go's `strings.Builder` walk -- `matches` (from `scan_rules`)
 *          are already sorted and non-overlapping, so appending `text[pos:
 *          match.start)` then the placeholder then advancing `pos =
 *          match.end` for each match, and the trailing `text[pos:]` at the
 *          end, reproduces Go's builder byte-for-byte. The defensive `match.
 *          start < pos` skip (masker.go:72) is kept even though `scan_rules`
 *          never emits overlapping matches through its own public API --
 *          `masker_test.go`'s `TestMaskerMaskText/skips_overlapping_later_match`
 *          exercises `MaskerState::mask_text` directly with a hand-built,
 *          deliberately-overlapping match list (bypassing the scanner
 *          entirely), so the port needs the same guard to reproduce that
 *          case.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <exception>
#include <future>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <re2/re2.h>

#include "guard/MaskingState.hpp"
#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/Scanner.hpp"

namespace Guard {

struct MaskOptions {
    ScanOptions scan;
    std::size_t parallel_min_bytes = 8192;
};

struct MaskResult {
    std::vector<std::string> masked_texts;
    MaskingState state;
};

namespace detail {

// handle.go:23's defaultParallelMinBytes, used whenever
// MaskOptions::parallel_min_bytes is 0 -- mirrors `scanWorkers`'s `if
// minBytes <= 0 { minBytes = defaultParallelMinBytes }` (handle.go:187-190):
// an explicit-but-non-positive override still falls back to the default
// rather than parallelizing unconditionally.
inline constexpr std::size_t kDefaultParallelMinBytes = 8 * 1024;

// masker.go:16's placeholderLiteralRe, read verbatim:
// `regexp.MustCompile(`<[A-Za-z0-9_]+_[0-9]+>`)`. Wrapped in one capturing
// group purely so RE2::FindAndConsume can report each match's text below --
// this does not change what the pattern matches.
inline const RE2& reserved_placeholder_regex() {
    static const RE2 re(R"((<[A-Za-z0-9_]+_[0-9]+>))", RE2::Quiet);
    return re;
}

// Ports `reservedPlaceholders` (masker.go:34-50): every `<TYPE_N>`-shaped
// literal already present in ANY of `texts`, collected up front (before any
// masking starts) so `MaskerState::next_placeholder` can skip generating a
// placeholder that would collide with one. Returns an empty set (Go: nil map,
// the common case) when none are found.
inline std::unordered_set<std::string> reserved_placeholders(const std::vector<std::string>& texts) {
    std::unordered_set<std::string> reserved;
    const RE2& re = reserved_placeholder_regex();
    for (const auto& t : texts) {
        if (t.find('<') == std::string::npos)
            continue;  // masker.go:39's strings.Contains(t, "<") fast-out
        std::string_view input(t);
        std::string_view found;
        while (RE2::FindAndConsume(&input, re, &found))
            reserved.emplace(found);
    }
    return reserved;
}

// masker.go:88-91's `dataType.IsValid() && dataType != models.
// DataTypeUNSPECIFIED`, collapsed to one range check: Go's generated
// `IsValid` is true for every declared value 0 (Unspecified) through 6
// (Custom), so excluding Unspecified leaves exactly `Credentials..Custom`
// (1-6) -- which also naturally excludes any raw out-of-range value (e.g. a
// hand-built CompiledRule carrying `DataType(999)`, mirroring
// TestMaskerTriggeredDataTypesFiltersInvalidValues).
inline bool is_triggerable_data_type(DataType dt) {
    const auto v = static_cast<int>(dt);
    return v >= static_cast<int>(DataType::Credentials) && v <= static_cast<int>(DataType::Custom);
}

// placeholderfmt.Format, read verbatim: `fmt.Sprintf("<%s_%d>",
// placeholderType, index)`. `placeholder_type` is the RAW (untrimmed)
// `rule.masking.placeholder` string -- never derived from the rule id.
inline std::string render_placeholder(const std::string& placeholder_type, int index) {
    return "<" + placeholder_type + "_" + std::to_string(index) + ">";
}

/**
 * @brief Per-request masking state: dedup map, per-type counters, reserved
 *        placeholders, and the accumulated triggered/replacement sets. Ports
 *        `masker` (masker.go), one instance shared across every text of one
 *        `mask_texts` call so numbering and dedup stay deterministic.
 */
class MaskerState {
public:
    explicit MaskerState(std::unordered_set<std::string> reserved) : reserved_(std::move(reserved)) {}

    /// Ports `maskText` (masker.go:62-100). `matches` must be sorted by
    /// `start` and non-overlapping (exactly what `scan_rules` returns) for
    /// the left-to-right splice to be correct; the `match.start < pos`
    /// defensive skip covers a caller that violates this directly (see the
    /// file-level doc comment).
    /// @throws std::runtime_error if any `match.rule` is null -- `scan_rules`
    ///         never produces this (mirrors `Scanner.hpp`'s own
    ///         `NullCompiledRulePointerThrows` precondition, scan_one_rule's
    ///         `if (!cr) throw ...`), but this function -- like `scan_rules`
    ///         -- accepts a caller-supplied match vector with no guarantee
    ///         every entry came from the scanner.
    std::string mask_text(std::string_view text, const std::vector<ScanMatch>& matches) {
        if (matches.empty())
            return std::string(text);

        std::string out;
        out.reserve(text.size());
        std::size_t pos = 0;

        for (const ScanMatch& match : matches) {
            if (!match.rule)
                throw std::runtime_error("MaskerState::mask_text: matches[] contains a null CompiledRule pointer");
            if (match.start < pos)
                continue;

            const std::string_view original = text.substr(match.start, match.end - match.start);
            const std::string& placeholder_type = match.rule->rule.masking.placeholder;
            if (original.empty() || placeholder_type.empty())
                continue;

            bool created = false;
            const std::string placeholder = placeholder_for_original(std::string(original), placeholder_type, created);

            if (created) {
                replacements_.push_back(
                    Replacement{match.rule->rule.id, match.rule->rule.data_type, std::string(original), placeholder});
            }

            seen_rules_.insert(match.rule->rule.id);
            if (is_triggerable_data_type(match.rule->rule.data_type))
                seen_data_types_.insert(match.rule->rule.data_type);

            out.append(text.substr(pos, match.start - pos));
            out.append(placeholder);
            pos = match.end;
        }
        out.append(text.substr(pos));
        return out;
    }

    /// Sorted unique (ports `triggeredRules`, masker.go:107-114 -- `std::set`
    /// keeps this invariant without a separate sort step).
    std::vector<std::string> triggered_rules() const { return {seen_rules_.begin(), seen_rules_.end()}; }

    /// Sorted unique, numeric order (ports `triggeredDataTypes`, masker.go:
    /// 116-123).
    std::vector<DataType> triggered_data_types() const { return {seen_data_types_.begin(), seen_data_types_.end()}; }

    /// First-encounter order (ports `replacements`, masker.go:102-105).
    const std::vector<Replacement>& replacements() const { return replacements_; }

private:
    // Ports `placeholderForOriginal` (masker.go:125-133).
    std::string placeholder_for_original(const std::string& original,
                                         const std::string& placeholder_type,
                                         bool& created) {
        const auto it = original_to_placeholder_.find(original);
        if (it != original_to_placeholder_.end()) {
            created = false;
            return it->second;
        }
        std::string placeholder = next_placeholder(placeholder_type);
        original_to_placeholder_.emplace(original, placeholder);
        created = true;
        return placeholder;
    }

    // Ports `nextPlaceholder` (masker.go:135-145): increments the
    // per-TYPE counter (even across a skipped/reserved value -- the counter
    // is never rolled back) until the rendered placeholder is not in
    // `reserved_`.
    std::string next_placeholder(const std::string& placeholder_type) {
        while (true) {
            const int counter = ++placeholder_counters_[placeholder_type];
            std::string placeholder = render_placeholder(placeholder_type, counter);
            if (reserved_.find(placeholder) == reserved_.end())
                return placeholder;
        }
    }

    std::unordered_set<std::string> reserved_;
    std::unordered_map<std::string, std::string> original_to_placeholder_;
    std::unordered_map<std::string, int> placeholder_counters_;
    std::set<std::string> seen_rules_;
    std::set<DataType> seen_data_types_;
    std::vector<Replacement> replacements_;
};

/// One text's Phase-A outcome: either its matches, or the exception it threw
/// (captured, not rethrown immediately, so the parallel path can still wait
/// for every other in-flight scan -- mirrors `scanResult`, handle.go:113-118,
/// minus the metrics-only `duration`/`textBytes` fields this port has no use
/// for).
struct TextScanResult {
    std::vector<ScanMatch> matches;
    std::exception_ptr error;
};

// Ports `scanWorkers` (handle.go:179-200), auto branch only -- see the
// file-level doc comment on why the `WithScanConcurrency` override branch has
// no equivalent here.
inline std::size_t text_scan_worker_count(const std::vector<std::string>& texts, const MaskOptions& opts) {
    if (texts.size() < 2)
        return 1;

    const std::size_t min_bytes = opts.parallel_min_bytes == 0 ? kDefaultParallelMinBytes : opts.parallel_min_bytes;
    std::size_t total = 0;
    for (const auto& t : texts)
        total += t.size();
    if (total < min_bytes)
        return 1;

    std::size_t hw = std::thread::hardware_concurrency();
    if (hw == 0)
        hw = 1;
    return std::min(texts.size(), hw);
}

// Ports `scanTexts` (handle.go:126-170): scans every text against `rules`,
// sequentially (stopping at the first failing index -- "no point scanning
// the remaining texts") when fan-out doesn't apply. When it does apply,
// bounds in-flight `std::async` tasks to exactly `text_scan_worker_count`
// (NOT one task per text -- see the file-level doc comment) by chunking
// `texts` into that many contiguous, non-overlapping index ranges, each
// scanned serially by its own task directly into its own slice of `results`
// (disjoint-index writes to a pre-sized vector need no synchronization) --
// the parallel branch always waits for every chunk task before returning,
// mirroring Go's `wg.Wait()`. Each task scans its own texts against the
// FULL, shared `rules` via the unchanged, single-text `scan_rules` -- see
// the file-level doc comment for why concurrent `RE2::Match` on that shared,
// already-compiled rule set is safe (and CI-verifiable) here.
inline std::vector<TextScanResult> scan_texts(const std::vector<std::string>& texts,
                                              const std::vector<const CompiledRule*>& rules,
                                              const MaskOptions& opts) {
    std::vector<TextScanResult> results(texts.size());
    const std::size_t workers = text_scan_worker_count(texts, opts);

    if (workers <= 1) {
        for (std::size_t i = 0; i < texts.size(); ++i) {
            try {
                results[i].matches = scan_rules(texts[i], rules, opts.scan);
            } catch (...) {
                results[i].error = std::current_exception();
                break;
            }
        }
        return results;
    }

    const std::size_t n = texts.size();
    const std::size_t chunk_size = (n + workers - 1) / workers;  // ceil(n / workers)

    std::vector<std::future<void>> futures;
    futures.reserve(workers);
    for (std::size_t w = 0; w < workers; ++w) {
        const std::size_t begin = w * chunk_size;
        const std::size_t end = std::min(n, begin + chunk_size);
        if (begin >= end)
            break;  // fewer texts than workers: later workers get an empty range
        futures.push_back(std::async(std::launch::async, [&texts, &rules, &opts, &results, begin, end]() {
            for (std::size_t i = begin; i < end; ++i) {
                try {
                    results[i].matches = scan_rules(texts[i], rules, opts.scan);
                } catch (...) {
                    results[i].error = std::current_exception();
                }
            }
        }));
    }
    for (auto& f : futures)
        f.get();
    return results;
}

// Ports handle.go:52-56: the first error by LOWEST TEXT INDEX wins and
// propagates. No-op if every text scanned cleanly.
inline void propagate_first_scan_error(const std::vector<TextScanResult>& results) {
    for (std::size_t i = 0; i < results.size(); ++i) {
        if (!results[i].error)
            continue;
        try {
            std::rethrow_exception(results[i].error);
        } catch (const std::exception& e) {
            throw std::runtime_error("mask_texts: scan text[" + std::to_string(i) + "]: " + e.what());
        } catch (...) {
            throw std::runtime_error("mask_texts: scan text[" + std::to_string(i) + "]: unknown exception");
        }
    }
}

}  // namespace detail

/**
 * @brief Scans every text in `texts` against `rules` (Phase A), then masks
 *        them sequentially in text order through one shared masking state
 *        (Phase B) so placeholder numbering and cross-text dedup stay
 *        deterministic. Ports `Handle` (handle.go:26-101) minus the
 *        DataTypes/registry-resolution steps that live one layer up (the
 *        caller resolves `rules` itself, e.g. via `Registry::for_data_types`).
 * @throws std::runtime_error if any text's scan fails -- the first failure by
 *         lowest text index wins (see `detail::propagate_first_scan_error`);
 *         the caller is expected to fail open on this, per the interface
 *         contract. Also throws `std::runtime_error` if a `ScanMatch` reaches
 *         `MaskerState::mask_text` with a null `rule` (see its own doc
 *         comment) -- unreachable through `scan_rules`'s own output, but
 *         `mask_text` accepts no narrower a contract than `scan_rules` itself
 *         does for its `rules` parameter. When the text-level fan-out gate
 *         (`detail::text_scan_worker_count`) is cleared, `detail::scan_texts`
 *         may additionally propagate a `std::system_error` from `std::async`
 *         (per `std::launch::async`'s specification) if the platform cannot
 *         start a new thread; this is NOT caught and wrapped, unlike a
 *         per-text scan failure, so it surfaces with its own type rather than
 *         as `std::runtime_error`.
 */
inline MaskResult mask_texts(const std::vector<std::string>& texts,
                             const std::vector<const CompiledRule*>& rules,
                             const MaskOptions& opts = {}) {
    MaskResult result;

    std::vector<detail::TextScanResult> scan_results = detail::scan_texts(texts, rules, opts);
    detail::propagate_first_scan_error(scan_results);

    detail::MaskerState masker(detail::reserved_placeholders(texts));
    result.masked_texts.resize(texts.size());
    for (std::size_t i = 0; i < texts.size(); ++i) {
        result.masked_texts[i] =
            scan_results[i].matches.empty() ? texts[i] : masker.mask_text(texts[i], scan_results[i].matches);
    }

    result.state.triggered_rule_ids = masker.triggered_rules();
    result.state.triggered_data_types = masker.triggered_data_types();
    result.state.replacements = masker.replacements();
    return result;
}

}  // namespace Guard
