/**
 * @file Scanner.hpp
 * @brief Finds sensitive spans in text against a set of compiled rules, and
 *        coalesces overlapping hits into non-overlapping union spans.
 * @details Ports `pkg/guardrails/regex/scanners/sensitive/scan.go`'s
 *          unexported `scanRules` PLUS `Scanner.ScanRules`'s keyword
 *          pre-filter step (`filterByKeywords` / `containsAnyKeyword`) --
 *          the two are fused into this file's single `scan_rules` entry
 *          point rather than split across two layers the way Go's
 *          `Scanner.ScanRules` (pre-filter) -> `scanRules` (regex fan-out)
 *          are, since this port has no separate `Scanner` type wrapping a
 *          `*Registry` yet (that lands in a later phase). See
 *          `detail::filter_by_keywords` below for the pre-filter itself
 *          (Task 1.8; ports `filterByKeywords`, scan.go:82-106) and the
 *          `ScanOptions.prefilter_enabled` doc comment for how it composes
 *          with the serial/parallel dispatch gate. Every
 *          divergence from the Go source below was confirmed by reading
 *          `scan.go` and its 837-line `scan_test.go` directly, not assumed.
 *
 *          **Per-rule match enumeration** (`detail::scan_one_rule`) ports
 *          `scanRule` + `buildMatch` + `sensitiveSpan` fused into one pass,
 *          using `RE2::Match(text, pos, end, RE2::UNANCHORED, groups,
 *          ngroups)` in a hand-rolled loop that reproduces Go's
 *          `FindAllStringSubmatchIndex(text, -1)` semantics -- OUTPUT-
 *          equivalent to Go, not a byte-for-byte port of its iteration
 *          count, including its empty-match advance rule (`regexp.go`'s
 *          `allMatches`, read directly, not guessed):
 *            - `pos` starts at 0; the loop runs while `pos <= len(text)`.
 *            - A non-empty match advances `pos` to the match's end and is
 *              always accepted.
 *            - An empty match (`mend == mstart`) is accepted UNLESS it sits
 *              exactly at the previous match's end (`mstart ==
 *              prevMatchEnd`) -- this is what stops a zero-width match from
 *              being reported redundantly right after a real match ends at
 *              the same byte. Either way (accepted or not), Go advances
 *              `pos` by one *rune* width decoded AT `pos` itself
 *              (`utf8.DecodeRuneInString(s[pos:end])`), or to `end + 1` if
 *              already at end-of-text. This port instead decodes AT
 *              `mstart` (the match's own start) and advances from there --
 *              a deliberate divergence, not an oversight, because `pos` and
 *              `mstart` can differ: an UNANCHORED search launched from
 *              `pos` returns the *leftmost reachable* match, which for a
 *              not-everywhere-nullable pattern (e.g. an alternation like
 *              `\n|$`) can start strictly after `pos` whenever nothing in
 *              `[pos, mstart)` can begin a match -- that range is exactly
 *              why the search skipped past it. Proof sketch that the two
 *              are output-equivalent despite this: any extra iterations
 *              Go's `pos`-based advance causes beyond what this port runs
 *              are re-discoveries of that SAME `mstart` position (nothing
 *              in `[pos, mstart)` can be a match start, so re-searching
 *              from anywhere in that range lands right back on `mstart`),
 *              and every such re-discovery is itself an empty match --
 *              either rejected here (`mstart == prevMatchEnd`, having
 *              already been counted once) or accepted-then-dropped by
 *              `sensitive_span` (an empty span is always dropped) -- so it
 *              contributes nothing to the delivered match set either way.
 *              Decoding at `mstart` instead skips straight past those
 *              guaranteed-empty re-discoveries, producing the identical
 *              final (filtered, sorted) match list in strictly fewer loop
 *              iterations. Go decodes a rune rather than one byte so the
 *              loop can't re-match inside a multi-byte sequence it just
 *              skipped. `Guard::detail::decode_utf8` (Validators.hpp)
 *              already ports that exact decoder (same U+FFFD-on-invalid-
 *              byte, width-1 fallback), so it's reused here rather than
 *              duplicated.
 *            - `RE2::Match`'s own doc comment carries a caveat this port
 *              leans on directly: "Passing text == absl::string_view() ...
 *              it will not be possible to tell whether submatch i matched
 *              the empty string or did not match: either way, submatch[i]
 *              .data() == NULL." `absl::string_view`'s equality is by
 *              content, so this fires for ANY empty `text` argument, not
 *              just a literal `absl::string_view{}` -- which would make the
 *              `groups[0].data() - text.data()` pointer arithmetic below
 *              undefined for an empty scan text. `scan_one_rule` therefore
 *              short-circuits on `text.empty()` before ever calling `Match`.
 *              This is provably a no-op simplification, not a behavior
 *              change: the only match an empty text can ever produce is an
 *              empty span at position 0, and `sensitive_span` (below, like
 *              Go's `sensitiveSpan`) always drops an empty span -- so the
 *              observable result (`filter.empty is skipped"` in
 *              `scan_test.go`, `regex "a*"` against `text ""`) is identical
 *              either way.
 *
 *          **Semantic span selection** (`detail::sensitive_span` ports
 *          `sensitiveSpan`): the first entry in `rule.masking.
 *          capture_groups` (in configured order) whose group PARTICIPATED
 *          and matched non-empty; else the full match, if non-empty; else
 *          the whole candidate is dropped. RE2 reports a group that didn't
 *          participate in a match with `data() == nullptr` on its
 *          `absl::string_view` submatch slot (this vcpkg-pinned RE2 uses
 *          `absl::string_view` -- itself `using std::string_view` under
 *          C++17+ -- directly in `RE2::Match`'s signature, confirmed by
 *          reading `re2.h` at the exact commit `vcpkg.json`'s baseline
 *          pins, not assumed from an older `re2::StringPiece`-based API)
 *          (documented on `RE2::Match` itself: "submatch[1].data() = NULL"
 *          for the unmatched alternate in `(foo)|(bar)baz`) -- distinct from
 *          a group that matched zero bytes, which has a non-null `data()`
 *          and `size() == 0`. Both cases fall through to the next
 *          configured group, mirroring Go's single check
 *          `groupStart < 0 || groupEnd <= groupStart`. A configured group
 *          index beyond the regex's actual capture count is skipped the
 *          same way (Go: `groupIdx+1 >= len(loc)`) -- defensive, since
 *          `Registry::compile_rule` already rejects this at compile time,
 *          but `scan_rules` takes raw `CompiledRule*` and must not assume
 *          every one of them came through that path (see
 *          `GuardScanner.InvalidCaptureGroupIndexSkipsMatch` in the test
 *          file, which builds one that didn't, exactly like `scan_test.go`'s
 *          own `TestScannerScan_InvalidCaptureGroupIndexesAreSkipped`). A
 *          configured group of exactly `0` is NOT skipped, and is not
 *          "defensive parity" with anything -- it is genuine Go behavior:
 *          `sensitiveSpan`'s `groupIdx := group * 2` makes `group == 0`
 *          index straight into `loc[0:2]`, the full-match slot, so Go
 *          silently treats a configured `0` exactly like the full match.
 *          `Registry::compile_rule` rejects `capture_groups` entries `<= 0`
 *          at compile time, so this is unreachable through the normal
 *          compile path (see `GuardScanner.CaptureGroupZeroSelectsFullMatch`,
 *          which builds a raw `CompiledRule` to reach it) -- but a
 *          faithful port matches Go's actual behavior here rather than
 *          inventing a stricter divergent one. Only a genuinely negative
 *          group index is defensive-skipped (Go's own guard doesn't cover
 *          it either, but `loc[negative]` would panic there; RE2 has
 *          nothing to mirror for that case, so this port just skips it
 *          rather than indexing out of bounds).
 *
 *          **Drop conditions**, checked in `sensitiveSpan`/`scanRule`
 *          order: selected span empty -> drop; `rule.min_length > 0 &&
 *          span.size() < min_length` -> drop; `!passes_validators(span,
 *          rule)` -> drop.
 *
 *          **Overlap coalescing** (`detail::resolve_conflicts` ports
 *          `resolveConflicts` + `coalesce` + `preferAsPrimary`): candidates
 *          are sorted by start ascending (longest-first, then rule id, as a
 *          tie-break that only affects sort stability, not the outcome --
 *          `coalesce`'s primary selection independently re-compares every
 *          member of a run via the same `prefer_as_primary` predicate
 *          Go's `preferAsPrimary` uses: longest constituent wins; tied
 *          length -> lowest start; still tied -> lexicographically-lower
 *          rule id, for determinism). A single sweep grows a "run" while
 *          `next.start < run_end`; the run's union span is `[run_start,
 *          run_end)`, attributed to whichever constituent `prefer_as_primary`
 *          selects. A run of exactly one match passes through unchanged
 *          (also matching Go). Two spans that only TOUCH
 *          (`next.start == run_end`) do NOT merge -- confirmed directly
 *          against `scan_test.go`'s `"adjacent matches are kept"` case and
 *          the `m.Start < runEnd` (strict) condition in `resolveConflicts`.
 *          Masking the union rather than dropping the shorter/losing match
 *          is deliberate (per the Go doc comment, kept here): dropping
 *          either match would emit that match's exclusive bytes verbatim,
 *          leaking part of a detected secret.
 *
 *          **Parallel fan-out** (`detail::scan_parallel` ports
 *          `scanParallel` + `bucketRules`): triggered by `scan_rules` only
 *          when `text.size() >= kParallelTextThreshold (4096)` AND
 *          `rules.size() > kParallelRuleThreshold (4)` -- i.e. the
 *          serial-path guard is `text.size() < 4096 || rules.size() <= 4`,
 *          read directly off `scanRules`'s `if` condition, operators and
 *          all. Rules are bucketed round-robin (`i % num_workers`) across
 *          `min(rules.size(), num_workers)` workers, where `num_workers` is
 *          `opts.max_workers` if non-zero, else
 *          `std::thread::hardware_concurrency()` (falling back to 1 if that
 *          reports 0, which the standard allows when the value "is not
 *          computable or well-defined") -- ports `bucketRules`'s `min(len
 *          (rules), runtime.NumCPU())`, with `max_workers` standing in for
 *          `runtime.NumCPU()` so tests can pin a worker count instead of
 *          depending on the CI runner's core count. Each bucket runs on its
 *          own `std::async(std::launch::async, ...)` task; results and
 *          exceptions are collected in bucket-index order (mirroring Go's
 *          `for _, err := range errs` after `wg.Wait()` -- the first
 *          bucket THAT FAILED, by index, not by completion order, is the
 *          one whose error surfaces) and merged into one candidate list
 *          before `resolve_conflicts` runs -- identically to the serial
 *          path, so fan-out is invisible in the final output (see
 *          `GuardScanner.ParallelMatchesSerialOnLargeText`, which compares
 *          `detail::scan_parallel` against `detail::scan_serial` directly
 *          on the SAME 100 KiB text).
 *
 *          Go recovers a per-worker goroutine *panic* (`recover()`) and
 *          turns it into an `error` so the caller degrades fail-open
 *          instead of crashing the whole process; its own test manufactures
 *          this via a `CompiledRule` with a nil `Re`, which panics inside
 *          `FindAllStringSubmatchIndex`. C++ has no panic/recover, and
 *          deliberately inducing the equivalent (dereferencing a null
 *          `RE2*`) would be undefined behavior that a sanitizer build (this
 *          repo's CI runs ASan+UBSan) is supposed to catch, not paper over
 *          -- so this port does not attempt to "recover" from a crash.
 *          Instead, `scan_one_rule` has an explicit precondition check
 *          (`if (!cr->re) throw ...`) that raises an ordinary C++ exception
 *          on exactly the same manufactured input (a `CompiledRule` with a
 *          null `re`), which a worker's `std::async` task then surfaces
 *          through its `std::future` the normal way. The observable
 *          contract Task 1.6 cares about --  a broken worker's failure
 *          becomes a `std::runtime_error` from `scan_rules`, so the caller
 *          fails open instead of the process crashing -- is preserved
 *          end-to-end; only the mechanism (checked exception vs.
 *          recovered panic) differs, and is documented here as a
 *          deliberate adaptation rather than a literal transliteration.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <future>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <re2/re2.h>

#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/Unicode.hpp"
#include "guard/Validators.hpp"

namespace Guard {

/// One coalesced (non-overlapping) sensitive span found by `scan_rules`.
/// Deliberately thinner than Go's `Match`: it carries no cached
/// `FullText`/`Placeholder` -- callers (the masker, later phases) recover
/// the original bytes via `text.substr(start, end - start)` and everything
/// else via `rule->rule` / `rule->rule.masking`.
struct ScanMatch {
    std::size_t start;
    std::size_t end;
    const CompiledRule* rule;
};

/// `prefilter_enabled` (Task 1.8): when true, `scan_rules` first drops every
/// `prefilter_eligible` rule (`Registry.hpp`) whose `rule.keywords` (already
/// lowercased at YAML-load time) are all absent from the text -- see
/// `detail::filter_by_keywords`. A rule that is NOT `prefilter_eligible`
/// (no keywords, or the prover couldn't prove the guarantee) is always kept,
/// so this is recall-preserving by construction: enabling it can only ever
/// remove work, never a match `scan_rules` would otherwise have returned.
/// The filtered rule count (not the original) then feeds the existing
/// serial/parallel dispatch gate below, mirroring Go's `ScanRules` (which
/// filters, THEN calls `scanRules` on the filtered set). `max_workers`, if
/// non-zero, overrides `std::thread::hardware_concurrency()` as the
/// parallel-fan-out worker count (see `detail::compute_worker_count`) --
/// mainly so tests can pin a deterministic worker count instead of
/// depending on the CI runner's core count.
struct ScanOptions {
    bool prefilter_enabled = false;
    unsigned max_workers = 0;  // 0 = auto (hardware_concurrency, min 1)
};

namespace detail {

// scanRules's own size gate, read verbatim off scan.go:60-63/66: the
// serial path runs when `text.size() < kParallelTextThreshold ||
// rules.size() <= kParallelRuleThreshold` -- i.e. parallel fan-out needs
// BOTH text.size() >= 4096 AND rules.size() > 4.
inline constexpr std::size_t kParallelTextThreshold = 4 * 1024;
inline constexpr std::size_t kParallelRuleThreshold = 4;

// Ports `filterByKeywords` + `containsAnyKeyword` (scan.go:82-106): drops
// every prefilter_eligible rule whose keywords are all absent from `text`,
// so the caller skips their regex entirely. A rule that is NOT
// prefilter_eligible (no keywords declared, or Prefilter.hpp's prover
// couldn't prove every match contains one) is always kept -- this is what
// makes the pre-filter recall-preserving. `rules` may be a shared/reused
// vector (Go's own comment on `filterByKeywords` makes the same point about
// `rules []registry.CompiledRule` there), so this returns a freshly
// allocated filtered view and never mutates the input.
//
// Matches against `cr->prefilter_keywords` (Registry.hpp), NOT
// `cr->rule.keywords` -- the former is guaranteed lowercased by
// `Registry::compile_rule` regardless of how the rule was constructed; the
// latter is only lowercased as a side effect of the YAML loader
// (`RulesYaml.hpp`) and is NOT guaranteed lowercased for a rule built any
// other way (e.g. a future configuration API). Matching raw, possibly
// mixed-case keywords against `lower` (always lowercased below) would
// silently never hit for such a rule -- prefilter_eligible would be true
// (the prover itself lowercases internally) but every scan would find zero
// keyword hits, dropping every match the regex would otherwise have found.
//
// `text` is lowercased at most once (lazily, only once the first eligible
// rule is seen), matching Go's `lowered` bool guard exactly: a rule set with
// no eligible rules pays nothing and skips the whole body copy.
//
// A null `CompiledRule*` is passed through unfiltered rather than
// dereferenced -- `scan_rules`'s own null-pointer contract
// (`GuardScanner.NullCompiledRulePointerThrows`) is enforced downstream in
// `scan_one_rule`, and must still fire the same way whether or not the
// pre-filter is enabled.
inline std::vector<const CompiledRule*> filter_by_keywords(std::string_view text,
                                                           const std::vector<const CompiledRule*>& rules) {
    std::string lower;
    bool lowered = false;

    std::vector<const CompiledRule*> out;
    out.reserve(rules.size());
    for (const CompiledRule* cr : rules) {
        if (cr == nullptr || !cr->prefilter_eligible) {
            out.push_back(cr);  // ineligible (or not yet validated) rules are always scanned
            continue;
        }
        if (!lowered) {
            lower = to_lower_utf8(text);
            lowered = true;
        }
        bool hit = false;
        for (const auto& kw : cr->prefilter_keywords) {
            if (!kw.empty() && lower.find(kw) != std::string::npos) {
                hit = true;
                break;
            }
        }
        if (hit)
            out.push_back(cr);
    }
    return out;
}

/// The semantic span selected from one raw regex match, or `ok == false`
/// if this match should be dropped entirely (mirrors `sensitiveSpan`'s
/// `(start, end, ok)` return).
struct SensitiveSpan {
    std::size_t start{0};
    std::size_t end{0};
    bool ok{false};
};

// Ports `sensitiveSpan` (scan.go:224-249). `groups[0]` is always the full
// match (`RE2::Match`'s convention, same as Go's `loc[0:2]`); `groups[g]`
// for `g >= 1` is capture group `g`, sized `NumberOfCapturingGroups() + 1`
// total, matching Go's fixed-length `loc` slice. An unmatched group has
// `data() == nullptr` (RE2's documented convention); a group that matched
// zero bytes has a non-null `data()` and `size() == 0` -- both fall
// through to the next configured group, exactly like Go's single
// `groupStart < 0 || groupEnd <= groupStart` check collapses both cases.
inline SensitiveSpan sensitive_span(const std::vector<std::string_view>& groups,
                                    std::string_view text,
                                    const Rule& rule) {
    if (rule.masking.capture_groups.empty()) {
        const std::string_view full = groups[0];
        const auto start = static_cast<std::size_t>(full.data() - text.data());
        const auto end = start + full.size();
        return SensitiveSpan{start, end, start < end};
    }

    const std::size_t ngroups = groups.size();
    for (int group : rule.masking.capture_groups) {
        // group == 0 is NOT skipped: Go's `groupIdx := group * 2` makes
        // group 0 index straight into `loc[0:2]` -- the full match slot --
        // so `sensitiveSpan` treats a configured `0` exactly like the
        // full match, and this port matches that behavior rather than
        // inventing a stricter rejection. Only a negative group is
        // defensive-skipped here (Go's `groupIdx+1 >= len(loc)` guard
        // doesn't cover negative indexes either, but `loc[negative]`
        // would panic in Go; RE2 has no test/behavior to mirror for that
        // case, so this port just skips it rather than indexing OOB).
        // Out-of-range-above is the same defensive story as before --
        // Registry::compile_rule already rejects both cases at compile
        // time, but scan_rules accepts raw CompiledRule* and must not
        // assume every one of them was built through that path.
        if (group < 0 || static_cast<std::size_t>(group) >= ngroups)
            continue;
        const std::string_view g = groups[static_cast<std::size_t>(group)];
        if (g.data() == nullptr)
            continue;  // didn't participate in this match
        const auto start = static_cast<std::size_t>(g.data() - text.data());
        const auto end = start + g.size();
        if (end <= start)
            continue;  // participated but matched empty
        return SensitiveSpan{start, end, true};
    }
    return SensitiveSpan{};
}

// Enumerates every match of `cr.re` in `text` (Go's `FindAllStringSubmatchIndex(text, -1)`,
// see the file-level doc comment for the empty-match advance rule this
// reproduces), and for each surviving match applies span selection +
// min_length + validators, appending accepted hits to `out`.
inline void scan_one_rule(std::string_view text, const CompiledRule* cr, std::vector<ScanMatch>& out) {
    if (!cr) {
        // `rules` is caller-supplied (`scan_rules`'s own parameter, or a
        // hand-built vector in a test); nothing upstream of this function
        // guarantees every entry is non-null the way Registry::for_data_types
        // and Registry::by_id do for their own return values. Dereferencing
        // a null CompiledRule* would be a real crash, not the recoverable
        // "broken rule" scenario `!cr->re` below models -- guard it
        // separately so a null entry fails the same documented way
        // (std::runtime_error, caller fails open) instead of crashing.
        throw std::runtime_error("scan_rules: rules[] contains a null CompiledRule pointer");
    }
    if (!cr->re) {
        // Deliberate C++ stand-in for Go's recovered nil-Re panic -- see
        // the file-level doc comment's "Parallel fan-out" section.
        throw std::runtime_error("scan_rules: compiled rule '" + cr->rule.id + "' has a null regex");
    }
    // RE2::Match's empty-text caveat -- see the file-level doc comment.
    // Provably a no-op short-circuit: any match on empty text is itself an
    // empty span, which sensitive_span always drops anyway.
    if (text.empty())
        return;

    const RE2& re = *cr->re;
    const int ngroups = re.NumberOfCapturingGroups() + 1;
    const std::size_t end = text.size();
    std::size_t pos = 0;
    std::ptrdiff_t prev_match_end = -1;
    std::vector<std::string_view> groups(static_cast<std::size_t>(ngroups));

    while (pos <= end) {
        if (!re.Match(text, pos, end, RE2::UNANCHORED, groups.data(), ngroups))
            break;

        const auto mstart = static_cast<std::size_t>(groups[0].data() - text.data());
        const auto mend = mstart + groups[0].size();

        bool accept = true;
        if (mend == mstart) {
            // Empty match: reject only if it sits exactly where the
            // previous match ended (regexp.go's allMatches).
            if (static_cast<std::ptrdiff_t>(mstart) == prev_match_end)
                accept = false;
            // Advances from `mstart` (the match's own start), not from
            // `pos` (this iteration's search floor) the way Go's `pos +=
            // width` does -- output-equivalent to Go, not byte-for-byte:
            // when the leftmost reachable match starts strictly after
            // `pos` (nothing in `[pos, mstart)` can start a match, which is
            // exactly why the unanchored search skipped past it), Go's
            // pos-based advance can re-search that same dead zone and
            // re-discover the identical empty match one or more extra
            // times before finally moving past it -- every one of those
            // extra rediscoveries is itself empty, so it is either
            // rejected here (adjacent-to-prior-match) or accepted-then-
            // dropped by sensitive_span (empty span always drops); either
            // way it contributes nothing to the delivered match set.
            // Advancing straight from `mstart` instead skips those
            // guaranteed-empty rediscoveries outright, so the final
            // (sorted, filtered) match list is identical to Go's while
            // this loop runs strictly fewer iterations.
            const std::size_t width = (mstart < end) ? decode_utf8(text, mstart).length : 0;
            pos = (width > 0) ? mstart + width : end + 1;
        } else {
            pos = mend;
        }
        prev_match_end = static_cast<std::ptrdiff_t>(mend);

        if (!accept)
            continue;

        const SensitiveSpan span = sensitive_span(groups, text, cr->rule);
        if (!span.ok)
            continue;
        const std::size_t len = span.end - span.start;
        if (cr->rule.min_length > 0 && len < cr->rule.min_length)
            continue;
        if (!passes_validators(text.substr(span.start, len), cr->rule))
            continue;

        out.push_back(ScanMatch{span.start, span.end, cr});
    }
}

/// Runs every rule against `text` in the caller's own thread/task, in rule
/// order. Ports the `var all []Match; for _, cr := range rules { ... }`
/// loop shared by both `scanRules`'s serial branch and each `scanParallel`
/// worker (scan.go:70-74/146-149) -- reused here as the body of one bucket
/// too (see `scan_parallel`).
inline std::vector<ScanMatch> scan_serial(std::string_view text, const std::vector<const CompiledRule*>& rules) {
    std::vector<ScanMatch> all;
    for (const CompiledRule* cr : rules)
        scan_one_rule(text, cr, all);
    return all;
}

// Ports `bucketRules`'s `min(len(rules), runtime.NumCPU())`, with
// `max_workers` (if non-zero) standing in for `runtime.NumCPU()`.
// `hardware_concurrency()` may return 0 when "not computable or
// well-defined" (the standard's own wording) -- falls back to 1 rather
// than dividing rules into zero buckets.
inline std::size_t compute_worker_count(std::size_t num_rules, unsigned max_workers) {
    std::size_t hw = static_cast<std::size_t>(max_workers);
    if (hw == 0)
        hw = std::thread::hardware_concurrency();
    if (hw == 0)
        hw = 1;
    return std::min(num_rules, hw);
}

// Ports `scanParallel` + `bucketRules` (scan.go:121-179). See the
// file-level doc comment's "Parallel fan-out" section for the worker
// design and exception-propagation adaptation.
inline std::vector<ScanMatch> scan_parallel(std::string_view text,
                                            const std::vector<const CompiledRule*>& rules,
                                            const ScanOptions& opts) {
    const std::size_t num_workers = compute_worker_count(rules.size(), opts.max_workers);
    if (num_workers == 0)
        return {};

    std::vector<std::vector<const CompiledRule*>> buckets(num_workers);
    for (std::size_t i = 0; i < rules.size(); ++i)
        buckets[i % num_workers].push_back(rules[i]);

    std::vector<std::future<std::vector<ScanMatch>>> futures;
    futures.reserve(buckets.size());
    for (const auto& bucket : buckets) {
        futures.push_back(std::async(std::launch::async, [text, &bucket]() { return scan_serial(text, bucket); }));
    }

    // Collect every bucket (mirrors Go's wg.Wait() -- wait for all workers
    // regardless of failures), then surface the first failure by BUCKET
    // INDEX order (mirrors `for _, err := range errs`), not completion
    // order.
    std::vector<std::vector<ScanMatch>> results(futures.size());
    std::exception_ptr first_error;
    for (std::size_t i = 0; i < futures.size(); ++i) {
        try {
            results[i] = futures[i].get();
        } catch (...) {
            if (!first_error)
                first_error = std::current_exception();
        }
    }
    if (first_error) {
        try {
            std::rethrow_exception(first_error);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("sensitive scan worker failed: ") + e.what());
        } catch (...) {
            throw std::runtime_error("sensitive scan worker failed: unknown exception");
        }
    }

    std::vector<ScanMatch> all;
    for (auto& bucket_matches : results)
        all.insert(
            all.end(), std::make_move_iterator(bucket_matches.begin()), std::make_move_iterator(bucket_matches.end()));
    return all;
}

// Sort key for resolve_conflicts's sweep: start ascending, then longest
// first, then rule id -- ports `resolveConflicts`'s `slices.SortFunc`
// (scan.go:268-277). Only the start-ascending part is load-bearing for
// correctness (it's what the run-building sweep depends on); the rest is
// kept for exact fidelity, though `prefer_as_primary` below independently
// re-derives the primary of a run regardless of sort order.
inline bool scan_match_less(const ScanMatch& a, const ScanMatch& b) {
    if (a.start != b.start)
        return a.start < b.start;
    const std::size_t la = a.end - a.start;
    const std::size_t lb = b.end - b.start;
    if (la != lb)
        return la > lb;  // longest first
    return a.rule->rule.id < b.rule->rule.id;
}

// Ports `preferAsPrimary` (scan.go:330-338): true if `m` should represent
// a merged run in place of `cur` -- longest wins, then lowest start, then
// lexicographically-lower rule id (deterministic tie-break).
inline bool prefer_as_primary(const ScanMatch& m, const ScanMatch& cur) {
    const std::size_t ml = m.end - m.start;
    const std::size_t cl = cur.end - cur.start;
    if (ml != cl)
        return ml > cl;
    if (m.start != cur.start)
        return m.start < cur.start;
    return m.rule->rule.id < cur.rule->rule.id;
}

// Ports `coalesce` (scan.go:308-326): a one-element run passes through
// verbatim (preserving its own exact span); a multi-element run becomes
// one union span `[start, end)` attributed to whichever constituent
// `prefer_as_primary` selects.
inline ScanMatch coalesce_run(std::size_t start, std::size_t end, const std::vector<ScanMatch>& run) {
    if (run.size() == 1)
        return run[0];
    const ScanMatch* primary = &run[0];
    for (std::size_t i = 1; i < run.size(); ++i)
        if (prefer_as_primary(run[i], *primary))
            primary = &run[i];
    return ScanMatch{start, end, primary->rule};
}

// Ports `resolveConflicts` (scan.go:263-301): sorts by start, then sweeps
// growing one coalesced "run" until a gap (`next.start >= run_end`, i.e.
// touching-but-not-overlapping spans do NOT merge -- confirmed against
// scan_test.go's "adjacent matches are kept" case), emitting each run via
// coalesce_run. Result is sorted by start and strictly non-overlapping.
inline std::vector<ScanMatch> resolve_conflicts(std::vector<ScanMatch> matches) {
    if (matches.size() <= 1)
        return matches;

    std::sort(matches.begin(), matches.end(), scan_match_less);

    std::vector<ScanMatch> resolved;
    resolved.reserve(matches.size());

    std::size_t run_start = matches[0].start;
    std::size_t run_end = matches[0].end;
    std::vector<ScanMatch> run{matches[0]};
    for (std::size_t i = 1; i < matches.size(); ++i) {
        const ScanMatch& m = matches[i];
        if (m.start < run_end) {
            run.push_back(m);
            if (m.end > run_end)
                run_end = m.end;
            continue;
        }
        resolved.push_back(coalesce_run(run_start, run_end, run));
        run_start = m.start;
        run_end = m.end;
        run.clear();
        run.push_back(m);
    }
    resolved.push_back(coalesce_run(run_start, run_end, run));
    return resolved;
}

}  // namespace detail

/**
 * @brief Finds every sensitive span `rules` match in `text`, coalesces
 *        overlapping hits into non-overlapping union spans, and returns
 *        them sorted by start.
 * @throws std::runtime_error if a parallel worker fails internally (the
 *         caller is expected to fail open on this, per the interface
 *         contract).
 */
inline std::vector<ScanMatch> scan_rules(std::string_view text,
                                         const std::vector<const CompiledRule*>& rules,
                                         const ScanOptions& opts = {}) {
    if (rules.empty())
        return {};

    // Task 1.8: apply the keyword pre-filter (if enabled) BEFORE the
    // serial/parallel dispatch gate below, so the gate sees the (possibly
    // smaller) filtered rule count -- mirrors Go's ScanRules, which filters
    // first and only then calls scanRules on the filtered set. See
    // detail::filter_by_keywords and the ScanOptions.prefilter_enabled doc
    // comment for why this can only ever remove work, never a match.
    std::vector<const CompiledRule*> filtered_storage;
    const std::vector<const CompiledRule*>* active_rules = &rules;
    if (opts.prefilter_enabled) {
        filtered_storage = detail::filter_by_keywords(text, rules);
        active_rules = &filtered_storage;
        if (active_rules->empty())
            return {};
    }

    std::vector<ScanMatch> candidates;
    if (text.size() < detail::kParallelTextThreshold || active_rules->size() <= detail::kParallelRuleThreshold) {
        candidates = detail::scan_serial(text, *active_rules);
    } else {
        candidates = detail::scan_parallel(text, *active_rules, opts);
    }
    return detail::resolve_conflicts(std::move(candidates));
}

}  // namespace Guard
