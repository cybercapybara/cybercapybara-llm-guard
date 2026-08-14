/**
 * @file Scanner.hpp
 * @brief Finds sensitive spans in text against a set of compiled rules, and
 *        coalesces overlapping hits into non-overlapping union spans.
 * @details Ports `pkg/guardrails/regex/scanners/sensitive/scan.go`'s
 *          unexported `scanRules` (the pre-prefilter entry point -- the
 *          keyword pre-filter itself lives in `Scanner.ScanRules`, one layer
 *          up in Go, and is out of scope here: `ScanOptions.prefilter_enabled`
 *          is accepted but a no-op passthrough until Task 1.8 wires
 *          `Prefilter.hpp`'s `regex_guarantees_keyword` prover in). Every
 *          divergence from the Go source below was confirmed by reading
 *          `scan.go` and its 837-line `scan_test.go` directly, not assumed.
 *
 *          **Per-rule match enumeration** (`detail::scan_one_rule`) ports
 *          `scanRule` + `buildMatch` + `sensitiveSpan` fused into one pass,
 *          using `RE2::Match(text, pos, end, RE2::UNANCHORED, groups,
 *          ngroups)` in a hand-rolled loop that reproduces Go's
 *          `FindAllStringSubmatchIndex(text, -1)` semantics byte-for-byte,
 *          including its empty-match advance rule (`regexp.go`'s
 *          `allMatches`, read directly, not guessed):
 *            - `pos` starts at 0; the loop runs while `pos <= len(text)`.
 *            - A non-empty match advances `pos` to the match's end and is
 *              always accepted.
 *            - An empty match (`mend == mstart`) is accepted UNLESS it sits
 *              exactly at the previous match's end (`mstart ==
 *              prevMatchEnd`) -- this is what stops a zero-width match from
 *              being reported redundantly right after a real match ends at
 *              the same byte. Either way (accepted or not), `pos` advances
 *              by one *rune* width (`utf8.DecodeRuneInString`), or to
 *              `end + 1` if already at end-of-text -- Go decodes a rune
 *              rather than one byte so the loop can't re-match inside a
 *              multi-byte sequence it just skipped. `Guard::detail::
 *              decode_utf8` (Validators.hpp) already ports that exact
 *              decoder (same U+FFFD-on-invalid-byte, width-1 fallback), so
 *              it's reused here rather than duplicated.
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
 *          own `TestScannerScan_InvalidCaptureGroupIndexesAreSkipped`).
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
 *          (`if (!cr.re) throw ...`) that raises an ordinary C++ exception
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

/// `prefilter_enabled` is accepted but currently a no-op passthrough --
/// Task 1.8 wires the keyword pre-filter (`Prefilter.hpp`'s
/// `regex_guarantees_keyword`) in ahead of the scan. `max_workers`, if
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
        // Out-of-range (including <= 0) is defensive -- Registry::
        // compile_rule already rejects this at compile time, but
        // scan_rules accepts raw CompiledRule* and must not assume every
        // one of them was built through that path. Mirrors Go's
        // `groupIdx+1 >= len(loc)` skip.
        if (group <= 0 || static_cast<std::size_t>(group) >= ngroups)
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
inline void scan_one_rule(std::string_view text, const CompiledRule& cr, std::vector<ScanMatch>& out) {
    if (!cr.re) {
        // Deliberate C++ stand-in for Go's recovered nil-Re panic -- see
        // the file-level doc comment's "Parallel fan-out" section.
        throw std::runtime_error("scan_rules: compiled rule '" + cr.rule.id + "' has a null regex");
    }
    // RE2::Match's empty-text caveat -- see the file-level doc comment.
    // Provably a no-op short-circuit: any match on empty text is itself an
    // empty span, which sensitive_span always drops anyway.
    if (text.empty())
        return;

    const RE2& re = *cr.re;
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
            const std::size_t width = (mstart < end) ? decode_utf8(text, mstart).length : 0;
            pos = (width > 0) ? mstart + width : end + 1;
        } else {
            pos = mend;
        }
        prev_match_end = static_cast<std::ptrdiff_t>(mend);

        if (!accept)
            continue;

        const SensitiveSpan span = sensitive_span(groups, text, cr.rule);
        if (!span.ok)
            continue;
        const std::size_t len = span.end - span.start;
        if (cr.rule.min_length > 0 && len < cr.rule.min_length)
            continue;
        if (!passes_validators(text.substr(span.start, len), cr.rule))
            continue;

        out.push_back(ScanMatch{span.start, span.end, &cr});
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
        scan_one_rule(text, *cr, all);
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
    // prefilter_enabled: no-op passthrough. See the file-level doc comment.
    (void)opts.prefilter_enabled;

    if (rules.empty())
        return {};

    std::vector<ScanMatch> candidates;
    if (text.size() < detail::kParallelTextThreshold || rules.size() <= detail::kParallelRuleThreshold) {
        candidates = detail::scan_serial(text, rules);
    } else {
        candidates = detail::scan_parallel(text, rules, opts);
    }
    return detail::resolve_conflicts(std::move(candidates));
}

}  // namespace Guard
