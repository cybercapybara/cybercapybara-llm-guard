/**
 * @file test_guard_scanner.cpp
 * @brief Unit tests for Guard::scan_rules / Guard::ScanMatch / the overlap
 *        coalescing sweep in Guard::detail.
 *
 * Ports the behavioral cases from the Go reference's
 * `pkg/guardrails/regex/scanners/sensitive/scan_test.go` (837 lines):
 * `TestScannerScan_MatchFields`, `_UsesByteOffsets`, `_CaptureGroups` (all 4
 * subtests), `_Filtering` (all 5 subtests),
 * `_InvalidCaptureGroupIndexesAreSkipped`, `_ResolveConflicts` (all 6
 * subtests), `TestScanRules_WorkerPanicRecoveredAsError`, and
 * `TestScanRules_SequentialAndParallelPathsAgree`. The keyword-pre-filter
 * tests in that file (`_KeywordPrefilter*`) exercise `Scanner.ScanRules`, a
 * layer above the `scanRules` free function this header ports -- they are
 * out of scope here (`ScanOptions.prefilter_enabled` is a no-op passthrough
 * until Task 1.8; see Scanner.hpp's file-level doc comment).
 */

#include <algorithm>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <re2/re2.h>

#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/Scanner.hpp"

namespace {

Guard::Rule make_rule(std::string id,
                      std::string regex,
                      std::vector<int> capture_groups = {},
                      std::string placeholder = "TEST",
                      Guard::DataType data_type = Guard::DataType::Custom) {
    Guard::Rule r;
    r.id = std::move(id);
    r.name = r.id;
    r.data_type = data_type;
    r.regex = std::move(regex);
    r.masking.capture_groups = std::move(capture_groups);
    r.masking.placeholder = std::move(placeholder);
    return r;
}

// Builds a Registry from `defs` and returns stable `const CompiledRule*`
// pointers (one per def, in order) alongside the Registry that owns them --
// Registry::all()'s storage never mutates after build(), so these pointers
// stay valid for as long as the returned Registry is kept alive.
struct RuleFixture {
    std::shared_ptr<const Guard::Registry> registry;
    std::vector<const Guard::CompiledRule*> rules;
};

RuleFixture build_rules(std::vector<Guard::Rule> defs) {
    RuleFixture fx;
    fx.registry = Guard::Registry::build(defs);
    fx.rules.reserve(defs.size());
    for (const auto& d : defs)
        fx.rules.push_back(fx.registry->by_id(d.id));
    return fx;
}

void expect_match(const Guard::ScanMatch& m, std::size_t start, std::size_t end, const std::string& rule_id) {
    EXPECT_EQ(m.start, start);
    EXPECT_EQ(m.end, end);
    ASSERT_NE(m.rule, nullptr);
    EXPECT_EQ(m.rule->rule.id, rule_id);
}

}  // namespace

// ── Threshold constants (documentation pin) ──────────────────────────────

TEST(GuardScanner, ParallelThresholdConstantsMatchGoReference) {
    EXPECT_EQ(Guard::detail::kParallelTextThreshold, 4096u);
    EXPECT_EQ(Guard::detail::kParallelRuleThreshold, 4u);
}

// ── Empty inputs (brief bullet g) ─────────────────────────────────────────

TEST(GuardScanner, EmptyRulesReturnsEmpty) {
    auto matches = Guard::scan_rules("token=secret", {});
    EXPECT_TRUE(matches.empty());
}

TEST(GuardScanner, EmptyTextIsDropped) {
    // Mirrors scan_test.go's "empty full match is skipped": regex `a*` can
    // match the empty string, but the empty span it would select is always
    // dropped -- see Scanner.hpp's file-level doc comment on the
    // RE2::Match empty-text caveat this sidesteps entirely.
    auto fx = build_rules({make_rule("filter.empty", "a*")});
    auto matches = Guard::scan_rules("", fx.rules);
    EXPECT_TRUE(matches.empty());
}

// ── Match fields / byte offsets ───────────────────────────────────────────

TEST(GuardScanner, MatchFieldsCaptureGroupAndOffsets) {
    auto fx = build_rules({make_rule("secrets.token", "token=([A-Z0-9]+)", {1}, "TOKEN")});
    auto matches = Guard::scan_rules("prefix token=ABC123 suffix", fx.rules);
    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 13, 19, "secrets.token");
}

TEST(GuardScanner, UsesByteOffsetsForUnicodeText) {
    auto fx = build_rules({make_rule("unicode.token", "секрет=([a-z]+)", {1}, "SECRET")});
    const std::string text = "до секрет=value после";
    const std::string prefix = "до секрет=";
    const std::string value = "value";

    auto matches = Guard::scan_rules(text, fx.rules);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], prefix.size(), prefix.size() + value.size(), "unicode.token");
    EXPECT_EQ(text.substr(matches[0].start, matches[0].end - matches[0].start), value);
}

// ── Capture group selection ───────────────────────────────────────────────

TEST(GuardScanner, FullMatchKeptWhenNoCaptureGroupsConfigured) {
    auto fx = build_rules({make_rule("test.rule", "secret;")});
    auto matches = Guard::scan_rules("x secret; y", fx.rules);
    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 2, 9, "test.rule");
}

TEST(GuardScanner, SingleCaptureGroupSelectsSemanticValue) {
    auto fx = build_rules({make_rule("test.rule", "token=([a-z]+);", {1})});
    auto matches = Guard::scan_rules("token=abc;", fx.rules);
    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 6, 9, "test.rule");
}

TEST(GuardScanner, MultipleCaptureGroupsSelectFirstMatchedConfigured) {
    auto fx = build_rules({make_rule("test.rule", "key=([a-z]+)|standalone-([0-9]+)", {1, 2})});
    auto matches = Guard::scan_rules("standalone-42", fx.rules);
    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 11, 13, "test.rule");
}

TEST(GuardScanner, UnmatchedConfiguredGroupDropsMatch) {
    auto fx = build_rules({make_rule("test.rule", "a([a])|(b)", {2})});
    auto matches = Guard::scan_rules("aa", fx.rules);
    EXPECT_TRUE(matches.empty());
}

TEST(GuardScanner, InvalidCaptureGroupIndexSkipsMatch) {
    // Registry::compile_rule would reject capture_groups={2} against a
    // 1-group regex at compile time (BadCaptureGroup) -- this bypasses that
    // path deliberately, exactly like scan_test.go's own compiledRule()
    // helper, to pin scan_rules's own defensive behavior for a raw
    // CompiledRule that never went through the registry.
    Guard::CompiledRule cr;
    cr.rule = make_rule("invalid.capture", "token=([a-z]+)", {2}, "TOKEN");
    cr.re = std::make_shared<RE2>("(?m)" + cr.rule.regex, RE2::Quiet);
    ASSERT_TRUE(cr.re->ok());

    std::vector<const Guard::CompiledRule*> rules{&cr};
    auto matches = Guard::scan_rules("token=abc", rules);
    EXPECT_TRUE(matches.empty());
}

TEST(GuardScanner, CaptureGroupZeroSelectsFullMatch) {
    // Go's sensitiveSpan indexes `loc[group*2 : group*2+2]`, so a
    // configured group of exactly 0 lands on `loc[0:2]` -- the full-match
    // slot -- and is treated like the full match rather than skipped. This
    // is genuine Go behavior (see Scanner.hpp's file-level doc comment),
    // not merely defensive skip territory, so it's pinned distinctly from
    // InvalidCaptureGroupIndexSkipsMatch above. Registry::compile_rule
    // rejects capture_groups entries <= 0, so this bypasses it exactly
    // like the same-style test above.
    Guard::CompiledRule cr;
    cr.rule = make_rule("group.zero", "token=([a-z]+)", {0}, "TOKEN");
    cr.re = std::make_shared<RE2>("(?m)" + cr.rule.regex, RE2::Quiet);
    ASSERT_TRUE(cr.re->ok());

    std::vector<const Guard::CompiledRule*> rules{&cr};
    auto matches = Guard::scan_rules("token=abc", rules);

    ASSERT_EQ(matches.size(), 1u);
    // Full match "token=abc" (9 bytes), NOT just the captured "abc" (3
    // bytes) that capture_groups={1} would select.
    expect_match(matches[0], 0, 9, "group.zero");
}

TEST(GuardScanner, NullCompiledRulePointerThrows) {
    // scan_rules takes a caller-supplied vector of raw pointers; nothing
    // upstream guarantees every entry is non-null the way Registry's own
    // accessors do. A literal null entry (as opposed to a valid pointer to
    // a CompiledRule whose `re` member happens to be null, covered by
    // ParallelWorkerExceptionSurfacesAsRuntimeError /
    // SerialWorkerNullRegexSurfacesAsRuntimeError below) must fail the same
    // documented way rather than crash.
    auto fx = build_rules({make_rule("ok.rule", "secret")});
    std::vector<const Guard::CompiledRule*> rules = fx.rules;
    rules.push_back(nullptr);

    EXPECT_THROW(Guard::scan_rules("public secret text", rules), std::runtime_error);
}

TEST(GuardScanner, SerialWorkerNullRegexSurfacesAsRuntimeError) {
    // ParallelWorkerExceptionSurfacesAsRuntimeError (below) only exercises
    // the parallel branch. The null-re precondition check lives in
    // scan_one_rule, shared by both branches, but it needs its own pin on
    // the serial path (<= kParallelRuleThreshold rules) so a future change
    // that special-cases either branch can't silently stop checking here.
    auto fx = build_rules({
        make_rule("r1", "aaa", {}, "A"),
        make_rule("r2", "bbb", {}, "B"),
    });

    Guard::CompiledRule broken;
    broken.rule = make_rule("boom", "unused", {}, "X");
    // broken.re is left null -- forces the defensive throw in scan_one_rule.

    std::vector<const Guard::CompiledRule*> rules = fx.rules;
    rules.push_back(&broken);
    ASSERT_LE(rules.size(), Guard::detail::kParallelRuleThreshold);

    EXPECT_THROW(Guard::scan_rules("short text", rules), std::runtime_error);
}

// ── Filtering: no-hit / min_length / validators ───────────────────────────

TEST(GuardScanner, NoRegexHitReturnsEmpty) {
    auto fx = build_rules({make_rule("filter.none", "secret")});
    auto matches = Guard::scan_rules("public", fx.rules);
    EXPECT_TRUE(matches.empty());
}

TEST(GuardScanner, CaptureShorterThanMinLengthIsDropped) {
    Guard::Rule r = make_rule("filter.min_length", "token=([A-Z0-9]+)", {1}, "TOKEN");
    r.min_length = 5;
    auto fx = build_rules({r});

    auto matches = Guard::scan_rules("token=AB12", fx.rules);
    EXPECT_TRUE(matches.empty());
}

TEST(GuardScanner, ValidatorRejectionIsDropped) {
    Guard::Rule r = make_rule("filter.email.invalid", R"([^\s]+@[^\s]+)", {}, "EMAIL");
    r.validators = {"email_ascii"};
    auto fx = build_rules({r});

    auto matches = Guard::scan_rules("person@example", fx.rules);
    EXPECT_TRUE(matches.empty());
}

TEST(GuardScanner, ValidatorAcceptanceKeepsMatch) {
    Guard::Rule r = make_rule("filter.email.valid", R"([^\s]+@[^\s]+)", {}, "EMAIL", Guard::DataType::PersonalData);
    r.validators = {"email_ascii"};
    auto fx = build_rules({r});

    auto matches = Guard::scan_rules("person.name+test@example.com", fx.rules);
    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 0, 28, "filter.email.valid");
}

// ── Multiple matches / start / end boundaries ─────────────────────────────

TEST(GuardScanner, MultipleMatchesSameRuleAreAllFound) {
    auto fx = build_rules({make_rule("digits.run", R"(\d{3})")});
    auto matches = Guard::scan_rules("111 bbb 222", fx.rules);
    ASSERT_EQ(matches.size(), 2u);
    expect_match(matches[0], 0, 3, "digits.run");
    expect_match(matches[1], 8, 11, "digits.run");
}

TEST(GuardScanner, MatchSpansEntireText) {
    auto fx = build_rules({make_rule("whole.text", "SECRET")});
    auto matches = Guard::scan_rules("SECRET", fx.rules);
    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 0, 6, "whole.text");
}

TEST(GuardScanner, ResultsAreSortedByStartRegardlessOfRuleOrder) {
    auto fx = build_rules({
        make_rule("second", "222"),
        make_rule("first", "111"),
        make_rule("third", "333"),
    });

    auto matches = Guard::scan_rules("111 222 333", fx.rules);

    ASSERT_EQ(matches.size(), 3u);
    expect_match(matches[0], 0, 3, "first");
    expect_match(matches[1], 4, 7, "second");
    expect_match(matches[2], 8, 11, "third");
}

// ── Empty-match advance (nullable regex) ──────────────────────────────────
// Every other regex in this file is incapable of matching empty, so the
// `mend == mstart` branch in scan_one_rule (accept/reject bookkeeping, the
// mstart-based advance, and the width==0/pos=end+1 termination path) had
// zero coverage before these two -- EmptyTextIsDropped above short-circuits
// before the loop even runs (text.empty()), so it doesn't reach this code
// either. Both traced by hand against the algorithm before being written.

TEST(GuardScanner, NullableRegexOverMultiByteTextFindsOnlyNonEmptySpan) {
    // "日本aa語": bytes [0,3)=日 [3,6)=本 [6,8)="aa" [8,11)=語. `a*` finds
    // an empty match at 0 (accepted, dropped -- empty span), advances 3
    // bytes past 日's lead byte via decode_utf8 (not a raw 1-byte skip --
    // that would drift into 日's continuation bytes and could re-match
    // there); an empty match at 3 (accepted, dropped), advances past 本;
    // "aa" itself as one non-empty match [6,8) (kept, pos jumps to 8); an
    // empty match at 8 == prevMatchEnd is REJECTED -- the exact case Go's
    // allMatches guards against (a zero-width match redundantly reported
    // right where a real match just ended); advances past 語; a final
    // empty match at end-of-text (11) is accepted but dropped (empty
    // span); pos becomes end+1 and the loop terminates. Net: exactly one
    // surviving match.
    auto fx = build_rules({make_rule("nullable.run", "a*")});
    const std::string text = "日本aa語";

    auto matches = Guard::scan_rules(text, fx.rules);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 6, 8, "nullable.run");
    EXPECT_EQ(text.substr(matches[0].start, matches[0].end - matches[0].start), "aa");
}

TEST(GuardScanner, NullableAlternationOnMultilineTextKeepsOnlyNonEmptyBranch) {
    // `line\d+|$` -- a nullable alternation (the multiline `$` that
    // Registry::compile_rule's "(?m)" prefix enables) paired with a
    // non-empty branch that can never compete for the same starting
    // position as `$` (the literal "line" prefix and a line-boundary
    // position are mutually exclusive by construction), so this test makes
    // no assumption about RE2's alternation-order/tie-break rules. Over
    // "line1\nline2\nline3" (no trailing newline), `line\d+` matches all
    // three "lineN" tokens as non-empty spans; the multiline `$` fires
    // (empty) immediately before each '\n' and at end-of-text, but every
    // one of those positions coincides with the previous match's end, so
    // each is rejected by the "not immediately after the previous match"
    // rule -- exercising that reject path again on a differently-shaped
    // regex. Net: exactly the three non-empty matches survive, proving
    // both that they aren't disturbed by the empty-match machinery and
    // that the loop terminates (a hang here would time out the whole test
    // binary, not just this test).
    auto fx = build_rules({make_rule("lines.run", R"(line\d+|$)")});
    const std::string text = "line1\nline2\nline3";

    auto matches = Guard::scan_rules(text, fx.rules);

    ASSERT_EQ(matches.size(), 3u);
    expect_match(matches[0], 0, 5, "lines.run");
    expect_match(matches[1], 6, 11, "lines.run");
    expect_match(matches[2], 12, 17, "lines.run");
}

// ── Overlap coalescing (ResolveConflicts) ─────────────────────────────────

TEST(GuardScanner, ConflictSameStartKeepsLongestMatch) {
    auto fx = build_rules({
        make_rule("conflict.short", "abc", {}, "SHORT"),
        make_rule("conflict.long", "abcdef", {}, "LONG"),
    });

    auto matches = Guard::scan_rules("abcdef", fx.rules);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 0, 6, "conflict.long");
}

TEST(GuardScanner, ConflictSameSpanKeepsLexicographicallyFirstRuleId) {
    auto fx = build_rules({
        make_rule("z.rule", "secret", {}, "Z"),
        make_rule("a.rule", "secret", {}, "A"),
    });

    auto matches = Guard::scan_rules("secret", fx.rules);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 0, 6, "a.rule");
}

TEST(GuardScanner, ConflictPartialOverlapEqualLengthLowestStartWins) {
    // abc[0,3) and bcd[1,4) overlap. Dropping either would emit its
    // exclusive byte ("a" or "d") verbatim, leaking part of a detected
    // value -- they merge into [0,4). Equal length -> lowest start wins.
    auto fx = build_rules({
        make_rule("conflict.left", "abc", {}, "LEFT"),
        make_rule("conflict.right", "bcd", {}, "RIGHT"),
    });

    auto matches = Guard::scan_rules("abcd", fx.rules);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 0, 4, "conflict.left");
}

TEST(GuardScanner, ConflictDifferentLengthPartialOverlapMasksUnion) {
    // short[0,4) and long[2,8) overlap; the union [0,8) covers short's
    // exclusive prefix "ab" that a plain longest-first drop would leak.
    auto fx = build_rules({
        make_rule("overlap.short", "abcd", {}, "SHORT"),
        make_rule("overlap.long", "cdefgh", {}, "LONG"),
    });

    auto matches = Guard::scan_rules("abcdefgh", fx.rules);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 0, 8, "overlap.long");
}

TEST(GuardScanner, ConflictChainOfOverlapsCoalescesTransitively) {
    // a[0,4) overlaps b[2,6) overlaps c[4,8); a does not reach c, but the
    // run extends transitively via the growing end. All three equal length
    // -> lowest start wins.
    auto fx = build_rules({
        make_rule("chain.a", "abcd", {}, "A"),
        make_rule("chain.b", "cdef", {}, "B"),
        make_rule("chain.c", "efgh", {}, "C"),
    });

    auto matches = Guard::scan_rules("abcdefgh", fx.rules);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], 0, 8, "chain.a");
}

TEST(GuardScanner, AdjacentMatchesAreNotMerged) {
    auto fx = build_rules({
        make_rule("adjacent.left", "abc", {}, "LEFT"),
        make_rule("adjacent.right", "def", {}, "RIGHT"),
    });

    auto matches = Guard::scan_rules("abcdef", fx.rules);

    ASSERT_EQ(matches.size(), 2u);
    expect_match(matches[0], 0, 3, "adjacent.left");
    expect_match(matches[1], 3, 6, "adjacent.right");
}

// ── Realistic rules (email, luhn-validated card, coalescing) ─────────────

TEST(GuardScanner, RealisticEmailAndLuhnValidatedCard) {
    Guard::Rule email_rule = make_rule(
        "pii.email", R"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", {}, "EMAIL", Guard::DataType::PersonalData);

    Guard::Rule card_rule = make_rule("payment.card", R"(\b\d{13,19}\b)", {}, "CARD", Guard::DataType::Credentials);
    card_rule.validators = {"luhn"};
    card_rule.min_length = 13;

    auto fx = build_rules({email_rule, card_rule});

    const std::string email = "person@example.com";
    const std::string good_card = "4111111111111111";  // valid Luhn PAN
    std::string bad_card = good_card;
    bad_card.back() = (bad_card.back() == '1') ? '2' : '1';  // guaranteed Luhn-invalid

    const std::string text = "contact " + email + " good " + good_card + " bad " + bad_card;
    auto matches = Guard::scan_rules(text, fx.rules);

    const auto email_pos = text.find(email);
    const auto card_pos = text.find(good_card);
    ASSERT_NE(email_pos, std::string::npos);
    ASSERT_NE(card_pos, std::string::npos);

    // bad_card fails the luhn validator and is dropped; only email + the
    // valid card survive.
    ASSERT_EQ(matches.size(), 2u);
    expect_match(matches[0], email_pos, email_pos + email.size(), "pii.email");
    expect_match(matches[1], card_pos, card_pos + good_card.size(), "payment.card");
}

TEST(GuardScanner, RealisticOverlappingTokenPatternsCoalesce) {
    // "tokens.suffix" nests entirely inside "tokens.long"'s span (both
    // match within the same "AB12345678" tail) -- crafted to force
    // coalescing between two realistic-shaped rules rather than two
    // synthetic single-letter patterns.
    Guard::Rule token_rule = make_rule("tokens.long", R"(TOK-[A-Z0-9]{10})", {}, "TOKEN", Guard::DataType::ApiKeys);
    Guard::Rule suffix_rule = make_rule("tokens.suffix", R"(AB[0-9]{8})", {}, "SUFFIX", Guard::DataType::ApiKeys);
    auto fx = build_rules({token_rule, suffix_rule});

    const std::string token = "TOK-AB12345678";
    const std::string text = "id " + token + " done";

    auto matches = Guard::scan_rules(text, fx.rules);

    const auto token_pos = text.find(token);
    ASSERT_NE(token_pos, std::string::npos);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], token_pos, token_pos + token.size(), "tokens.long");
}

// ── Parallel fan-out ───────────────────────────────────────────────────────

TEST(GuardScanner, ScanRulesSmallAndLargeTextBothFindMatch) {
    // Ports TestScanRules_SequentialAndParallelPathsAgree: the same rule
    // set over a small text (serial, below both thresholds) and a large
    // text (parallel, clears both) must find the same value.
    std::vector<Guard::Rule> defs{
        make_rule("r1", "SECRET", {}, "S"),
        make_rule("r2", "zzz1", {}, "Z1"),
        make_rule("r3", "zzz2", {}, "Z2"),
        make_rule("r4", "zzz3", {}, "Z3"),
        make_rule("r5", "zzz4", {}, "Z4"),
        make_rule("r6", "zzz5", {}, "Z5"),
    };
    auto fx = build_rules(defs);

    const std::string small = "prefix SECRET suffix";
    ASSERT_LT(small.size(), Guard::detail::kParallelTextThreshold);
    auto small_matches = Guard::scan_rules(small, fx.rules);
    ASSERT_EQ(small_matches.size(), 1u);
    EXPECT_EQ(small_matches[0].rule->rule.id, "r1");

    const std::string large = std::string(5 * 1024, 'p') + " SECRET";
    ASSERT_GE(large.size(), Guard::detail::kParallelTextThreshold);
    auto large_matches = Guard::scan_rules(large, fx.rules);
    ASSERT_EQ(large_matches.size(), 1u);
    EXPECT_EQ(large_matches[0].rule->rule.id, "r1");
}

TEST(GuardScanner, ParallelMatchesSerialOnLargeText) {
    // Direct white-box comparison (brief bullet f): the SAME 100 KiB text
    // and 20-rule set run through detail::scan_serial and
    // detail::scan_parallel (max_workers pinned so this doesn't depend on
    // the CI runner's core count) must produce byte-identical coalesced
    // output.
    std::vector<Guard::Rule> defs;
    defs.reserve(20);
    for (int i = 0; i < 20; ++i)
        defs.push_back(make_rule("rule." + std::to_string(i), "NEEDLE_" + std::to_string(i) + "_END"));
    auto fx = build_rules(defs);

    std::string text(100 * 1024, 'x');
    for (int i = 0; i < 20; ++i) {
        const std::string needle = "NEEDLE_" + std::to_string(i) + "_END";
        const std::size_t offset = static_cast<std::size_t>(i) * 4000 + 10;
        text.replace(offset, needle.size(), needle);
    }

    ASSERT_GE(text.size(), Guard::detail::kParallelTextThreshold);
    ASSERT_GT(fx.rules.size(), Guard::detail::kParallelRuleThreshold);

    auto serial = Guard::detail::resolve_conflicts(Guard::detail::scan_serial(text, fx.rules));

    Guard::ScanOptions opts;
    opts.max_workers = 4;
    auto parallel = Guard::detail::resolve_conflicts(Guard::detail::scan_parallel(text, fx.rules, opts));

    ASSERT_EQ(serial.size(), 20u);
    ASSERT_EQ(serial.size(), parallel.size());
    for (std::size_t i = 0; i < serial.size(); ++i) {
        EXPECT_EQ(serial[i].start, parallel[i].start);
        EXPECT_EQ(serial[i].end, parallel[i].end);
        ASSERT_NE(serial[i].rule, nullptr);
        ASSERT_NE(parallel[i].rule, nullptr);
        EXPECT_EQ(serial[i].rule->rule.id, parallel[i].rule->rule.id);
    }
}

TEST(GuardScanner, CrossBucketOverlapCoalescesUnderRealParallelPath) {
    // ParallelMatchesSerialOnLargeText's needles are 4000 bytes apart and
    // never overlap, so resolve_conflicts there is never asked to merge
    // candidates that came out of DIFFERENT parallel buckets -- coalescing
    // across a bucket boundary was untested. Here rule index 2
    // ("leftpart") and rule index 7 ("partright") -- differing by 5, not a
    // multiple of max_workers=4, so `i % num_workers` puts them in
    // different buckets (2%4=2, 7%4=3) -- are crafted to match OVERLAPPING
    // spans of the same embedded literal "LEFTPARTRIGHT". The assertion
    // calls the real public Guard::scan_rules directly once (no manual
    // detail::resolve_conflicts call on either side), so this exercises
    // the actual production dispatch + cross-bucket merge + coalescing
    // pipeline end-to-end, not just the coalescing sweep in isolation.
    std::vector<Guard::Rule> defs{
        make_rule("m0", "MARKER_A"),          // index 0 -> bucket 0
        make_rule("m1", "MARKER_B"),          // index 1 -> bucket 1
        make_rule("leftpart", "LEFTPART"),    // index 2 -> bucket 2
        make_rule("m3", "MARKER_C"),          // index 3 -> bucket 3
        make_rule("m4", "MARKER_D"),          // index 4 -> bucket 0
        make_rule("m5", "MARKER_E"),          // index 5 -> bucket 1
        make_rule("m6", "MARKER_F"),          // index 6 -> bucket 2
        make_rule("partright", "PARTRIGHT"),  // index 7 -> bucket 3
    };
    auto fx = build_rules(defs);
    ASSERT_EQ(fx.rules.size(), 8u);
    ASSERT_GT(fx.rules.size(), Guard::detail::kParallelRuleThreshold);

    std::string text(5 * 1024, 'x');
    const std::vector<std::pair<std::size_t, std::string>> placements{
        {100, "MARKER_A"},
        {600, "MARKER_B"},
        {1100, "MARKER_C"},
        {1600, "MARKER_D"},
        {2100, "MARKER_E"},
        {2600, "MARKER_F"},
        {3100, "LEFTPARTRIGHT"},
    };
    for (const auto& [offset, needle] : placements)
        text.replace(offset, needle.size(), needle);

    ASSERT_GE(text.size(), Guard::detail::kParallelTextThreshold);

    Guard::ScanOptions opts;
    opts.max_workers = 4;
    auto matches = Guard::scan_rules(text, fx.rules, opts);

    // 6 independent markers + 1 coalesced ("leftpart" + "partright") union.
    ASSERT_EQ(matches.size(), 7u);

    const auto coalesced = std::find_if(
        matches.begin(), matches.end(), [](const Guard::ScanMatch& m) { return m.rule->rule.id == "partright"; });
    ASSERT_NE(coalesced, matches.end());
    const std::string leftpartright = "LEFTPARTRIGHT";
    const auto union_pos = text.find(leftpartright);
    ASSERT_NE(union_pos, std::string::npos);
    // "PARTRIGHT" (9 bytes) is longer than "LEFTPART" (8 bytes), so
    // "partright" is the coalesced pair's representative -- the union span
    // is [union_pos, union_pos+13), not either constituent's own span.
    expect_match(*coalesced, union_pos, union_pos + leftpartright.size(), "partright");

    // "leftpart" -- the shorter overlapping constituent -- must NOT appear
    // as its own separate match; it was absorbed into the union above.
    const auto shadowed = std::find_if(
        matches.begin(), matches.end(), [](const Guard::ScanMatch& m) { return m.rule->rule.id == "leftpart"; });
    EXPECT_EQ(shadowed, matches.end());

    // The six independent markers all survive untouched. `const char*` (not
    // `const std::string&`) as the loop variable type: GCC's
    // -Wrange-loop-construct (an error under this repo's -Werror) flags a
    // std::string& binding to a temporary materialized from each `const
    // char*` element as an avoidable-copy-disguised-as-reference pattern.
    for (const char* id : {"m0", "m1", "m3", "m4", "m5", "m6"}) {
        const auto found = std::find_if(
            matches.begin(), matches.end(), [&id](const Guard::ScanMatch& m) { return m.rule->rule.id == id; });
        EXPECT_NE(found, matches.end()) << "missing match for rule " << id;
    }
}

TEST(GuardScanner, ParallelWorkerExceptionSurfacesAsRuntimeError) {
    // Ports TestScanRules_WorkerPanicRecoveredAsError: a broken rule mixed
    // into a rule set large enough to force the parallel path must surface
    // as a std::runtime_error from scan_rules rather than crashing --see
    // Scanner.hpp's file-level doc comment for why this port uses a
    // checked precondition (null CompiledRule::re) instead of literally
    // reproducing Go's recovered nil-pointer panic.
    std::vector<Guard::Rule> defs{
        make_rule("r1", "aaa", {}, "A"),
        make_rule("r2", "bbb", {}, "B"),
        make_rule("r3", "ccc", {}, "C"),
        make_rule("r4", "ddd", {}, "D"),
        make_rule("r5", "eee", {}, "E"),
    };
    auto fx = build_rules(defs);

    Guard::CompiledRule broken;
    broken.rule = make_rule("boom", "unused", {}, "X");
    // broken.re is left null -- forces the defensive throw in scan_one_rule.

    std::vector<const Guard::CompiledRule*> rules = fx.rules;
    rules.push_back(&broken);

    const std::string text(5 * 1024, 'x');
    ASSERT_GE(text.size(), Guard::detail::kParallelTextThreshold);
    ASSERT_GT(rules.size(), Guard::detail::kParallelRuleThreshold);

    EXPECT_THROW(Guard::scan_rules(text, rules), std::runtime_error);
}

// ── Keyword pre-filter (Task 1.8) ─────────────────────────────────────────
// Helper: builds a rule with keywords set (make_rule above has no keywords
// param), so its prefilter_eligible gets computed for real by
// Registry::compile_rule via Guard::Prefilter.hpp's regex_guarantees_keyword.
// The exhaustive port of Go's regexGuaranteesKeyword/foldSafeForToLower test
// vectors lives in test_guard_prefilter.cpp; these pin only the scanner's
// own wiring: the lazy-lowercase, filter-then-dispatch behavior, and the
// end-to-end recall-preserving guarantee.

namespace {

Guard::Rule make_keyword_rule(std::string id,
                              std::string regex,
                              std::vector<std::string> keywords,
                              std::string placeholder = "TEST") {
    Guard::Rule r = make_rule(std::move(id), std::move(regex), {}, std::move(placeholder));
    r.keywords = std::move(keywords);
    return r;
}

}  // namespace

TEST(GuardScanner, FilterByKeywordsDropsEligibleRuleWithoutKeywordHitButKeepsIneligible) {
    // White-box check on detail::filter_by_keywords directly: for a truly
    // eligible rule (regex_guarantees_keyword proved every match contains
    // the keyword), it is IMPOSSIBLE to observe a difference in scan_rules's
    // output when the keyword is absent -- the regex literally cannot match
    // text that doesn't contain it, by construction of eligibility. So the
    // pre-filter's own effect (skipping the eligible rule's regex work
    // entirely) is only observable by calling filter_by_keywords itself.
    auto fx = build_rules({
        make_keyword_rule("eligible.rule", "found=([a-z]+)", {"found"}),
        // Ineligible: the keyword is an external label the regex doesn't
        // require (self-contained hex token, gitleaks-style) -- must never
        // be dropped by the pre-filter regardless of whether its own
        // declared keyword appears in the text.
        make_keyword_rule("ineligible.rule", R"(\b([a-f0-9]{6})\b)", {"vendorlabel"}),
    });
    ASSERT_TRUE(fx.registry->by_id("eligible.rule")->prefilter_eligible);
    ASSERT_FALSE(fx.registry->by_id("ineligible.rule")->prefilter_eligible);

    const std::string text = "no keywords here, just abc123";  // neither "found" nor "vendorlabel" appear
    auto filtered = Guard::detail::filter_by_keywords(text, fx.rules);

    ASSERT_EQ(filtered.size(), 1u);
    EXPECT_EQ(filtered[0]->rule.id, "ineligible.rule");
}

TEST(GuardScanner, IneligibleRuleIsScannedByPrefilterEvenWhenItsKeywordNeverAppears) {
    // The observable, end-to-end counterpart of the white-box test above:
    // an ineligible rule's match must survive with the pre-filter ON even
    // though the text never contains its declared keyword at all -- proof
    // it was never filtered on that keyword's (irrelevant) presence.
    auto fx = build_rules({make_keyword_rule("ineligible.rule", R"(\b([a-f0-9]{6})\b)", {"vendorlabel"})});
    ASSERT_FALSE(fx.registry->by_id("ineligible.rule")->prefilter_eligible);

    const std::string text = "token is abc123 in the log";  // "vendorlabel" never appears

    Guard::ScanOptions on;
    on.prefilter_enabled = true;
    auto matches = Guard::scan_rules(text, fx.rules, on);

    ASSERT_EQ(matches.size(), 1u);
    expect_match(matches[0], text.find("abc123"), text.find("abc123") + 6, "ineligible.rule");
}

TEST(GuardScanner, PrefilterEnabledIsRecallPreservingEquivalentToDisabled) {
    // scan_rules(text, rules, {prefilter_enabled=true}) ==
    // scan_rules(text, rules, {prefilter_enabled=false}) for a mixed rule
    // set (eligible + ineligible) over a text that DOES contain hits for
    // everything -- the pre-filter must never change WHAT is found, only
    // how much regex work it takes to find it.
    auto fx = build_rules({
        make_keyword_rule("r1.eligible", "token=([a-z]+)", {"token"}, "TOKEN"),
        make_keyword_rule("r2.eligible", "secret=([a-z]+)", {"secret"}, "SECRET"),
        make_keyword_rule("r3.ineligible", R"(\b([a-f0-9]{6})\b)", {"vendorlabel"}, "HEX"),
    });
    ASSERT_TRUE(fx.registry->by_id("r1.eligible")->prefilter_eligible);
    ASSERT_TRUE(fx.registry->by_id("r2.eligible")->prefilter_eligible);
    ASSERT_FALSE(fx.registry->by_id("r3.ineligible")->prefilter_eligible);

    const std::string text = "token=abc secret=xyz id=abc123";

    Guard::ScanOptions off;
    off.prefilter_enabled = false;
    Guard::ScanOptions on;
    on.prefilter_enabled = true;

    auto matches_off = Guard::scan_rules(text, fx.rules, off);
    auto matches_on = Guard::scan_rules(text, fx.rules, on);

    ASSERT_EQ(matches_off.size(), 3u);
    ASSERT_EQ(matches_off.size(), matches_on.size());
    for (std::size_t i = 0; i < matches_off.size(); ++i) {
        EXPECT_EQ(matches_off[i].start, matches_on[i].start);
        EXPECT_EQ(matches_off[i].end, matches_on[i].end);
        ASSERT_NE(matches_off[i].rule, nullptr);
        ASSERT_NE(matches_on[i].rule, nullptr);
        EXPECT_EQ(matches_off[i].rule->rule.id, matches_on[i].rule->rule.id);
    }
}

TEST(GuardScanner, PrefilterEnabledOnRuleSetWithNoKeywordsAtAllBehavesLikeDisabled) {
    // No rule declares keywords (the original make_rule default) -- every
    // rule is trivially "not eligible", so filter_by_keywords is a pure
    // passthrough and the lazy lowercase never even runs. Pins that this
    // degenerate case (the shape every pre-1.8 test in this file used)
    // still behaves identically on vs. off.
    auto fx = build_rules({
        make_rule("r1", "token=([a-z]+)", {1}, "TOKEN"),
        make_rule("r2", "secret=([a-z]+)", {1}, "SECRET"),
    });
    const std::string text = "token=abc secret=xyz";

    Guard::ScanOptions off;
    off.prefilter_enabled = false;
    Guard::ScanOptions on;
    on.prefilter_enabled = true;

    auto matches_off = Guard::scan_rules(text, fx.rules, off);
    auto matches_on = Guard::scan_rules(text, fx.rules, on);

    ASSERT_EQ(matches_off.size(), 2u);
    ASSERT_EQ(matches_off.size(), matches_on.size());
    for (std::size_t i = 0; i < matches_off.size(); ++i) {
        EXPECT_EQ(matches_off[i].start, matches_on[i].start);
        EXPECT_EQ(matches_off[i].end, matches_on[i].end);
        ASSERT_NE(matches_off[i].rule, nullptr);
        ASSERT_NE(matches_on[i].rule, nullptr);
        EXPECT_EQ(matches_off[i].rule->rule.id, matches_on[i].rule->rule.id);
    }
}

// ── Uppercase (non-pre-lowered) keywords still hit (code review finding) ──
// RulesYaml.hpp lowercases rule.keywords as a side effect of the YAML
// loader, but Registry::compile_rule is the single validation path for
// ANY rule source -- including a hypothetical rule built directly (as
// this test does, and as a future configuration API would) with keywords
// that were never run through that loader. regex_guarantees_keyword
// lowercases keywords INTERNALLY to decide eligibility, so such a rule can
// still end up prefilter_eligible even though rule.keywords itself is
// mixed-case. Before this fix, the scanner matched raw (unlowered)
// rule.keywords against the lowered scan text -- silently never hitting
// for a keyword like "Bearer" and dropping every match of an eligible
// rule, exactly the failure mode the pre-filter must never have. The fix
// is CompiledRule::prefilter_keywords: a lowercased copy Registry::
// compile_rule always computes, which the scanner matches against instead.
TEST(GuardScanner, UppercaseKeywordNotPreLoweredStillHitsAfterPrefilterKeywordsFix) {
    Guard::Rule r;
    r.id = "uppercase.keyword.rule";
    r.name = r.id;
    r.data_type = Guard::DataType::AccessTokens;
    r.regex = "Bearer ([a-z0-9]+)";  // literal "Bearer" -- eligible regardless of keyword casing
    r.keywords = {"Bearer"};         // deliberately NOT pre-lowered, unlike the YAML loader's output
    r.masking.capture_groups = {1};
    r.masking.placeholder = "TOKEN";

    auto reg = Guard::Registry::build({r});
    const Guard::CompiledRule* cr = reg->by_id("uppercase.keyword.rule");
    ASSERT_NE(cr, nullptr);
    ASSERT_TRUE(cr->prefilter_eligible);
    ASSERT_EQ(cr->prefilter_keywords, std::vector<std::string>{"bearer"});

    const std::string text = "Bearer abc123";
    std::vector<const Guard::CompiledRule*> rules{cr};

    Guard::ScanOptions off;
    off.prefilter_enabled = false;
    auto matches_off = Guard::scan_rules(text, rules, off);
    ASSERT_EQ(matches_off.size(), 1u) << "baseline (prefilter off) must find the match";

    Guard::ScanOptions on;
    on.prefilter_enabled = true;
    auto matches_on = Guard::scan_rules(text, rules, on);
    ASSERT_EQ(matches_on.size(), 1u)
        << "prefilter on must still find the match -- a raw-keyword bug would silently drop it";
    expect_match(matches_on[0], 7, 13, "uppercase.keyword.rule");
}
