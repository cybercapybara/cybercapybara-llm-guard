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

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <re2/re2.h>

#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/Scanner.hpp"

namespace {

Guard::Rule make_rule(std::string id, std::string regex, std::vector<int> capture_groups = {},
                      std::string placeholder = "TEST", Guard::DataType data_type = Guard::DataType::Custom) {
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
    Guard::Rule email_rule = make_rule("pii.email", R"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", {}, "EMAIL",
                                       Guard::DataType::PersonalData);

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
        make_rule("r1", "SECRET", {}, "S"), make_rule("r2", "zzz1", {}, "Z1"), make_rule("r3", "zzz2", {}, "Z2"),
        make_rule("r4", "zzz3", {}, "Z3"),  make_rule("r5", "zzz4", {}, "Z4"), make_rule("r6", "zzz5", {}, "Z5"),
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

TEST(GuardScanner, ParallelWorkerExceptionSurfacesAsRuntimeError) {
    // Ports TestScanRules_WorkerPanicRecoveredAsError: a broken rule mixed
    // into a rule set large enough to force the parallel path must surface
    // as a std::runtime_error from scan_rules rather than crashing --see
    // Scanner.hpp's file-level doc comment for why this port uses a
    // checked precondition (null CompiledRule::re) instead of literally
    // reproducing Go's recovered nil-pointer panic.
    std::vector<Guard::Rule> defs{
        make_rule("r1", "aaa", {}, "A"), make_rule("r2", "bbb", {}, "B"), make_rule("r3", "ccc", {}, "C"),
        make_rule("r4", "ddd", {}, "D"), make_rule("r5", "eee", {}, "E"),
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
