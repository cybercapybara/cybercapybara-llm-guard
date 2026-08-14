/**
 * @file test_guard_masker.cpp
 * @brief Unit tests for Guard::mask_texts / Guard::MaskingState / the
 *        placeholder-collision-guarded masking core in Guard::detail.
 *
 * Ports the behavioral cases from the Go reference's
 * `internal/usecases/guardrails/mask/{masker_test.go,handle_test.go}`:
 * `TestMaskerMaskText` (all 4 subtests), `TestMaskerStateAcrossCalls`,
 * `TestMaskerTriggeredDataTypesFiltersInvalidValues`,
 * `TestUseCase_Handle_MasksSingleText`,
 * `TestUseCase_Handle_MasksMultipleTextsWithSharedState`,
 * `TestUseCase_Handle_AvoidsPlaceholderCollision`,
 * `TestUseCase_Handle_ParallelEqualsSequential`,
 * `TestUseCase_Handle_ScannerError` / `_ParallelScannerError` (adapted: see
 * the "error propagation" section below for why this port can't reproduce
 * per-text-dependent scan failures the way Go's mocked scanner does).
 * `TestMaskerPlaceholderHelpers`'s reuse-ignores-differing-type assertion is
 * covered by `MultiTextSameOriginalDifferentTypeStillDedupes` below rather
 * than ported as its own test, since `MaskerState::placeholder_for_original`/
 * `next_placeholder` are private (Go's package-internal test reaches methods
 * this port deliberately doesn't expose as public API).
 */

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <re2/re2.h>

#include "guard/Masker.hpp"
#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/Scanner.hpp"

namespace {

using Guard::CompiledRule;
using Guard::DataType;
using Guard::MaskOptions;
using Guard::MaskResult;
using Guard::Registry;
using Guard::Rule;
using Guard::ScanMatch;

Rule make_rule(std::string id,
               std::string regex,
               std::string placeholder = "TEST",
               DataType data_type = DataType::Custom) {
    Rule r;
    r.id = std::move(id);
    r.name = r.id;
    r.data_type = data_type;
    r.regex = std::move(regex);
    r.masking.placeholder = std::move(placeholder);
    return r;
}

// Same stable-pointer fixture idiom as test_guard_scanner.cpp: Registry::
// all()'s storage never mutates after build(), so `rules` stays valid for as
// long as `registry` is kept alive.
struct RuleFixture {
    std::shared_ptr<const Registry> registry;
    std::vector<const CompiledRule*> rules;
};

RuleFixture build_rules(std::vector<Rule> defs) {
    RuleFixture fx;
    fx.registry = Registry::build(defs);
    fx.rules.reserve(defs.size());
    for (const auto& d : defs)
        fx.rules.push_back(fx.registry->by_id(d.id));
    return fx;
}

// Simple, synthetic-but-realistic patterns shared by several tests: an email
// address and a bare 16-digit run standing in for a payment card (no Luhn
// validator -- keeps the fixture focused on masking, not validation, which
// Scanner.hpp/Validators.hpp already cover exhaustively).
Rule email_rule(std::string id = "pii.email") {
    return make_rule(
        std::move(id), R"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", "EMAIL", DataType::PersonalData);
}

Rule card_rule(std::string id = "payment.card") {
    return make_rule(std::move(id), R"(\b[0-9]{16}\b)", "CREDIT_CARD", DataType::Credentials);
}

}  // namespace

// ── Phase B behavioral floor: (a)-(g) from the task brief ────────────────

TEST(GuardMasker, SameOriginalAcrossTextsDedupesToOnePlaceholder) {
    auto fx = build_rules({email_rule()});
    Guard::MaskResult got =
        Guard::mask_texts({"contact alice@example.com now", "again alice@example.com here"}, fx.rules);

    ASSERT_EQ(got.masked_texts.size(), 2u);
    EXPECT_EQ(got.masked_texts[0], "contact <EMAIL_1> now");
    EXPECT_EQ(got.masked_texts[1], "again <EMAIL_1> here");

    ASSERT_EQ(got.state.replacements.size(), 1u);
    EXPECT_EQ(got.state.replacements[0].rule_id, "pii.email");
    EXPECT_EQ(got.state.replacements[0].data_type, DataType::PersonalData);
    EXPECT_EQ(got.state.replacements[0].original, "alice@example.com");
    EXPECT_EQ(got.state.replacements[0].placeholder, "<EMAIL_1>");
}

TEST(GuardMasker, DistinctOriginalsNumberedInEncounterOrderAcrossTexts) {
    auto fx = build_rules({email_rule()});
    // Encounter order: "bob@..." (text 0) first, then "alice@..." (text 1,
    // appears before the repeated "bob@..." within that same text) -- text
    // order, then within-text offset order.
    Guard::MaskResult got =
        Guard::mask_texts({"first bob@example.com", "second alice@example.com then bob@example.com"}, fx.rules);

    EXPECT_EQ(got.masked_texts[0], "first <EMAIL_1>");
    EXPECT_EQ(got.masked_texts[1], "second <EMAIL_2> then <EMAIL_1>");

    ASSERT_EQ(got.state.replacements.size(), 2u);
    EXPECT_EQ(got.state.replacements[0].original, "bob@example.com");
    EXPECT_EQ(got.state.replacements[0].placeholder, "<EMAIL_1>");
    EXPECT_EQ(got.state.replacements[1].original, "alice@example.com");
    EXPECT_EQ(got.state.replacements[1].placeholder, "<EMAIL_2>");
}

TEST(GuardMasker, DifferentTypesGetIndependentCounters) {
    auto fx = build_rules({email_rule(), card_rule()});
    Guard::MaskResult got = Guard::mask_texts({"email alice@example.com card 4111111111111111"}, fx.rules);

    EXPECT_EQ(got.masked_texts[0], "email <EMAIL_1> card <CREDIT_CARD_1>");
    ASSERT_EQ(got.state.replacements.size(), 2u);
    EXPECT_EQ(got.state.replacements[0].placeholder, "<EMAIL_1>");
    EXPECT_EQ(got.state.replacements[1].placeholder, "<CREDIT_CARD_1>");
}

TEST(GuardMasker, CollisionGuardSkipsReservedLiteralAndLeavesItUntouched) {
    auto fx = build_rules({email_rule()});
    Guard::MaskResult got = Guard::mask_texts({"already have <EMAIL_1> literal, new email bob@example.com"}, fx.rules);

    // The literal "<EMAIL_1>" isn't an email match at all (no '@'), so it
    // survives untouched; the real email is masked, but its counter skips
    // the reserved value 1 and lands on 2.
    EXPECT_EQ(got.masked_texts[0], "already have <EMAIL_1> literal, new email <EMAIL_2>");

    ASSERT_EQ(got.state.replacements.size(), 1u);
    EXPECT_EQ(got.state.replacements[0].original, "bob@example.com");
    EXPECT_EQ(got.state.replacements[0].placeholder, "<EMAIL_2>");
    for (const auto& r : got.state.replacements)
        EXPECT_NE(r.original, "<EMAIL_1>");
}

TEST(GuardMasker, CollisionGuardSkipsEveryReservedCounterValue) {
    auto fx = build_rules({email_rule()});
    Guard::MaskResult got =
        Guard::mask_texts({"seen <EMAIL_1> and <EMAIL_2> already; alice@example.com then bob@example.com"}, fx.rules);

    ASSERT_EQ(got.state.replacements.size(), 2u);
    EXPECT_EQ(got.state.replacements[0].placeholder, "<EMAIL_3>");
    EXPECT_EQ(got.state.replacements[1].placeholder, "<EMAIL_4>");
}

TEST(GuardMasker, TriggeredRuleIdsAndDataTypesAreSortedUnique) {
    Rule z = make_rule("z.rule", "ZED", "Z", DataType::Custom);
    Rule a = make_rule("a.rule", "ALPHA", "A", DataType::ApiKeys);
    Rule m = make_rule("m.rule", "MID", "M", DataType::Credentials);
    auto fx = build_rules({z, a, m});

    Guard::MaskResult got = Guard::mask_texts({"ZED ALPHA MID ZED"}, fx.rules);

    EXPECT_EQ(got.state.triggered_rule_ids, (std::vector<std::string>{"a.rule", "m.rule", "z.rule"}));
    // Numeric order: Credentials(1) < ApiKeys(2) < Custom(6).
    ASSERT_EQ(got.state.triggered_data_types.size(), 3u);
    EXPECT_EQ(got.state.triggered_data_types[0], DataType::Credentials);
    EXPECT_EQ(got.state.triggered_data_types[1], DataType::ApiKeys);
    EXPECT_EQ(got.state.triggered_data_types[2], DataType::Custom);
}

TEST(GuardMasker, ParallelEqualsSerialAcrossParallelMinBytesThreshold) {
    auto fx = build_rules({email_rule(), card_rule()});

    std::vector<std::string> texts;
    // A repeated field (dedup stress) plus enough padding that combined
    // bytes clear the default 8192-byte auto-parallel gate, with >= 2 texts.
    for (int i = 0; i < 40; ++i) {
        // Built via separate `+=` steps rather than one long chained
        // expression: GCC 13 at -O3 mis-derives an out-of-bounds SSO-buffer
        // access (-Werror=array-bounds) when std::to_string results feed
        // straight into a multi-operator std::string concatenation chain
        // that's then passed directly to push_back.
        std::string text = "padding ";
        text += std::string(200, 'x');
        text += " user";
        text += std::to_string(i % 5);
        text += "@example.com card ";
        text += std::to_string(4000000000000000L + (i % 3));
        texts.push_back(std::move(text));
    }
    std::size_t total = 0;
    for (const auto& t : texts)
        total += t.size();
    ASSERT_GE(total, 8192u);
    ASSERT_GE(texts.size(), 2u);

    MaskOptions auto_opts;  // default parallel_min_bytes = 8192: this run fans out
    MaskOptions forced_serial_opts;
    forced_serial_opts.parallel_min_bytes = total + 1;  // never clears the gate -> serial

    Guard::MaskResult par = Guard::mask_texts(texts, fx.rules, auto_opts);
    Guard::MaskResult ser = Guard::mask_texts(texts, fx.rules, forced_serial_opts);

    EXPECT_EQ(par.masked_texts, ser.masked_texts);
    EXPECT_EQ(par.state.triggered_rule_ids, ser.state.triggered_rule_ids);
    EXPECT_EQ(par.state.triggered_data_types, ser.state.triggered_data_types);
    ASSERT_EQ(par.state.replacements.size(), ser.state.replacements.size());
    for (std::size_t i = 0; i < par.state.replacements.size(); ++i) {
        EXPECT_EQ(par.state.replacements[i].original, ser.state.replacements[i].original);
        EXPECT_EQ(par.state.replacements[i].placeholder, ser.state.replacements[i].placeholder);
        EXPECT_EQ(par.state.replacements[i].rule_id, ser.state.replacements[i].rule_id);
    }
}

TEST(GuardMasker, TextOutsideSpansIsByteIdentical) {
    auto fx = build_rules({make_rule("secret.token", "secret", "SECRET", DataType::Credentials)});
    const std::string text = "до secret после";
    const std::string prefix = "до ";
    const std::string suffix = " после";

    Guard::MaskResult got = Guard::mask_texts({text}, fx.rules);

    ASSERT_EQ(got.masked_texts.size(), 1u);
    EXPECT_EQ(got.masked_texts[0], prefix + "<SECRET_1>" + suffix);
}

// ── Additional coverage beyond the brief's floor ──────────────────────────

TEST(GuardMasker, UnionSpanCoalescedMatchUsesAttributedRulePlaceholder) {
    // "short" [0,4) and "long" [2,8) overlap; scan_rules coalesces them into
    // one union span attributed to "long" (the longer constituent) -- the
    // masker must mask that ONE union span with "long"'s placeholder/rule id,
    // not two separate placeholders.
    Rule short_rule = make_rule("overlap.short", "abcd", "SHORT", DataType::Custom);
    Rule long_rule = make_rule("overlap.long", "cdefgh", "LONG", DataType::ApiKeys);
    auto fx = build_rules({short_rule, long_rule});

    Guard::MaskResult got = Guard::mask_texts({"x abcdefgh y"}, fx.rules);

    EXPECT_EQ(got.masked_texts[0], "x <LONG_1> y");
    ASSERT_EQ(got.state.replacements.size(), 1u);
    EXPECT_EQ(got.state.replacements[0].rule_id, "overlap.long");
    EXPECT_EQ(got.state.replacements[0].original, "abcdefgh");
    EXPECT_EQ(got.state.replacements[0].placeholder, "<LONG_1>");
    EXPECT_EQ(got.state.triggered_rule_ids, (std::vector<std::string>{"overlap.long"}));
}

TEST(GuardMasker, MultiTextCounterContinuesAcrossTexts) {
    auto fx = build_rules({email_rule()});
    Guard::MaskResult got =
        Guard::mask_texts({"a@example.com", "b@example.com", "a@example.com again plus c@example.com"}, fx.rules);

    EXPECT_EQ(got.masked_texts[0], "<EMAIL_1>");
    EXPECT_EQ(got.masked_texts[1], "<EMAIL_2>");
    EXPECT_EQ(got.masked_texts[2], "<EMAIL_1> again plus <EMAIL_3>");

    ASSERT_EQ(got.state.replacements.size(), 3u);
    EXPECT_EQ(got.state.replacements[0].placeholder, "<EMAIL_1>");
    EXPECT_EQ(got.state.replacements[1].placeholder, "<EMAIL_2>");
    EXPECT_EQ(got.state.replacements[2].placeholder, "<EMAIL_3>");
}

TEST(GuardMasker, MultiTextSameOriginalDifferentTypeStillDedupes) {
    // Ports TestMaskerPlaceholderHelpers' reuse-ignores-differing-type
    // assertion indirectly through the public API: "secret" is masked once
    // via a SECRET-placeholder rule, then a DIFFERENT rule (placeholder
    // "DIFFERENT") also matches the literal string "secret" in another text
    // -- dedup keys on the ORIGINAL VALUE alone, so the second occurrence
    // reuses "<SECRET_1>" rather than minting "<DIFFERENT_1>".
    Rule secret_rule = make_rule("credentials.secret", "secret", "SECRET", DataType::Credentials);
    Rule different_rule = make_rule("credentials.other", "other", "DIFFERENT", DataType::Credentials);
    auto fx = build_rules({secret_rule, different_rule});

    Guard::MaskResult got = Guard::mask_texts({"secret and api", "secret and other"}, fx.rules);

    EXPECT_EQ(got.masked_texts[0], "<SECRET_1> and api");
    EXPECT_EQ(got.masked_texts[1], "<SECRET_1> and other");
}

TEST(GuardMasker, EmptyTextsVectorReturnsEmptyResult) {
    auto fx = build_rules({email_rule()});
    Guard::MaskResult got = Guard::mask_texts({}, fx.rules);

    EXPECT_TRUE(got.masked_texts.empty());
    EXPECT_TRUE(got.state.triggered_rule_ids.empty());
    EXPECT_TRUE(got.state.triggered_data_types.empty());
    EXPECT_TRUE(got.state.replacements.empty());
}

TEST(GuardMasker, TextWithNoMatchesPassesThroughUnchanged) {
    auto fx = build_rules({email_rule()});
    Guard::MaskResult got = Guard::mask_texts({"nothing sensitive here"}, fx.rules);

    ASSERT_EQ(got.masked_texts.size(), 1u);
    EXPECT_EQ(got.masked_texts[0], "nothing sensitive here");
    EXPECT_TRUE(got.state.triggered_rule_ids.empty());
    EXPECT_TRUE(got.state.triggered_data_types.empty());
    EXPECT_TRUE(got.state.replacements.empty());
}

TEST(GuardMasker, EmptyRulesVectorPassesEveryTextThroughUnchanged) {
    Guard::MaskResult got = Guard::mask_texts({"token=secret", "other"}, {});

    EXPECT_EQ(got.masked_texts, (std::vector<std::string>{"token=secret", "other"}));
    EXPECT_TRUE(got.state.replacements.empty());
}

TEST(GuardMasker, BlankPlaceholderRuleDetectsButNeverMasksOrTriggers) {
    // Registry.hpp's blank-placeholder guard means a rule like this compiles
    // fine (no placeholder recognizer) but still scans; masker.go:72's
    // `match.Placeholder == ""` skip means it's never masked, never
    // triggers, and never adds a Replacement -- ported verbatim.
    auto fx = build_rules({make_rule("silent.rule", "secret", "", DataType::Credentials)});
    Guard::MaskResult got = Guard::mask_texts({"token=secret here"}, fx.rules);

    EXPECT_EQ(got.masked_texts[0], "token=secret here");
    EXPECT_TRUE(got.state.triggered_rule_ids.empty());
    EXPECT_TRUE(got.state.triggered_data_types.empty());
    EXPECT_TRUE(got.state.replacements.empty());
}

TEST(GuardMasker, UnspecifiedDataTypeRuleTriggersRuleButNotDataType) {
    auto fx = build_rules({make_rule("unspecified.rule", "MARK", "MARK", DataType::Unspecified)});
    Guard::MaskResult got = Guard::mask_texts({"MARK here"}, fx.rules);

    EXPECT_EQ(got.masked_texts[0], "<MARK_1> here");
    EXPECT_EQ(got.state.triggered_rule_ids, (std::vector<std::string>{"unspecified.rule"}));
    EXPECT_TRUE(got.state.triggered_data_types.empty());
}

// ── Error propagation ──────────────────────────────────────────────────────
// mask_texts calls the concrete Scanner.hpp::scan_rules directly (no
// injectable scanner the way Go's mocked SensitiveScanner allows), and the
// only way to force scan_rules to throw is a permanently-broken CompiledRule
// (null `re`) -- a failure mode that is the SAME for every text, not
// text-content-dependent, so this port can't reproduce Go's
// "only text[1] fails" mocked scenario end-to-end through the public API.
// The "first error by lowest index wins" contract itself is pinned directly
// against detail::propagate_first_scan_error below instead, and the
// end-to-end throw/stop-early behavior is pinned against the concrete
// broken-rule failure mode here.

TEST(GuardMasker, MaskTextsThrowsRuntimeErrorAndNamesFailingIndex) {
    auto fx = build_rules({email_rule()});
    Guard::CompiledRule broken;
    broken.rule = make_rule("boom", "unused", "X");
    // broken.re left null -- forces the defensive throw in scan_one_rule.
    std::vector<const Guard::CompiledRule*> rules = fx.rules;
    rules.push_back(&broken);

    try {
        Guard::mask_texts({"ok", "also fine"}, rules);
        FAIL() << "expected mask_texts to throw";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("text[0]"), std::string::npos) << e.what();
    }
}

TEST(GuardMasker, PropagateFirstScanErrorPicksLowestIndex) {
    std::vector<Guard::detail::TextScanResult> results(3);
    try {
        throw std::runtime_error("error at index 1");
    } catch (...) {
        results[1].error = std::current_exception();
    }
    try {
        throw std::runtime_error("error at index 2");
    } catch (...) {
        results[2].error = std::current_exception();
    }

    try {
        Guard::detail::propagate_first_scan_error(results);
        FAIL() << "expected propagate_first_scan_error to throw";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("text[1]"), std::string::npos) << e.what();
        EXPECT_NE(std::string(e.what()).find("error at index 1"), std::string::npos) << e.what();
    }
}

TEST(GuardMasker, PropagateFirstScanErrorNoOpWhenNoneFailed) {
    std::vector<Guard::detail::TextScanResult> results(3);
    EXPECT_NO_THROW(Guard::detail::propagate_first_scan_error(results));
}

TEST(GuardMasker, ScanTextsSerialStopsAtFirstFailure) {
    auto fx = build_rules({make_rule("ok.rule", "aaa", "A")});
    Guard::CompiledRule broken;
    broken.rule = make_rule("boom", "unused", "X");
    std::vector<const Guard::CompiledRule*> rules = fx.rules;
    rules.push_back(&broken);

    MaskOptions opts;
    opts.parallel_min_bytes = 1'000'000;  // stay well under the gate -> serial
    std::vector<std::string> texts{"ok", "bad", "not scanned"};
    auto results = Guard::detail::scan_texts(texts, rules, opts);

    ASSERT_EQ(results.size(), 3u);
    EXPECT_TRUE(static_cast<bool>(results[0].error));
    // The serial loop stops at the first failure -- later slots were never
    // touched, so they carry neither an error nor any matches.
    EXPECT_FALSE(static_cast<bool>(results[1].error));
    EXPECT_TRUE(results[1].matches.empty());
    EXPECT_FALSE(static_cast<bool>(results[2].error));
    EXPECT_TRUE(results[2].matches.empty());
}

// ── Text-level fan-out gate ────────────────────────────────────────────────

TEST(GuardMasker, WorkerCountIsSerialForFewerThanTwoTexts) {
    MaskOptions opts;
    EXPECT_EQ(Guard::detail::text_scan_worker_count({}, opts), 1u);
    EXPECT_EQ(Guard::detail::text_scan_worker_count({"solo"}, opts), 1u);
}

TEST(GuardMasker, WorkerCountIsSerialBelowByteThreshold) {
    MaskOptions opts;
    opts.parallel_min_bytes = 8192;
    EXPECT_EQ(Guard::detail::text_scan_worker_count({"a", "b"}, opts), 1u);
}

TEST(GuardMasker, WorkerCountParallelizesAtOrAboveByteThreshold) {
    if (std::thread::hardware_concurrency() <= 1)
        GTEST_SKIP() << "single-core runner: cannot observe fan-out";

    MaskOptions opts;
    opts.parallel_min_bytes = 1;  // trivially cleared
    const std::size_t workers = Guard::detail::text_scan_worker_count({"a", "b", "c"}, opts);
    EXPECT_GT(workers, 1u);
    EXPECT_LE(workers, 3u);
}

TEST(GuardMasker, ZeroParallelMinBytesFallsBackToDefault) {
    MaskOptions opts;
    opts.parallel_min_bytes = 0;
    // Two 1-byte texts never clear the 8192-byte default, whether the
    // override is "0" (falls back to default) or omitted entirely.
    EXPECT_EQ(Guard::detail::text_scan_worker_count({"a", "b"}, opts), 1u);
}

// ── Reserved-placeholder collection ────────────────────────────────────────

TEST(GuardMasker, ReservedPlaceholdersCollectsEveryLookalikeToken) {
    auto reserved =
        Guard::detail::reserved_placeholders({"a <EMAIL_1> b", "c <FOO_BAR_42> d no angle bracket", "nothing here"});
    EXPECT_EQ(reserved.size(), 2u);
    EXPECT_NE(reserved.find("<EMAIL_1>"), reserved.end());
    EXPECT_NE(reserved.find("<FOO_BAR_42>"), reserved.end());
}

TEST(GuardMasker, ReservedPlaceholdersEmptyWhenNoAngleBracketsPresent) {
    auto reserved = Guard::detail::reserved_placeholders({"plain", "text", "no brackets"});
    EXPECT_TRUE(reserved.empty());
}

// ── MaskerState direct tests (masker.go's TestMaskerMaskText /
//    TestMaskerStateAcrossCalls / TestMaskerTriggeredDataTypesFiltersInvalidValues) ──

namespace {

ScanMatch find_match(std::string_view text, std::string_view needle, const CompiledRule* rule) {
    const std::size_t pos = text.find(needle);
    if (pos == std::string_view::npos)
        throw std::runtime_error("needle not found");
    return ScanMatch{pos, pos + needle.size(), rule};
}

}  // namespace

TEST(GuardMaskerState, NoMatchesReturnsOriginalText) {
    Guard::detail::MaskerState state({});
    EXPECT_EQ(state.mask_text("plain text", {}), "plain text");
}

TEST(GuardMaskerState, MasksByteSpanAfterUtf8Prefix) {
    auto fx = build_rules({make_rule("credentials.secret", "secret", "SECRET", DataType::Credentials)});
    Guard::detail::MaskerState state({});
    const std::string text = "до secret после";
    std::vector<ScanMatch> matches{find_match(text, "secret", fx.rules[0])};

    EXPECT_EQ(state.mask_text(text, matches), "до <SECRET_1> после");
}

TEST(GuardMaskerState, SkipsOverlappingLaterMatch) {
    auto fx = build_rules({
        make_rule("left", "abcd", "SECRET", DataType::Credentials),
        make_rule("right", "cdef", "KEY", DataType::ApiKeys),
    });
    Guard::detail::MaskerState state({});
    const std::string text = "abcdef";
    // Hand-built, deliberately overlapping (bypasses scan_rules, which would
    // never emit this) -- mirrors masker_test.go's identical case.
    std::vector<ScanMatch> matches{
        ScanMatch{0, 4, fx.rules[0]},
        ScanMatch{2, 6, fx.rules[1]},
    };

    EXPECT_EQ(state.mask_text(text, matches), "<SECRET_1>ef");
}

TEST(GuardMaskerState, SkipsEmptyFullTextAndEmptyPlaceholder) {
    auto fx = build_rules({
        make_rule("empty.full_text", "unused1", "SECRET", DataType::Credentials),
        make_rule("empty.placeholder", "unused2", "", DataType::Credentials),
    });
    Guard::detail::MaskerState state({});
    const std::string text = "token=secret";
    const std::size_t start = text.find("secret");
    std::vector<ScanMatch> matches{
        ScanMatch{start, start, fx.rules[0]},        // empty span -- FullText == ""
        ScanMatch{start, text.size(), fx.rules[1]},  // blank placeholder
    };

    EXPECT_EQ(state.mask_text(text, matches), "token=secret");
}

TEST(GuardMaskerState, StateAccumulatesAcrossMultipleMaskTextCalls) {
    auto fx = build_rules({
        make_rule("credentials.secret", "secret", "SECRET", DataType::Credentials),
        make_rule("api.key", "api", "API_KEY", DataType::ApiKeys),
        make_rule("credentials.secret.repeat", "secret", "DIFFERENT", DataType::Credentials),
        make_rule("credentials.other", "other", "SECRET", DataType::Credentials),
    });
    Guard::detail::MaskerState state({});

    const std::string text1 = "secret and api";
    std::vector<ScanMatch> matches1{
        find_match(text1, "secret", fx.rules[0]),
        find_match(text1, "api", fx.rules[1]),
    };
    const std::string got1 = state.mask_text(text1, matches1);

    const std::string text2 = "secret and other";
    std::vector<ScanMatch> matches2{
        find_match(text2, "secret", fx.rules[2]),
        find_match(text2, "other", fx.rules[3]),
    };
    const std::string got2 = state.mask_text(text2, matches2);

    EXPECT_EQ(got1, "<SECRET_1> and <API_KEY_1>");
    EXPECT_EQ(got2, "<SECRET_1> and <SECRET_2>");

    ASSERT_EQ(state.replacements().size(), 3u);
    EXPECT_EQ(state.replacements()[0].rule_id, "credentials.secret");
    EXPECT_EQ(state.replacements()[0].original, "secret");
    EXPECT_EQ(state.replacements()[0].placeholder, "<SECRET_1>");
    EXPECT_EQ(state.replacements()[1].rule_id, "api.key");
    EXPECT_EQ(state.replacements()[1].original, "api");
    EXPECT_EQ(state.replacements()[1].placeholder, "<API_KEY_1>");
    EXPECT_EQ(state.replacements()[2].rule_id, "credentials.other");
    EXPECT_EQ(state.replacements()[2].original, "other");
    EXPECT_EQ(state.replacements()[2].placeholder, "<SECRET_2>");

    EXPECT_EQ(
        state.triggered_rules(),
        (std::vector<std::string>{"api.key", "credentials.other", "credentials.secret", "credentials.secret.repeat"}));
    EXPECT_EQ(state.triggered_data_types(), (std::vector<DataType>{DataType::Credentials, DataType::ApiKeys}));
}

TEST(GuardMaskerState, TriggeredDataTypesFiltersUnspecifiedAndOutOfRange) {
    auto fx = build_rules({
        make_rule("unspecified", "a", "A", DataType::Unspecified),
        make_rule("valid", "c", "C", DataType::PersonalData),
    });
    // A raw out-of-range DataType, mirroring Go's DataType(999) -- reached
    // via a hand-built CompiledRule, exactly like the raw-CompiledRule tests
    // in test_guard_scanner.cpp.
    Guard::CompiledRule invalid;
    invalid.rule = make_rule("invalid", "b", "B", static_cast<DataType>(999));

    Guard::detail::MaskerState state({});
    const std::string text = "a b c";
    std::vector<ScanMatch> matches{
        find_match(text, "a", fx.rules[0]),
        ScanMatch{2, 3, &invalid},
        find_match(text, "c", fx.rules[1]),
    };

    const std::string got = state.mask_text(text, matches);

    EXPECT_EQ(got, "<A_1> <B_1> <C_1>");
    EXPECT_EQ(state.triggered_data_types(), (std::vector<DataType>{DataType::PersonalData}));
}
