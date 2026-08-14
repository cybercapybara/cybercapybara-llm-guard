/**
 * @file test_guard_prefilter.cpp
 * @brief Unit tests for `Guard::regex_guarantees_keyword` (Prefilter.hpp) and
 *        its wiring into `Registry::compile_rule` / `scan_rules`.
 *
 * Ports the Go reference's `TestCompileRule_PrefilterKeywords` (registry_test.go)
 * and `TestRealConfigPrefilterIsRecallPreservingOnUnicode`
 * (tests/rules/prefilter_unicode_test.go) test vectors, plus the additional
 * cases the task-1.8 brief calls out directly. Registry/Scanner wiring tests
 * (prefilter_eligible computation, filter_by_keywords, scan_rules
 * equivalence for hand-built rules) live in test_guard_registry.cpp /
 * test_guard_scanner.cpp; this file focuses on the prover itself and the
 * real 266-rule catalog.
 */

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "guard/Prefilter.hpp"
#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/RulesYaml.hpp"
#include "guard/Scanner.hpp"

using Guard::regex_guarantees_keyword;

// ── Port of registry_test.go's TestCompileRule_PrefilterKeywords ─────────
// Each case there records `want []string` (nil = ineligible); this port
// checks the boolean `regex_guarantees_keyword` directly (`want != nullopt`
// in the Go table becomes `true` here).

TEST(GuardPrefilter, KeywordIsALiteralInTheRegex) {
    EXPECT_TRUE(regex_guarantees_keyword("secret=([a-z]+)", {"secret"}));
}

TEST(GuardPrefilter, VendorContextLiteralGitleaksStyle) {
    EXPECT_TRUE(regex_guarantees_keyword(R"((?i)[\w.-]{0,50}?(?:adobe)[\s'"]{0,3}([a-f0-9]{32}))", {"adobe"}));
}

TEST(GuardPrefilter, EveryAlternationBranchContainsTheKeyword) {
    EXPECT_TRUE(regex_guarantees_keyword(R"((?:tokenA|tokenB)-[0-9]+)", {"token"}));
}

TEST(GuardPrefilter, StoredKeywordCaseIsIrrelevant) {
    // Go stores keywords lowercased before calling regexGuaranteesKeyword;
    // this port lowercases internally, so a mixed-case keyword argument
    // still proves the guarantee.
    EXPECT_TRUE(regex_guarantees_keyword("secret=([a-z]+)", {"SECRET"}));
}

TEST(GuardPrefilter, NoKeywordsIsNeverPrefilterable) {
    EXPECT_FALSE(regex_guarantees_keyword("secret=([a-z]+)", {}));
}

TEST(GuardPrefilter, ExternalKeywordAbsentFromRegexVaultLike) {
    EXPECT_FALSE(regex_guarantees_keyword(R"((hv[sbr]\.[A-Za-z0-9_\-]{90,120}))", {"vault", "VAULT_TOKEN"}));
}

TEST(GuardPrefilter, SelfContainedHexTokenTwilioLike) {
    EXPECT_FALSE(regex_guarantees_keyword(R"(\b([a-f0-9]{32})\b)", {"twilio", "auth_token"}));
}

TEST(GuardPrefilter, BareChecksumNumberInnLike) {
    EXPECT_FALSE(regex_guarantees_keyword(R"(\b\d{12}\b)", {"инн", "inn"}));
}

TEST(GuardPrefilter, AlternationBranchWithoutKeywordPassportLike) {
    EXPECT_FALSE(regex_guarantees_keyword(R"((?:паспорт|пасп\.?|серия)\s*(\d{6}))", {"паспорт", "серия", "номер"}));
}

TEST(GuardPrefilter, CaseInsensitiveAsciiLiteralStaysEligible) {
    EXPECT_TRUE(regex_guarantees_keyword(R"((?i)bearer\s+([a-z0-9]+))", {"bearer"}));
}

TEST(GuardPrefilter, CaseInsensitiveGreekSigmaLiteralIsIneligible) {
    // Greek sigma folds Sigma/sigma/final-sigma; the runtime prefilter's
    // strings-ToLower-equivalent keeps final sigma distinct from sigma, so a
    // RE2 (?i) match can diverge from what the lowercased text search would
    // find -- refuse the guarantee.
    EXPECT_FALSE(regex_guarantees_keyword("(?i)ΣΤΑ([0-9]+)", {"ΣΤΑ"}));
}

TEST(GuardPrefilter, CaseInsensitiveKeywordWithLongSCrossFoldIsIneligible) {
    // ASCII 's'/'S' cross-folds with U+017F LATIN SMALL LETTER LONG S under
    // RE2, but the runtime lowercase pass never normalises 'ſ' back to 's'.
    EXPECT_FALSE(regex_guarantees_keyword(R"((?i)secret=([a-z]+))", {"secret"}));
}

TEST(GuardPrefilter, CaseSensitiveNonAsciiLiteralStaysEligible) {
    EXPECT_TRUE(regex_guarantees_keyword(R"(паспорт\s*(\d{6}))", {"паспорт"}));
}

// ── Task-1.8-brief-specific vectors ───────────────────────────────────────

TEST(GuardPrefilter, StripeStyleUnderscoreLiteralWithCharClassSuffix) {
    EXPECT_TRUE(regex_guarantees_keyword("stripe_[a-z0-9]{24}", {"stripe"}));
}

TEST(GuardPrefilter, AlternationWhereOnlyOneBranchHasKeywordIsFalse) {
    EXPECT_FALSE(regex_guarantees_keyword("(foo|bar)", {"foo"}));
}

TEST(GuardPrefilter, NonCapturingAlternationConcatChildSuffices) {
    EXPECT_TRUE(regex_guarantees_keyword("(?:aws|amzn)key", {"key"}));
}

TEST(GuardPrefilter, StarWrappingTheLiteralIsFalse) {
    EXPECT_FALSE(regex_guarantees_keyword("(?:secret)*", {"secret"}));
}

TEST(GuardPrefilter, OptionalWrappingTheLiteralIsFalse) {
    EXPECT_FALSE(regex_guarantees_keyword("(?:secret)?", {"secret"}));
}

TEST(GuardPrefilter, PlusWrappingTheLiteralIsTrue) {
    // Unlike * and ?, + always contributes at least one copy of the operand.
    EXPECT_TRUE(regex_guarantees_keyword("(?:secret)+", {"secret"}));
}

// ── Op-mapping edge cases not directly in the Go table, pinning this
//    port's own AST construction (literal-run merging, concat "any
//    suffices" with a leading unprovable sibling, repeat with min>=2). ─────

TEST(GuardPrefilter, ConcatAnyChildSufficesEvenAfterAnUnprovableSibling) {
    // Mirrors the real "vendor context literal" shape but pinned narrowly:
    // an unprovable char-class-repeat sibling earlier in the same concat
    // must not stop a later literal from proving the guarantee.
    EXPECT_TRUE(regex_guarantees_keyword(R"([\w.-]{0,50}?secret=([a-z]+))", {"secret"}));
}

TEST(GuardPrefilter, RepeatWithMinAtLeastTwoGuaranteesLikeMinOne) {
    EXPECT_TRUE(regex_guarantees_keyword("(?:secret){2,4}", {"secret"}));
}

TEST(GuardPrefilter, RepeatWithMinZeroNeverGuarantees) {
    EXPECT_FALSE(regex_guarantees_keyword("(?:secret){0,4}", {"secret"}));
}

TEST(GuardPrefilter, CharacterClassAloneNeverGuarantees) {
    EXPECT_FALSE(regex_guarantees_keyword("[a-z]{6}", {"secret"}));
}

TEST(GuardPrefilter, DotAloneNeverGuarantees) {
    EXPECT_FALSE(regex_guarantees_keyword(".*", {"secret"}));
}

TEST(GuardPrefilter, NamedCaptureGroupBehavesLikeCaptureGroup) {
    EXPECT_TRUE(regex_guarantees_keyword("(?P<val>secret=[a-z]+)", {"secret"}));
}

TEST(GuardPrefilter, AsciiKAndKelvinCrossFoldIsFoldSafeUnlikeS) {
    // ASCII k/K's fold orbit adds U+212A KELVIN SIGN, but KELVIN SIGN's own
    // lowercase mapping IS 'k' -- unlike 's'/long-s, this orbit is
    // internally consistent, so a case-insensitive 'k'-only keyword stays
    // eligible even though PlaceholderRegex.hpp treats k/K as "wide" for an
    // unrelated (byte-length) reason.
    EXPECT_TRUE(regex_guarantees_keyword("(?i)key=([a-z0-9]+)", {"key"}));
}

TEST(GuardPrefilter, EmptyPatternNeverGuarantees) {
    EXPECT_FALSE(regex_guarantees_keyword("", {"secret"}));
}

// ── Full-catalog: eligibility stats + recall-preserving equivalence ──────
// The phase-1 exit criterion: both shipped catalogs (266 rules combined)
// must compile, SOME rules must end up prefilter_eligible (otherwise the
// whole feature is dead code against the real config), and scanning with
// the pre-filter on vs. off must return byte-identical results -- including
// over text containing hits for several distinct rules and Cyrillic
// keyword-bearing rules (ОГРН / ИНН), per the task brief.

namespace {

std::vector<std::string> real_catalog_paths() {
    const std::string root(LLMGUARD_REPO_ROOT);
    return {root + "/configs/rules.yaml", root + "/configs/rules.gitleaks.generated.yaml"};
}

std::shared_ptr<const Guard::Registry> build_real_registry() {
    auto loaded = Guard::load_rules_files(real_catalog_paths());
    return Guard::Registry::build(loaded.rules);
}

std::vector<const Guard::CompiledRule*> all_rule_pointers(const Guard::Registry& reg) {
    std::vector<const Guard::CompiledRule*> out;
    out.reserve(reg.size());
    for (const auto& cr : reg.all())
        out.push_back(&cr);
    return out;
}

void expect_scan_equivalence(const std::string& text, const std::vector<const Guard::CompiledRule*>& rules) {
    Guard::ScanOptions off;
    off.prefilter_enabled = false;
    Guard::ScanOptions on;
    on.prefilter_enabled = true;

    auto matches_off = Guard::scan_rules(text, rules, off);
    auto matches_on = Guard::scan_rules(text, rules, on);

    ASSERT_EQ(matches_off.size(), matches_on.size());
    for (std::size_t i = 0; i < matches_off.size(); ++i) {
        EXPECT_EQ(matches_off[i].start, matches_on[i].start);
        EXPECT_EQ(matches_off[i].end, matches_on[i].end);
        ASSERT_NE(matches_off[i].rule, nullptr);
        ASSERT_NE(matches_on[i].rule, nullptr);
        EXPECT_EQ(matches_off[i].rule->rule.id, matches_on[i].rule->rule.id) << "diverged at match index " << i;
    }
}

}  // namespace

TEST(GuardPrefilter, FullCatalogHasNonEmptyEligibleSet) {
    auto reg = build_real_registry();
    ASSERT_EQ(reg->size(), 266u);

    std::size_t keyword_bearing = 0;
    std::size_t eligible = 0;
    for (const auto& cr : reg->all()) {
        if (!cr.rule.keywords.empty())
            ++keyword_bearing;
        if (cr.prefilter_eligible)
            ++eligible;
    }

    EXPECT_GT(keyword_bearing, 0u);
    // The phase-1 exit criterion (task-1.8 brief): the whole feature is dead
    // weight against the real catalog if nothing ever ends up eligible.
    // Deliberately not a tighter ratio bound here -- many of the
    // gitleaks-generated vendor names contain an ASCII 's'/'S' and are
    // matched under an enclosing "(?i)", which genuinely (and correctly,
    // matching Go's own foldSafeForToLower) makes them fold-unsafe and
    // therefore ineligible (see GuardPrefilter.
    // CaseInsensitiveKeywordWithLongSCrossFoldIsIneligible) -- so the exact
    // eligible fraction isn't a stable enough invariant to pin a ratio on.
    EXPECT_GT(eligible, 0u);

    // prefilter_ineligible_rule_ids is consistent with the per-rule flags
    // computed above: every keyword-bearing, non-eligible rule appears
    // exactly once, sorted.
    auto ineligible_ids = reg->prefilter_ineligible_rule_ids();
    EXPECT_EQ(ineligible_ids.size(), keyword_bearing - eligible);
    EXPECT_TRUE(std::is_sorted(ineligible_ids.begin(), ineligible_ids.end()));
}

TEST(GuardPrefilter, FullCatalogScanEquivalenceAcrossFiveDistinctRulesIncludingCyrillic) {
    auto reg = build_real_registry();
    auto rules = all_rule_pointers(*reg);

    // Real, valid values for 7 candidate rules (comfortable margin over the
    // ">= 5 distinct" bar below, since exactly which of the 266 real rules
    // end up as the coalesced "primary" for a given span isn't hand-provable
    // against the full catalog -- only that the recall-preserving guarantee
    // holds regardless, which expect_scan_equivalence checks separately).
    // Each candidate sits on its own line, well clear of the others, so no
    // broader catalog rule can span two candidates and coalesce them into
    // one match. OGRN/inn-org checksums are reused from
    // test_guard_validators_checksums.cpp's own verified-valid vectors so
    // their validators actually accept them.
    const std::string text =
        "Реквизиты: ОГРН 1027700132195.\n"
        "Реквизиты: ИНН 7707083893.\n"
        "adobe_key: \"deadbeefdeadbeefdeadbeefdeadbeef\"\n"
        "token id 0123456789abcdef0123456789abcdef done\n"
        "Authorization: Bearer abcDEF123456ghijklMNOP\n"
        "contact person.name@example.com for access\n"
        "server address 192.168.1.1 is up\n";

    // Sanity: prefilter-off alone must actually find several distinct rules
    // -- otherwise the equivalence check below would be trivially (and
    // uselessly) true over zero matches.
    Guard::ScanOptions off;
    auto baseline = Guard::scan_rules(text, rules, off);
    std::vector<std::string> distinct_rule_ids;
    for (const auto& m : baseline) {
        const auto& id = m.rule->rule.id;
        const auto it = std::find(distinct_rule_ids.begin(), distinct_rule_ids.end(), id);
        if (it == distinct_rule_ids.end())
            distinct_rule_ids.push_back(id);
    }
    EXPECT_GE(distinct_rule_ids.size(), 5u) << "expected hits for >= 5 distinct rules to make this test meaningful";

    expect_scan_equivalence(text, rules);

    // Same corpus, padded well past the parallel-fan-out threshold, so the
    // equivalence check also exercises scan_rules's parallel dispatch path
    // (rules.size() is already far past kParallelRuleThreshold for the
    // full catalog).
    std::string large_text = text + std::string(8 * 1024, 'x');
    ASSERT_GE(large_text.size(), Guard::detail::kParallelTextThreshold);
    expect_scan_equivalence(large_text, rules);
}

// ── Port of prefilter_unicode_test.go's corpus ────────────────────────────
// TestRealConfigPrefilterIsRecallPreservingOnUnicode's exact bodies, run
// against the real catalog the same way: prefilter on must equal off for
// every one of them, including bodies mixing Cyrillic, Greek fold-unsafe
// characters, and long-s.

TEST(GuardPrefilter, RealConfigPrefilterIsRecallPreservingOnUnicodeCorpus) {
    auto reg = build_real_registry();
    auto rules = all_rule_pointers(*reg);

    const std::vector<std::string> bodies{
        "Bearer sk-ABCDEFGHIJKLMNOPQRSTUVWX secret=пароль",
        "ключ ΣΤΑ значение api_key=deadbeefdeadbeefdeadbeefdeadbeef",
        "straße SECRET ſecret Σ σ ς mixed-case AWS_SECRET",
        "нормальный текст без секретов",
    };

    for (const auto& body : bodies)
        expect_scan_equivalence(body, rules);
}
