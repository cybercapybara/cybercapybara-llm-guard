/**
 * @file test_guard_registry.cpp
 * @brief Unit tests for Guard::Registry / Guard::CompiledRule /
 *        Guard::ReloadableRegistry.
 *
 * Mirrors the Go reference's registry tests
 * (pkg/guardrails/regex/registry/registry_test.go): CompileRule rejection
 * cases, duplicate-id-on-build, by-id/by-data-type lookups, and the
 * blank-placeholder guard (`compilePlaceholderRegex`'s
 * `TrimSpace(placeholder) == ""` -> nil regex, zero length, no error) --
 * confirmed by reading registry.go directly, not assumed: the Go reference
 * has no fallback anywhere that derives a placeholder name from the rule id.
 *
 * Also covers `ReloadableRegistry`'s atomic swap/get pair and the phase-1
 * exit-criterion catalog smoke test: both shipped rule catalogs must compile
 * end-to-end under the real Registry.
 */

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "guard/Errors.hpp"
#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/RulesYaml.hpp"

namespace {

Guard::Rule make_rule(std::string id, std::string regex = "[A-Z]+", std::string placeholder = "TEST",
                      Guard::DataType data_type = Guard::DataType::Credentials) {
    Guard::Rule r;
    r.id = std::move(id);
    r.name = r.id;
    r.data_type = data_type;
    r.regex = std::move(regex);
    r.masking.placeholder = std::move(placeholder);
    return r;
}

}  // namespace

// ── Registry::compile_rule: rejection cases ─────────────────────────────

TEST(GuardRegistry, CompileRuleRejectsInvalidId) {
    Guard::Rule r = make_rule("UPPER");  // uppercase not allowed by ^[a-z0-9_.-]{1,128}$

    bool threw = false;
    try {
        Guard::Registry::compile_rule(r);
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::InvalidId);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRegistry, CompileRuleRejectsEmptyId) {
    Guard::Rule r = make_rule("");

    bool threw = false;
    try {
        Guard::Registry::compile_rule(r);
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::InvalidId);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRegistry, CompileRuleRejectsUnknownValidator) {
    Guard::Rule r = make_rule("test.rule");
    r.validators = {"not_a_real_validator"};

    bool threw = false;
    try {
        Guard::Registry::compile_rule(r);
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::UnknownValidator);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRegistry, CompileRuleAcceptsKnownValidators) {
    Guard::Rule r = make_rule("test.rule");
    r.validators = {"luhn", "entropy", "banlist"};

    EXPECT_NO_THROW(Guard::Registry::compile_rule(r));
}

TEST(GuardRegistry, CompileRuleRejectsBadRegex) {
    // RE2 doesn't support lookbehind -- fails to compile.
    Guard::Rule r = make_rule("test.rule", "(?<=x)y");

    bool threw = false;
    try {
        Guard::Registry::compile_rule(r);
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::BadRegex);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRegistry, CompileRuleRejectsCaptureGroupExceedingRegexGroups) {
    Guard::Rule r = make_rule("test.rule", "(a)");  // exactly 1 capturing group
    r.masking.capture_groups = {2};

    bool threw = false;
    try {
        Guard::Registry::compile_rule(r);
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::BadCaptureGroup);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRegistry, CompileRuleRejectsNonPositiveCaptureGroup) {
    Guard::Rule r = make_rule("test.rule", "(a)");
    r.masking.capture_groups = {0};

    bool threw = false;
    try {
        Guard::Registry::compile_rule(r);
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::BadCaptureGroup);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRegistry, CompileRuleAcceptsValidCaptureGroups) {
    Guard::Rule r = make_rule("test.rule", "(a)|(b)");
    r.masking.capture_groups = {1, 2};

    EXPECT_NO_THROW(Guard::Registry::compile_rule(r));
}

TEST(GuardRegistry, CompileRuleAcceptsEmptyCaptureGroupsAsFullMatch) {
    Guard::Rule r = make_rule("test.rule", "secret");
    r.masking.capture_groups.clear();

    EXPECT_NO_THROW(Guard::Registry::compile_rule(r));
}

// ── Registry::compile_rule: blank placeholder guard ─────────────────────
// Read directly from compilePlaceholderRegex (registry.go:394-398): a
// blank/whitespace-only placeholder means no recognizer at all -- nil regex,
// zero length, and (critically) no error. No id-derived fallback exists.

TEST(GuardRegistry, EmptyPlaceholderCompilesWithNullRecognizer) {
    Guard::Rule r = make_rule("blank.placeholder", "[A-Z]+", "");

    Guard::CompiledRule cr = Guard::Registry::compile_rule(r);
    EXPECT_EQ(cr.placeholder_re, nullptr);
    EXPECT_EQ(cr.placeholder_len, 0u);
    ASSERT_NE(cr.re, nullptr);
    EXPECT_TRUE(cr.re->ok());
}

TEST(GuardRegistry, WhitespaceOnlyPlaceholderCompilesWithNullRecognizer) {
    Guard::Rule r = make_rule("blank.placeholder.ws", "[A-Z]+", "   ");

    Guard::CompiledRule cr = Guard::Registry::compile_rule(r);
    EXPECT_EQ(cr.placeholder_re, nullptr);
    EXPECT_EQ(cr.placeholder_len, 0u);
}

TEST(GuardRegistry, NonBlankPlaceholderCompilesWithRecognizer) {
    Guard::Rule r = make_rule("pii.email", "[A-Z]+", "EMAIL");

    Guard::CompiledRule cr = Guard::Registry::compile_rule(r);
    ASSERT_NE(cr.placeholder_re, nullptr);
    EXPECT_TRUE(cr.placeholder_re->ok());
    EXPECT_GT(cr.placeholder_len, 0u);
    EXPECT_EQ(cr.placeholder_re->NumberOfCapturingGroups(), 1);
}

TEST(GuardRegistry, PrefilterEligibleAlwaysFalse) {
    // Task 1.8 wires the keyword-prefilter prover -- until then this stays
    // false unconditionally, even for a rule with keywords.
    Guard::Rule r = make_rule("test.rule", "secret");
    r.keywords = {"secret"};

    Guard::CompiledRule cr = Guard::Registry::compile_rule(r);
    EXPECT_FALSE(cr.prefilter_eligible);
}

// ── Registry::build: duplicate ids ───────────────────────────────────────

TEST(GuardRegistry, BuildRejectsDuplicateId) {
    std::vector<Guard::Rule> rules{make_rule("dup.rule"), make_rule("dup.rule")};

    bool threw = false;
    try {
        Guard::Registry::build(rules);
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::DuplicateId);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRegistry, BuildPropagatesFirstInvalidRuleError) {
    std::vector<Guard::Rule> rules{make_rule("ok.rule"), make_rule("UPPER")};

    bool threw = false;
    try {
        Guard::Registry::build(rules);
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::InvalidId);
    }
    EXPECT_TRUE(threw);
}

// ── Registry: by_id / for_data_types / size / all ────────────────────────

TEST(GuardRegistry, ByIdFindsAndReturnsNullForUnknown) {
    std::vector<Guard::Rule> rules{
        make_rule("pii.email", "[A-Z]+", "EMAIL", Guard::DataType::PersonalData),
        make_rule("tokens.api", "[A-Z]+", "API_TOKEN", Guard::DataType::ApiKeys),
    };
    auto reg = Guard::Registry::build(rules);

    const Guard::CompiledRule* found = reg->by_id("pii.email");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->rule.id, "pii.email");

    EXPECT_EQ(reg->by_id("missing.rule"), nullptr);
}

TEST(GuardRegistry, ForDataTypesReturnsOnlyMatchingRulesInOrder) {
    std::vector<Guard::Rule> rules{
        make_rule("pii.email", "[A-Z]+", "EMAIL", Guard::DataType::PersonalData),
        make_rule("tokens.api", "[A-Z]+", "API_TOKEN", Guard::DataType::ApiKeys),
        make_rule("pii.phone", "[A-Z]+", "PHONE", Guard::DataType::PersonalData),
    };
    auto reg = Guard::Registry::build(rules);

    auto matches = reg->for_data_types({Guard::DataType::PersonalData});
    ASSERT_EQ(matches.size(), 2u);
    EXPECT_EQ(matches[0]->rule.id, "pii.email");
    EXPECT_EQ(matches[1]->rule.id, "pii.phone");

    EXPECT_TRUE(reg->for_data_types({Guard::DataType::IpAddresses}).empty());
}

TEST(GuardRegistry, SizeAndAllReflectBuiltRules) {
    std::vector<Guard::Rule> rules{make_rule("a.rule"), make_rule("b.rule")};
    auto reg = Guard::Registry::build(rules);

    EXPECT_EQ(reg->size(), 2u);
    EXPECT_EQ(reg->all().size(), 2u);
}

// ── ReloadableRegistry: atomic swap ──────────────────────────────────────

TEST(GuardRegistry, ReloadableRegistryGetReturnsInitialSnapshot) {
    auto reg = Guard::Registry::build({make_rule("a.rule")});
    Guard::ReloadableRegistry reloadable(reg);

    auto snapshot = reloadable.get();
    ASSERT_NE(snapshot, nullptr);
    EXPECT_EQ(snapshot->size(), 1u);
    EXPECT_NE(snapshot->by_id("a.rule"), nullptr);
}

TEST(GuardRegistry, ReloadableRegistrySwapIsVisibleToSubsequentGet) {
    auto reg1 = Guard::Registry::build({make_rule("a.rule")});
    Guard::ReloadableRegistry reloadable(reg1);

    auto reg2 = Guard::Registry::build({make_rule("a.rule"), make_rule("b.rule")});
    reloadable.swap(reg2);

    auto snapshot = reloadable.get();
    EXPECT_EQ(snapshot->size(), 2u);
    EXPECT_EQ(snapshot.get(), reg2.get());
}

TEST(GuardRegistry, ReloadableRegistryOldSnapshotStaysValidAfterSwap) {
    auto reg1 = Guard::Registry::build({make_rule("a.rule")});
    Guard::ReloadableRegistry reloadable(reg1);

    auto old_snapshot = reloadable.get();  // holds its own shared_ptr ref

    auto reg2 = Guard::Registry::build({make_rule("a.rule"), make_rule("b.rule")});
    reloadable.swap(reg2);

    // The pointer captured before the swap is still a complete, usable
    // Registry -- shared_ptr refcounting keeps it alive.
    ASSERT_NE(old_snapshot, nullptr);
    EXPECT_EQ(old_snapshot->size(), 1u);
    EXPECT_NE(old_snapshot->by_id("a.rule"), nullptr);

    // The new snapshot, fetched fresh, reflects the swap.
    EXPECT_EQ(reloadable.get()->size(), 2u);
}

// ── Full-catalog smoke test: the phase-1 exit criterion ──────────────────
// Both shipped rule catalogs must load AND compile end-to-end through the
// real Registry -- not just the loader. size()==266 pins the known-good
// combined rule count (46 + 220, see test_guard_rules_yaml.cpp); every
// compiled rule with a non-null placeholder recognizer must have a positive
// bound, since that bound sizes the SSE pending buffer downstream.

namespace {

std::vector<std::string> real_catalog_paths() {
    const std::string root(LLMGUARD_REPO_ROOT);
    return {root + "/configs/rules.yaml", root + "/configs/rules.gitleaks.generated.yaml"};
}

}  // namespace

TEST(GuardRegistry, FullCatalogCompiles) {
    auto loaded = Guard::load_rules_files(real_catalog_paths());

    std::shared_ptr<const Guard::Registry> reg;
    ASSERT_NO_THROW(reg = Guard::Registry::build(loaded.rules));

    EXPECT_EQ(reg->size(), 266u);
    for (const auto& cr : reg->all()) {
        if (cr.placeholder_re == nullptr)
            continue;
        EXPECT_GT(cr.placeholder_len, 0u) << "rule '" << cr.rule.id << "' has zero placeholder_len";
    }
}
