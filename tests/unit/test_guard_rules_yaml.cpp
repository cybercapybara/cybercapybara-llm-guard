/**
 * @file test_guard_rules_yaml.cpp
 * @brief Unit tests for Guard::Rule / Guard::DataType / Guard::load_rules_files.
 *
 * Mirrors the Go reference's loader tests
 * (pkg/guardrails/regex/rule/loader_test.go): group/data_type inheritance,
 * keyword/banlist lower-casing, duplicate-rule_id-across-files, path
 * dedup, empty-input rejection — plus loading the two real ported catalogs
 * that ship in configs/.
 */

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

#include "guard/Errors.hpp"
#include "guard/Rule.hpp"
#include "guard/RulesYaml.hpp"
#include "guard/Unicode.hpp"

namespace {

// RAII temp-file fixture: unique path per instance (so multiple files can
// coexist within one test), removed in the destructor so an early
// ASSERT_*/FAIL return -- which skips the rest of the test body -- still
// cleans up rather than leaking files into the temp dir across runs.
class TempYamlFile {
public:
    explicit TempYamlFile(const std::string& content) {
        static std::atomic<int> counter{0};
        const auto* test_info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string label = test_info ? std::string(test_info->test_suite_name()) + "_" + test_info->name()
                                            : std::string("guard_rules");
        path_ = (std::filesystem::temp_directory_path() /
                 ("guard_rules_" + label + "_" + std::to_string(counter.fetch_add(1)) + ".yaml"))
                    .string();
        std::ofstream file(path_);
        file << content;
        const bool write_ok = static_cast<bool>(file);
        file.close();
        EXPECT_TRUE(write_ok) << "failed writing temp yaml file: " << path_;
    }

    ~TempYamlFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    TempYamlFile(const TempYamlFile&) = delete;
    TempYamlFile& operator=(const TempYamlFile&) = delete;

    const std::string& path() const { return path_; }

private:
    std::string path_;
};

}  // namespace

// ── Rule + group inheritance ────────────────────────────────────────────

TEST(GuardRulesYaml, GroupFieldsInheritedAndFieldsParsed) {
    TempYamlFile file(R"(
guardrails_regex_rules:
  - data_type: 1
    group_priority: 90
    name: CREDENTIALS
    display_name: "Credentials"
    description: "test group one"
    rules:
      - rule_id: "credentials.example"
        name: "credentials.example"
        regex: '\bfoo\b'
        keywords: ["Secret", "API"]
        min_length: 8
        entropy: 3.0
        banlist: ["ExAmple", "Placeholder"]
        validators: [entropy, banlist]
        default_on: true
        masking:
          capture_groups: [1, 2]
          placeholder: "EXAMPLE"
  - data_type: 4
    group_priority: 10
    name: IP_ADDRESSES
    display_name: "IP addresses"
    description: "test group two"
    rules:
      - rule_id: "ip.example"
        name: "ip.example"
        regex: '\d+\.\d+\.\d+\.\d+'
        default_on: false
        masking:
          placeholder: "IPV4"
)");

    auto loaded = Guard::load_rules_files({file.path()});

    ASSERT_EQ(loaded.groups.size(), 2u);
    EXPECT_EQ(loaded.groups[0].data_type, Guard::DataType::Credentials);
    EXPECT_EQ(loaded.groups[0].priority, 90);
    EXPECT_EQ(loaded.groups[0].name, "CREDENTIALS");
    EXPECT_EQ(loaded.groups[0].display_name, "Credentials");
    EXPECT_EQ(loaded.groups[0].description, "test group one");
    EXPECT_EQ(loaded.groups[1].data_type, Guard::DataType::IpAddresses);
    EXPECT_EQ(loaded.groups[1].priority, 10);

    ASSERT_EQ(loaded.rules.size(), 2u);

    const Guard::Rule& r0 = loaded.rules[0];
    EXPECT_EQ(r0.id, "credentials.example");
    EXPECT_EQ(r0.name, "credentials.example");
    // Group name + data_type are inherited from the enclosing group, not
    // read from the rule itself.
    EXPECT_EQ(r0.group, "CREDENTIALS");
    EXPECT_EQ(r0.data_type, Guard::DataType::Credentials);
    EXPECT_EQ(r0.regex, "\\bfoo\\b");
    // Keywords are lower-cased at load time.
    ASSERT_EQ(r0.keywords.size(), 2u);
    EXPECT_EQ(r0.keywords[0], "secret");
    EXPECT_EQ(r0.keywords[1], "api");
    // ... as is the banlist.
    ASSERT_EQ(r0.banlist.size(), 2u);
    EXPECT_EQ(r0.banlist[0], "example");
    EXPECT_EQ(r0.banlist[1], "placeholder");
    EXPECT_EQ(r0.min_length, 8u);
    EXPECT_DOUBLE_EQ(r0.entropy, 3.0);
    ASSERT_EQ(r0.validators.size(), 2u);
    EXPECT_EQ(r0.validators[0], "entropy");
    EXPECT_EQ(r0.validators[1], "banlist");
    EXPECT_TRUE(r0.default_on);
    ASSERT_EQ(r0.masking.capture_groups.size(), 2u);
    EXPECT_EQ(r0.masking.capture_groups[0], 1);
    EXPECT_EQ(r0.masking.capture_groups[1], 2);
    EXPECT_EQ(r0.masking.placeholder, "EXAMPLE");

    const Guard::Rule& r1 = loaded.rules[1];
    EXPECT_EQ(r1.id, "ip.example");
    EXPECT_EQ(r1.group, "IP_ADDRESSES");
    EXPECT_EQ(r1.data_type, Guard::DataType::IpAddresses);
    // No masking.capture_groups given -> full-match mode (empty vector).
    EXPECT_TRUE(r1.masking.capture_groups.empty());
    EXPECT_EQ(r1.masking.placeholder, "IPV4");
    // No keywords/banlist/validators given -> empty, not garbage.
    EXPECT_TRUE(r1.keywords.empty());
    EXPECT_TRUE(r1.banlist.empty());
    EXPECT_TRUE(r1.validators.empty());
    EXPECT_EQ(r1.min_length, 0u);
    EXPECT_DOUBLE_EQ(r1.entropy, 0.0);
    // Explicit `default_on: false` overrides the declared default.
    EXPECT_FALSE(r1.default_on);
}

TEST(GuardRulesYaml, DefaultOnAbsentKeepsDeclaredDefault) {
    // Interface-contract ruling: Rule::default_on{true} is the struct's
    // declared default; an omitted YAML key must NOT be reinterpreted as
    // Go's inert zero-value. Only an explicit `default_on: false` flips it.
    TempYamlFile file(R"(
guardrails_regex_rules:
  - data_type: 1
    group_priority: 1
    name: CREDENTIALS
    display_name: "Credentials"
    description: "d"
    rules:
      - rule_id: "credentials.default_on_absent"
        name: "credentials.default_on_absent"
        regex: 'x'
        masking:
          placeholder: "X"
)");

    auto loaded = Guard::load_rules_files({file.path()});

    ASSERT_EQ(loaded.rules.size(), 1u);
    EXPECT_TRUE(loaded.rules[0].default_on);
}

TEST(GuardRulesYaml, RuleLevelGroupAndDataTypeKeysAreIgnored) {
    // A rule can't override its group's name/data_type by declaring its own
    // `group:`/`data_type:` keys -- those are inherited from the enclosing
    // group entry only, mirroring the Go reference (`yaml:"-"` on both
    // fields there).
    TempYamlFile file(R"(
guardrails_regex_rules:
  - data_type: 1
    group_priority: 1
    name: CREDENTIALS
    display_name: "Credentials"
    description: "d"
    rules:
      - rule_id: "credentials.spoofed_fields"
        name: "credentials.spoofed_fields"
        group: "SOMETHING_ELSE"
        data_type: 9
        regex: 'x'
        masking:
          placeholder: "X"
)");

    auto loaded = Guard::load_rules_files({file.path()});

    ASSERT_EQ(loaded.rules.size(), 1u);
    EXPECT_EQ(loaded.rules[0].group, "CREDENTIALS");
    EXPECT_EQ(loaded.rules[0].data_type, Guard::DataType::Credentials);
}

TEST(GuardRulesYaml, GroupWithoutRulesKeyIsEmptyGroup) {
    TempYamlFile file(R"(
guardrails_regex_rules:
  - data_type: 6
    group_priority: 1
    name: CUSTOM
    display_name: "Custom"
    description: "no rules key at all"
)");

    auto loaded = Guard::load_rules_files({file.path()});

    ASSERT_EQ(loaded.groups.size(), 1u);
    EXPECT_EQ(loaded.groups[0].name, "CUSTOM");
    EXPECT_TRUE(loaded.rules.empty());
}

TEST(GuardRulesYaml, UnknownTopLevelAndRuleKeysAreIgnored) {
    // Forward-compat: neither an unrecognized top-level sibling key nor an
    // unrecognized rule-level key should break the load.
    TempYamlFile file(R"(
some_future_top_level_key: "ignore me"
guardrails_regex_rules:
  - data_type: 1
    group_priority: 1
    name: CREDENTIALS
    display_name: "Credentials"
    description: "d"
    some_future_group_key: 123
    rules:
      - rule_id: "credentials.forward_compat"
        name: "credentials.forward_compat"
        regex: 'x'
        some_future_rule_key: "ignore me too"
        masking:
          placeholder: "X"
)");

    auto loaded = Guard::load_rules_files({file.path()});

    ASSERT_EQ(loaded.rules.size(), 1u);
    EXPECT_EQ(loaded.rules[0].id, "credentials.forward_compat");
}

TEST(GuardRulesYaml, DataTypeOutsideNamedEnumStillLoads) {
    // The Go reference's Rule.DataType is a raw int (not a strict enum) at
    // load time -- an out-of-range value round-trips rather than erroring.
    // Guard::DataType is a C++ enum class over int, so a static_cast holds
    // the raw value the same way.
    TempYamlFile file(R"(
guardrails_regex_rules:
  - data_type: 42
    group_priority: 900
    name: test.group
    display_name: "Test"
    description: "Desc"
    rules:
      - rule_id: "test.rule"
        name: test.rule
        regex: '\bfoo\b'
        masking:
          placeholder: "TEST"
)");

    auto loaded = Guard::load_rules_files({file.path()});

    ASSERT_EQ(loaded.groups.size(), 1u);
    EXPECT_EQ(static_cast<int>(loaded.groups[0].data_type), 42);
    EXPECT_EQ(loaded.groups[0].priority, 900);
    ASSERT_EQ(loaded.rules.size(), 1u);
    EXPECT_EQ(static_cast<int>(loaded.rules[0].data_type), 42);
    EXPECT_EQ(loaded.rules[0].group, "test.group");
}

// ── load_rules_file (singular) ───────────────────────────────────────────

namespace {

// The two real catalogs shipped in configs/, loaded together.
std::vector<std::string> real_catalog_paths() {
    const std::string root(LLMGUARD_REPO_ROOT);
    return {root + "/configs/rules.yaml", root + "/configs/rules.gitleaks.generated.yaml"};
}

}  // namespace

TEST(GuardRulesYaml, LoadRulesFileSingularLoadsOneFile) {
    TempYamlFile file(R"(
guardrails_regex_rules:
  - data_type: 1
    group_priority: 1
    name: CREDENTIALS
    display_name: "Credentials"
    description: "d"
    rules:
      - rule_id: "credentials.singular"
        name: "credentials.singular"
        regex: 'x'
        masking:
          placeholder: "X"
)");

    auto loaded = Guard::load_rules_file(file.path());

    ASSERT_EQ(loaded.groups.size(), 1u);
    ASSERT_EQ(loaded.rules.size(), 1u);
    EXPECT_EQ(loaded.rules[0].id, "credentials.singular");
}

// ── Multi-file loading: dedup, merge, duplicate rule_id ─────────────────

TEST(GuardRulesYaml, LoadsAndMergesMultipleFiles) {
    const std::string tmpl = R"(
guardrails_regex_rules:
  - data_type: 1
    group_priority: 100
    name: CREDENTIALS
    display_name: "Credentials"
    description: "test"
    rules:
      - rule_id: "%s"
        name: "%s"
        regex: "test_[a-z0-9]+"
        masking:
          placeholder: "TEST"
)";
    auto render = [&](const std::string& id) {
        std::string out = tmpl;
        auto pos = out.find("%s");
        out.replace(pos, 2, id);
        pos = out.find("%s");
        out.replace(pos, 2, id);
        return out;
    };
    TempYamlFile f1(render("r1"));
    TempYamlFile f2(render("r2"));

    auto loaded = Guard::load_rules_files({f1.path(), f2.path()});

    EXPECT_EQ(loaded.groups.size(), 2u);
    ASSERT_EQ(loaded.rules.size(), 2u);
    EXPECT_EQ(loaded.rules[0].id, "r1");
    EXPECT_EQ(loaded.rules[1].id, "r2");
}

TEST(GuardRulesYaml, DuplicateRuleIdAcrossFilesThrows) {
    const std::string tmpl = R"(
guardrails_regex_rules:
  - data_type: 1
    group_priority: 100
    name: CREDENTIALS
    display_name: "Credentials"
    description: "test"
    rules:
      - rule_id: "dup"
        name: "dup"
        regex: "test_[a-z0-9]+"
        masking:
          placeholder: "TEST"
)";
    TempYamlFile f1(tmpl);
    TempYamlFile f2(tmpl);

    bool threw = false;
    try {
        Guard::load_rules_files({f1.path(), f2.path()});
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::DuplicateId);
        EXPECT_NE(std::string(e.what()).find("dup"), std::string::npos);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRulesYaml, RepeatedPathIsLoadedOnce) {
    TempYamlFile file(R"(
guardrails_regex_rules:
  - data_type: 1
    group_priority: 100
    name: CREDENTIALS
    display_name: "Credentials"
    description: "test"
    rules:
      - rule_id: "solo"
        name: "solo"
        regex: "x"
        masking:
          placeholder: "X"
)");

    // Same path given twice (and once with surrounding whitespace, which
    // should trim to the same path) -- loaded exactly once, not thrice.
    auto loaded = Guard::load_rules_files({file.path(), file.path(), "  " + file.path() + "  "});

    EXPECT_EQ(loaded.groups.size(), 1u);
    EXPECT_EQ(loaded.rules.size(), 1u);
}

TEST(GuardRulesYaml, EmptyOrBlankPathsThrow) {
    EXPECT_THROW(Guard::load_rules_files({}), Guard::RuleError);
    EXPECT_THROW(Guard::load_rules_files({"", "   "}), Guard::RuleError);
}

TEST(GuardRulesYaml, MissingFileThrowsParseError) {
    bool threw = false;
    try {
        Guard::load_rules_files({"/nonexistent/path/to/rules.yaml"});
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::ParseError);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRulesYaml, MalformedYamlSyntaxThrowsParseError) {
    // Invalid YAML syntax (unterminated flow sequence).
    TempYamlFile file(R"(
guardrails_regex_rules: [
  - data_type: 1
)");

    bool threw = false;
    try {
        Guard::load_rules_files({file.path()});
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::ParseError);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRulesYaml, TopLevelKeyWrongTypeThrowsParseError) {
    // `guardrails_regex_rules` present but a scalar, not a sequence -- must
    // fail loudly rather than silently loading zero rules (the worst
    // failure shape for a masking proxy: it looks like a valid, empty
    // catalog).
    TempYamlFile file(R"(
guardrails_regex_rules: "not a list"
)");

    bool threw = false;
    try {
        Guard::load_rules_files({file.path()});
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::ParseError);
    }
    EXPECT_TRUE(threw);
}

TEST(GuardRulesYaml, TopLevelKeyAsMapThrowsParseError) {
    TempYamlFile file(R"(
guardrails_regex_rules:
  not_a_sequence: true
)");

    bool threw = false;
    try {
        Guard::load_rules_files({file.path()});
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::ParseError);
    }
    EXPECT_TRUE(threw);
}

// ── DataType string parsing ──────────────────────────────────────────────

TEST(GuardRulesYaml, DataTypeFromStringParsesNamesAndNumbers) {
    EXPECT_EQ(Guard::data_type_from_string("credentials"), Guard::DataType::Credentials);
    EXPECT_EQ(Guard::data_type_from_string("CREDENTIALS"), Guard::DataType::Credentials);
    EXPECT_EQ(Guard::data_type_from_string("Credentials"), Guard::DataType::Credentials);
    EXPECT_EQ(Guard::data_type_from_string("1"), Guard::DataType::Credentials);
    EXPECT_EQ(Guard::data_type_from_string("api_keys"), Guard::DataType::ApiKeys);
    EXPECT_EQ(Guard::data_type_from_string("2"), Guard::DataType::ApiKeys);
    EXPECT_EQ(Guard::data_type_from_string("access_tokens"), Guard::DataType::AccessTokens);
    EXPECT_EQ(Guard::data_type_from_string("ip_addresses"), Guard::DataType::IpAddresses);
    EXPECT_EQ(Guard::data_type_from_string("personal_data"), Guard::DataType::PersonalData);
    EXPECT_EQ(Guard::data_type_from_string("custom"), Guard::DataType::Custom);
    EXPECT_EQ(Guard::data_type_from_string("0"), Guard::DataType::Unspecified);
    EXPECT_EQ(Guard::data_type_from_string("unspecified"), Guard::DataType::Unspecified);
}

TEST(GuardRulesYaml, DataTypeFromStringRejectsGarbage) {
    EXPECT_EQ(Guard::data_type_from_string(""), std::nullopt);
    EXPECT_EQ(Guard::data_type_from_string("not_a_data_type"), std::nullopt);
    EXPECT_EQ(Guard::data_type_from_string("7"), std::nullopt);
    EXPECT_EQ(Guard::data_type_from_string("-1"), std::nullopt);
    EXPECT_EQ(Guard::data_type_from_string("apikeys"), std::nullopt);  // missing underscore
}

TEST(GuardRulesYaml, DataTypeNameRoundTrips) {
    EXPECT_EQ(Guard::data_type_name(Guard::DataType::Credentials), "CREDENTIALS");
    EXPECT_EQ(Guard::data_type_name(Guard::DataType::ApiKeys), "API_KEYS");
    EXPECT_EQ(Guard::data_type_name(Guard::DataType::AccessTokens), "ACCESS_TOKENS");
    EXPECT_EQ(Guard::data_type_name(Guard::DataType::IpAddresses), "IP_ADDRESSES");
    EXPECT_EQ(Guard::data_type_name(Guard::DataType::PersonalData), "PERSONAL_DATA");
    EXPECT_EQ(Guard::data_type_name(Guard::DataType::Custom), "CUSTOM");
    EXPECT_EQ(Guard::data_type_name(Guard::DataType::Unspecified), "UNSPECIFIED");

    for (const auto& name : {"CREDENTIALS", "API_KEYS", "ACCESS_TOKENS", "IP_ADDRESSES", "PERSONAL_DATA", "CUSTOM"}) {
        auto parsed = Guard::data_type_from_string(name);
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(Guard::data_type_name(*parsed), name);
    }
}

// ── Real ported catalogs ──────────────────────────────────────────────────

TEST(GuardRulesYaml, LoadsPortedCatalogs) {
    auto loaded = Guard::load_rules_files(real_catalog_paths());
    EXPECT_EQ(loaded.rules.size(), 266u);  // 46 + 220
    EXPECT_GE(loaded.groups.size(), 8u);
}

TEST(GuardRulesYaml, EveryKeywordAndBanlistEntryInRealCatalogsIsAlreadyLowercase) {
    // Regression test for the ASCII-only-lowercase bug: configs/rules.yaml
    // carries Cyrillic keywords (pii.docs.inn-person/-org/-ogrn/-ogrnip use
    // "ИНН"/"ОГРН"/"ОГРНИП"). If the loader ever regresses to a byte-wise
    // lowercase, this fails because a Cyrillic entry stops being a fixed
    // point of to_lower_utf8 while still uppercase.
    auto loaded = Guard::load_rules_files(real_catalog_paths());

    std::size_t checked_keywords = 0;
    std::size_t checked_banlist = 0;
    for (const auto& rule : loaded.rules) {
        for (const auto& kw : rule.keywords) {
            EXPECT_EQ(kw, Guard::to_lower_utf8(kw)) << "rule " << rule.id << " keyword '" << kw << "' not lowercase";
            ++checked_keywords;
        }
        for (const auto& b : rule.banlist) {
            EXPECT_EQ(b, Guard::to_lower_utf8(b)) << "rule " << rule.id << " banlist entry '" << b << "' not lowercase";
            ++checked_banlist;
        }
    }
    // Sanity: make sure this test actually exercised non-trivial data,
    // including at least the four Cyrillic-keyword rules in rules.yaml.
    EXPECT_GT(checked_keywords, 0u);
    EXPECT_GT(checked_banlist, 0u);
}
