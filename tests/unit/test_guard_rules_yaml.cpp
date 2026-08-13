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

#include <cstdio>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include "guard/Errors.hpp"
#include "guard/Rule.hpp"
#include "guard/RulesYaml.hpp"

namespace {

// Writes `content` to `path` (relative to the test binary's cwd) and returns
// path, for callers that want a RAII-free one-liner.
std::string write_temp_yaml(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
    file.close();
    return path;
}

void remove_temp(const std::string& path) {
    std::remove(path.c_str());
}

}  // namespace

// ── Rule + group inheritance ────────────────────────────────────────────

TEST(GuardRulesYaml, GroupFieldsInheritedAndFieldsParsed) {
    const std::string yaml_text = R"(
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
        masking:
          placeholder: "IPV4"
)";
    const std::string path = write_temp_yaml("test_guard_rules_a.yaml", yaml_text);

    auto loaded = Guard::load_rules_files({path});

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
    // default_on omitted -> Go zero-value semantics: false, not the struct's
    // true default-member-initializer (that only applies to a Rule built
    // outside the loader).
    EXPECT_FALSE(r1.default_on);

    remove_temp(path);
}

TEST(GuardRulesYaml, GroupWithoutRulesKeyIsEmptyGroup) {
    const std::string yaml_text = R"(
guardrails_regex_rules:
  - data_type: 6
    group_priority: 1
    name: CUSTOM
    display_name: "Custom"
    description: "no rules key at all"
)";
    const std::string path = write_temp_yaml("test_guard_rules_empty_group.yaml", yaml_text);

    auto loaded = Guard::load_rules_files({path});

    ASSERT_EQ(loaded.groups.size(), 1u);
    EXPECT_EQ(loaded.groups[0].name, "CUSTOM");
    EXPECT_TRUE(loaded.rules.empty());

    remove_temp(path);
}

TEST(GuardRulesYaml, UnknownTopLevelAndRuleKeysAreIgnored) {
    // Forward-compat: neither an unrecognized top-level sibling key nor an
    // unrecognized rule-level key should break the load.
    const std::string yaml_text = R"(
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
)";
    const std::string path = write_temp_yaml("test_guard_rules_forward_compat.yaml", yaml_text);

    auto loaded = Guard::load_rules_files({path});

    ASSERT_EQ(loaded.rules.size(), 1u);
    EXPECT_EQ(loaded.rules[0].id, "credentials.forward_compat");

    remove_temp(path);
}

TEST(GuardRulesYaml, DataTypeOutsideNamedEnumStillLoads) {
    // The Go reference's Rule.DataType is a raw int (not a strict enum) at
    // load time -- an out-of-range value round-trips rather than erroring.
    // Guard::DataType is a C++ enum class over int, so a static_cast holds
    // the raw value the same way.
    const std::string yaml_text = R"(
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
)";
    const std::string path = write_temp_yaml("test_guard_rules_odd_datatype.yaml", yaml_text);

    auto loaded = Guard::load_rules_files({path});

    ASSERT_EQ(loaded.groups.size(), 1u);
    EXPECT_EQ(static_cast<int>(loaded.groups[0].data_type), 42);
    EXPECT_EQ(loaded.groups[0].priority, 900);
    ASSERT_EQ(loaded.rules.size(), 1u);
    EXPECT_EQ(static_cast<int>(loaded.rules[0].data_type), 42);
    EXPECT_EQ(loaded.rules[0].group, "test.group");

    remove_temp(path);
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
    const std::string f1 = write_temp_yaml("test_guard_rules_multi1.yaml", render("r1"));
    const std::string f2 = write_temp_yaml("test_guard_rules_multi2.yaml", render("r2"));

    auto loaded = Guard::load_rules_files({f1, f2});

    EXPECT_EQ(loaded.groups.size(), 2u);
    ASSERT_EQ(loaded.rules.size(), 2u);
    EXPECT_EQ(loaded.rules[0].id, "r1");
    EXPECT_EQ(loaded.rules[1].id, "r2");

    remove_temp(f1);
    remove_temp(f2);
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
    const std::string f1 = write_temp_yaml("test_guard_rules_dup1.yaml", tmpl);
    const std::string f2 = write_temp_yaml("test_guard_rules_dup2.yaml", tmpl);

    bool threw = false;
    try {
        Guard::load_rules_files({f1, f2});
    } catch (const Guard::RuleError& e) {
        threw = true;
        EXPECT_EQ(e.code, Guard::RuleError::Code::DuplicateId);
        EXPECT_NE(std::string(e.what()).find("dup"), std::string::npos);
    }
    EXPECT_TRUE(threw);

    remove_temp(f1);
    remove_temp(f2);
}

TEST(GuardRulesYaml, RepeatedPathIsLoadedOnce) {
    const std::string yaml_text = R"(
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
)";
    const std::string path = write_temp_yaml("test_guard_rules_repeat.yaml", yaml_text);

    // Same path given twice (and once with surrounding whitespace, which
    // should trim to the same path) -- loaded exactly once, not thrice.
    auto loaded = Guard::load_rules_files({path, path, "  " + path + "  "});

    EXPECT_EQ(loaded.groups.size(), 1u);
    EXPECT_EQ(loaded.rules.size(), 1u);

    remove_temp(path);
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
    auto loaded = Guard::load_rules_files({std::string(LLMGUARD_REPO_ROOT) + "/configs/rules.yaml",
                                           std::string(LLMGUARD_REPO_ROOT) + "/configs/rules.gitleaks.generated.yaml"});
    EXPECT_EQ(loaded.rules.size(), 266u);  // 46 + 220
    EXPECT_GE(loaded.groups.size(), 8u);
}
