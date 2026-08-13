/**
 * @file RulesYaml.hpp
 * @brief YAML catalog loader for `Guard::Rule` / `Guard::DataTypeGroup`.
 * @details Mirrors the Go reference's loader
 *          (`pkg/guardrails/regex/rule/loader.go`, functions `LoadAll` /
 *          `LoadAllFromFiles`) field-for-field and error-for-error:
 *            - top-level YAML key `guardrails_regex_rules:`, a sequence of
 *              group entries, each carrying `rules:`.
 *            - a rule's `group` and `data_type` are NOT read from the rule
 *              itself; they are inherited from the enclosing group entry.
 *            - `keywords` and `banlist` are lower-cased at load time so
 *              matching downstream can do a plain case-sensitive compare.
 *            - loading the same file path twice is a no-op (paths are
 *              deduped before reading).
 *            - a `rule_id` seen in more than one file throws
 *              `RuleError{Code::DuplicateId}`.
 *          Unknown YAML keys are ignored (forward compatibility): every
 *          field is read by name via `node["key"]`, never by iterating the
 *          map, so an unrecognized sibling key is silently skipped. A group
 *          with no `rules:` key produces zero rules for that group, not an
 *          error.
 */

#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "guard/Errors.hpp"
#include "guard/Rule.hpp"

namespace Guard {

struct LoadedRules {
    std::vector<DataTypeGroup> groups;
    std::vector<Rule> rules;
};

namespace detail {

inline std::string rules_yaml_to_lower_(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline std::vector<std::string> rules_yaml_lower_all_(std::vector<std::string> values) {
    for (auto& v : values)
        v = rules_yaml_to_lower_(std::move(v));
    return values;
}

inline std::string rules_yaml_trim_(const std::string& s) {
    auto not_space = [](unsigned char c) { return std::isspace(c) == 0; };
    auto begin = std::find_if(s.begin(), s.end(), not_space);
    auto end = std::find_if(s.rbegin(), s.rend(), not_space).base();
    if (begin >= end)
        return "";
    return std::string(begin, end);
}

inline Rule parse_rule_(const YAML::Node& node, const std::string& path) {
    Rule r;
    try {
        if (node["rule_id"])
            r.id = node["rule_id"].as<std::string>();
        if (node["name"])
            r.name = node["name"].as<std::string>();
        if (node["regex"])
            r.regex = node["regex"].as<std::string>();
        if (node["keywords"])
            r.keywords = rules_yaml_lower_all_(node["keywords"].as<std::vector<std::string>>());
        if (node["validators"])
            r.validators = node["validators"].as<std::vector<std::string>>();
        if (node["min_length"])
            r.min_length = node["min_length"].as<std::size_t>();
        if (node["entropy"])
            r.entropy = node["entropy"].as<double>();
        if (node["banlist"])
            r.banlist = rules_yaml_lower_all_(node["banlist"].as<std::vector<std::string>>());
        // Matches the Go reference exactly: `default_on` has no YAML default
        // spelled out there either, so an omitted key decodes to the zero
        // value (false), not the struct's default-construction value (true,
        // which only applies to a Rule built outside the loader).
        r.default_on = node["default_on"] && node["default_on"].as<bool>();
        if (YAML::Node m = node["masking"]) {
            if (m["capture_groups"])
                r.masking.capture_groups = m["capture_groups"].as<std::vector<int>>();
            if (m["placeholder"])
                r.masking.placeholder = m["placeholder"].as<std::string>();
        }
    } catch (const YAML::Exception& e) {
        throw RuleError(RuleError::Code::ParseError, "parse rule in " + path + ": " + e.what());
    }
    return r;
}

}  // namespace detail

/**
 * @brief Loads groups + rules from a single YAML file. Group name/data_type
 *        are stamped onto every rule nested under it. Missing `rules:` on a
 *        group yields zero rules for that group (not an error).
 * @throws RuleError{Code::ParseError} on I/O failure or malformed YAML.
 */
inline LoadedRules load_rules_file(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception& e) {
        throw RuleError(RuleError::Code::ParseError, "read rules file " + path + ": " + e.what());
    }

    LoadedRules result;
    YAML::Node groups_node;
    try {
        groups_node = root["guardrails_regex_rules"];
    } catch (const YAML::Exception& e) {
        throw RuleError(RuleError::Code::ParseError, "parse rules YAML " + path + ": " + e.what());
    }
    if (!groups_node || !groups_node.IsSequence())
        return result;

    for (const auto& g : groups_node) {
        DataTypeGroup group{};
        try {
            group.data_type = static_cast<DataType>(g["data_type"] ? g["data_type"].as<int>() : 0);
            group.priority = g["group_priority"] ? g["group_priority"].as<int>() : 0;
            group.name = g["name"] ? g["name"].as<std::string>() : std::string{};
            group.display_name = g["display_name"] ? g["display_name"].as<std::string>() : std::string{};
            group.description = g["description"] ? g["description"].as<std::string>() : std::string{};
        } catch (const YAML::Exception& e) {
            throw RuleError(RuleError::Code::ParseError, "parse group in " + path + ": " + e.what());
        }
        result.groups.push_back(group);

        YAML::Node rules_node = g["rules"];
        if (!rules_node)
            continue;
        if (!rules_node.IsSequence()) {
            throw RuleError(RuleError::Code::ParseError,
                            "group '" + group.name + "' rules is not a sequence in " + path);
        }
        for (const auto& rn : rules_node) {
            Rule r = detail::parse_rule_(rn, path);
            r.group = group.name;
            r.data_type = group.data_type;
            result.rules.push_back(std::move(r));
        }
    }
    return result;
}

/**
 * @brief Loads and merges rules from multiple YAML files.
 * @details Blank/whitespace-only paths are skipped. Duplicate paths (after
 *          trimming) are loaded once. Mirrors
 *          `rule.LoadAllFromFiles` in the Go reference.
 * @throws RuleError{Code::ParseError} if no files were provided/loadable, or
 *         on a per-file load failure.
 * @throws RuleError{Code::DuplicateId} if a rule_id appears in more than one
 *         of the loaded files.
 */
inline LoadedRules load_rules_files(const std::vector<std::string>& paths) {
    LoadedRules all;
    std::unordered_set<std::string> seen_paths;
    std::unordered_map<std::string, std::string> seen_rule_ids;  // rule_id -> path it was first seen in
    std::size_t loaded_files = 0;

    for (const auto& raw_path : paths) {
        const std::string path = detail::rules_yaml_trim_(raw_path);
        if (path.empty())
            continue;
        if (!seen_paths.insert(path).second)
            continue;

        LoadedRules loaded = load_rules_file(path);
        ++loaded_files;

        for (auto& group : loaded.groups)
            all.groups.push_back(std::move(group));

        for (auto& r : loaded.rules) {
            auto it = seen_rule_ids.find(r.id);
            if (it != seen_rule_ids.end()) {
                throw RuleError(RuleError::Code::DuplicateId,
                                "duplicate guardrails rule_id '" + r.id + "' in files " + it->second + " and " + path);
            }
            seen_rule_ids.emplace(r.id, path);
            all.rules.push_back(std::move(r));
        }
    }

    if (loaded_files == 0) {
        throw RuleError(RuleError::Code::ParseError, "no guardrails rules files configured");
    }

    return all;
}

}  // namespace Guard
