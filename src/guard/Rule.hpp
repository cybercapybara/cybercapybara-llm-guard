/**
 * @file Rule.hpp
 * @brief Detection-rule model shared by every Phase-1 masking-engine module.
 * @details A `Rule` is the in-memory shape produced by the YAML catalog
 *          loader (RulesYaml.hpp) and consumed by the RE2 compiler
 *          (Registry.hpp). It carries no compiled state (no RE2 handles) —
 *          those live in `CompiledRule` — so it stays cheap to copy and easy
 *          to round-trip through the configuration API in later phases.
 */

#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "guard/Unicode.hpp"

namespace Guard {

// User-facing toggle category. Values and names mirror the Go reference's
// proto-derived `DATA_TYPE_*` enum (data_type.pb.go / data_type_enum.go)
// with the `DATA_TYPE_` prefix dropped.
enum class DataType : int {
    Unspecified = 0,
    Credentials = 1,
    ApiKeys = 2,
    AccessTokens = 3,
    IpAddresses = 4,
    PersonalData = 5,
    Custom = 6,
};

/**
 * @brief Parses a DataType from either its numeric string ("1") or its
 *        canonical name, case-insensitive ("credentials", "API_KEYS").
 *        Returns std::nullopt for anything else, including out-of-range
 *        numbers and names without the required underscores.
 */
inline std::optional<DataType> data_type_from_string(std::string_view s) {
    if (s.empty())
        return std::nullopt;

    // Numeric form: "0".."6".
    if (std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
        int value = 0;
        for (char c : s) {
            value = value * 10 + (c - '0');
            if (value > 6)
                return std::nullopt;
        }
        return static_cast<DataType>(value);
    }

    const std::string upper = detail::ascii_to_upper(std::string(s));
    if (upper == "UNSPECIFIED")
        return DataType::Unspecified;
    if (upper == "CREDENTIALS")
        return DataType::Credentials;
    if (upper == "API_KEYS")
        return DataType::ApiKeys;
    if (upper == "ACCESS_TOKENS")
        return DataType::AccessTokens;
    if (upper == "IP_ADDRESSES")
        return DataType::IpAddresses;
    if (upper == "PERSONAL_DATA")
        return DataType::PersonalData;
    if (upper == "CUSTOM")
        return DataType::Custom;
    return std::nullopt;
}

/// Canonical upper-case, underscore-separated name, e.g. "API_KEYS".
inline std::string data_type_name(DataType t) {
    switch (t) {
        case DataType::Unspecified:
            return "UNSPECIFIED";
        case DataType::Credentials:
            return "CREDENTIALS";
        case DataType::ApiKeys:
            return "API_KEYS";
        case DataType::AccessTokens:
            return "ACCESS_TOKENS";
        case DataType::IpAddresses:
            return "IP_ADDRESSES";
        case DataType::PersonalData:
            return "PERSONAL_DATA";
        case DataType::Custom:
            return "CUSTOM";
    }
    return "UNSPECIFIED";
}

struct Masking {
    std::vector<int> capture_groups;  // 1-based; empty = full match
    std::string placeholder;          // e.g. "EMAIL"
};

struct Rule {
    std::string id;  // ^[a-z0-9_.-]{1,128}$
    std::string name;
    std::string group;  // inherited from YAML group
    DataType data_type{DataType::Unspecified};
    std::string regex;                  // RE2 source, compiled with "(?m)" prefix
    std::vector<std::string> keywords;  // lowercased at load
    std::vector<std::string> validators;
    std::size_t min_length{0};
    double entropy{0.0};
    std::vector<std::string> banlist;  // lowercased at load
    bool default_on{true};
    Masking masking;
};

struct DataTypeGroup {
    DataType data_type;
    int priority;
    std::string name, display_name, description;
};

}  // namespace Guard
