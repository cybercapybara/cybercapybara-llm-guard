/**
 * @file Errors.hpp
 * @brief The single exception type thrown across the masking-engine's
 *        loader/compiler pipeline (RulesYaml.hpp, PlaceholderRegex.hpp,
 *        Registry.hpp).
 * @details One error type with a `Code` tag (rather than a hierarchy of
 *          exception classes) keeps every throw site in the pipeline
 *          catchable with a single `catch (const RuleError&)`, while still
 *          letting callers branch on `.code` when they need to (e.g. a
 *          configuration API surfacing 400 vs 422 depending on the failure
 *          kind in a later phase).
 */

#pragma once

#include <stdexcept>
#include <string>

namespace Guard {

struct RuleError : std::runtime_error {
    enum class Code {
        InvalidId,             // rule_id fails ^[a-z0-9_.-]{1,128}$
        DuplicateId,           // same rule_id loaded from two files
        UnknownValidator,      // rule.validators names something not in Validators.hpp
        BadRegex,              // RE2 failed to compile rule.regex
        BadCaptureGroup,       // capture_groups references a group the regex doesn't have
        UnboundedPlaceholder,  // placeholder pattern has no finite max length
        ParseError,            // catch-all for I/O / YAML structure failures
    };

    Code code;

    RuleError(Code c, const std::string& msg) : std::runtime_error(msg), code(c) {}
};

}  // namespace Guard
