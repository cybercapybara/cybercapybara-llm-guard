/**
 * @file MaskingState.hpp
 * @brief The masking result types persisted across the request/response
 *        split: one unique original->placeholder mapping (`Replacement`) and
 *        the aggregate `MaskingState` a request's masking phase produces.
 * @details Split out of Masker.hpp per phase1-interfaces.md so the plain data
 *          shapes (round-tripped through later phases' storage/API layers)
 *          don't drag in the masking algorithm's own includes. Ports
 *          `internal/models/maskingstate.go`'s `Replacement`/`MaskingState`,
 *          with one deliberate addition: `Replacement::data_type`, which the
 *          Go struct does not carry (its JSON wire shape is `rule_id`/
 *          `original`/`placeholder` only) -- present here per
 *          phase1-interfaces.md's own `Masker.hpp` declaration block, for
 *          later phases (e.g. an audit trail) that want the data type without
 *          re-resolving it through `rule_id`.
 */

#pragma once

#include <string>
#include <vector>

#include "guard/Rule.hpp"

namespace Guard {

/// One unique original -> synthetic placeholder mapping, recorded the first
/// time a given original value is masked (subsequent occurrences of the same
/// original, anywhere across the request's texts, reuse the same placeholder
/// and do not add a second entry).
struct Replacement {
    std::string rule_id;
    DataType data_type;
    std::string original;
    std::string placeholder;  // "<TYPE_N>" format
};

/// Aggregate masking outcome for one request's texts, produced by
/// `mask_texts` and later inverted by the demasker.
struct MaskingState {
    std::vector<std::string> triggered_rule_ids;  // sorted unique
    std::vector<DataType> triggered_data_types;   // sorted unique, numeric order
    std::vector<Replacement> replacements;        // first-encounter order
    std::string format;                           // set by the caller (gateway), not this module
};

}  // namespace Guard
