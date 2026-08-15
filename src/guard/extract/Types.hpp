/**
 * @file Types.hpp
 * @brief Shared extraction types (`ContentField`, `Unsupported`,
 *        `ExtractResult`) used by `Extract.hpp`'s dispatch and every
 *        per-format extractor header (`ChatCompletions.hpp`, `Messages.hpp`,
 *        `Responses.hpp`).
 * @details Split out of `Extract.hpp` (Task 2.2 controller ruling) to break
 *          a real circular-include hazard: `Extract.hpp`'s dispatch needs
 *          to `#include` each per-format header so it can call into it for
 *          real (an earlier revision forward-declared the per-format
 *          functions instead of including the header, to sidestep the
 *          cycle -- but a forward-declared `inline` function that is
 *          odr-used in a translation unit which never itself includes the
 *          header containing the actual definition is ill-formed per
 *          [dcl.inline]p7 ("An inline function... shall be defined in
 *          every translation unit in which it is odr-used"), and was
 *          confirmed to produce an undefined-symbol link failure for
 *          exactly that TU shape -- a `.cpp` including only `Extract.hpp`,
 *          never `ChatCompletions.hpp`, that still calls
 *          `extract_request(body, ApiFormat::ChatCompletions)`). Each
 *          per-format header, in turn, needs `ContentField`/`Unsupported`/
 *          `ExtractResult` to write its own `ExtractResult`-returning
 *          functions. Two files both wanting to `#include` each other is
 *          exactly a cycle; the fix is the standard one -- move the
 *          shared, cycle-causing dependency (these three types) into a
 *          third file that both depend on, so the graph becomes a strict
 *          DAG: `ChatCompletions.hpp` depends only on `Types.hpp` (NOT
 *          `Extract.hpp`); `Extract.hpp` depends on both `Types.hpp` and
 *          `ChatCompletions.hpp` (a real `#include`, calling its functions
 *          directly, no forward declaration). `Messages.hpp`/
 *          `Responses.hpp` (Tasks 2.3/2.4) should follow the same shape:
 *          include `Types.hpp`, not `Extract.hpp`.
 */

#pragma once

#include <string>
#include <variant>
#include <vector>

#include "guard/json/Json.hpp"

namespace Guard::Extract {

/// A mutable text field addressed in an ORIGINAL request/response body.
struct ContentField {
    std::vector<Guard::Json::PathSeg> path;  // patchable location (re-resolve via find_value, or splice_all directly)
    Guard::Json::ValueSpan span;             // span in the ORIGINAL body bytes
    std::string text;                        // decoded string value
    bool is_raw_object{false};  // true for e.g. messages tool_use `.input` (patch the raw object, not a string)
};

/// Sentinel for "this body doesn't match the expected schema for its
/// declared format" (spec §5): callers fail open (pass the body through
/// unmodified) and bump a counter, rather than reject the request.
struct Unsupported {};

using ExtractResult = std::variant<std::vector<ContentField>, Unsupported>;

}  // namespace Guard::Extract
