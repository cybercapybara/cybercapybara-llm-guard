/**
 * @file Extract.hpp
 * @brief Shared extraction contract for the three per-format extractors
 *        (`ChatCompletions.hpp`, `Messages.hpp`, `Responses.hpp` -- Tasks
 *        2.2-2.4), plus `wants_stream`, which needs no per-format
 *        dispatch and is fully implemented here.
 * @details `extract_request`/`extract_response` are declared here as
 *          DISPATCH STUBS ONLY: both unconditionally return `Unsupported{}`
 *          for every `Guard::ApiFormat`. The real per-format bodies land in
 *          Tasks 2.2 (chat_completions), 2.3 (messages), 2.4 (responses),
 *          each in their own header/translation unit so the three tasks
 *          can proceed in parallel worktrees without colliding on this
 *          file (a controller ruling for Task 2.1, made to remove a
 *          three-writer collision otherwise created by all three extractor
 *          tasks needing to add cases to the same `switch`). Returning
 *          `Unsupported{}` here is not a behavior regression in the
 *          interim: `ExtractResult`'s `Unsupported` sentinel is exactly
 *          the fail-open-plus-counter signal callers already must handle
 *          for a genuinely unsupported body schema (spec §5), so a caller
 *          built against this stub sees the same "nothing to mask, but
 *          don't fail closed" behavior it would see for real unsupported
 *          input -- just for every input, until 2.2-2.4 replace this
 *          dispatch with real per-format logic (almost certainly via
 *          `ApiFormat`-keyed calls out to the three per-format headers,
 *          included here once they exist).
 *
 *          `wants_stream` reads the Go reference's `internal/controller/
 *          gateway/gateway.go`: `gjson.GetBytes(body, "stream").Bool()`,
 *          checked once against the top-level "stream" field, the SAME
 *          field name across all three wire formats (spec §5's closing
 *          line) -- so, unlike `extract_request`/`extract_response`, this
 *          needs no per-format branching and is safe to implement in full
 *          now via `Json::find_value`. gjson's `Result.Bool()` does loose
 *          type coercion rather than requiring a strict JSON boolean
 *          (read directly from gjson's source, `gjson.go`'s `func (t
 *          Result) Bool() bool`, not assumed): `true`/`false` map
 *          directly; a JSON string is parsed via `strconv.ParseBool` on
 *          its lowercased content (so `"true"`, `"TRUE"`, `"t"`, `"1"` are
 *          truthy and `"false"`, `"f"`, `"0"` -- and anything
 *          `ParseBool` rejects -- are not); a JSON number is truthy iff
 *          nonzero; `null`, an object, an array, or a missing field are
 *          all falsy. This mirrors that exactly rather than requiring a
 *          strict `stream: true` boolean, since real upstream traffic is
 *          not guaranteed to send a strict bool and the gateway's
 *          streaming-detection contract (spec §5, §6) inherits gjson's
 *          looseness by construction.
 */

#pragma once

#include <cctype>
#include <cstdlib>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "guard/ApiFormat.hpp"
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

// Dispatch stubs -- see the file-level doc comment. Every format currently
// reports Unsupported; Tasks 2.2-2.4 replace this body with a switch over
// `format` that calls into their own per-format header.
inline ExtractResult extract_request(std::string_view body, Guard::ApiFormat format) {
    (void)body;
    (void)format;
    return Unsupported{};
}

inline ExtractResult extract_response(std::string_view body, Guard::ApiFormat format) {
    (void)body;
    (void)format;
    return Unsupported{};
}

namespace detail {

inline char ascii_lower(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

}  // namespace detail

/// Top-level `"stream"` field, loosely coerced to bool exactly like
/// gjson's `Result.Bool()` -- see the file-level doc comment.
inline bool wants_stream(std::string_view body) {
    const auto span = Guard::Json::find_value(body, {Guard::Json::PathSeg{"stream", 0, false}});
    if (!span)
        return false;
    const std::string_view raw = body.substr(span->start, span->end - span->start);
    if (raw.empty())
        return false;

    if (raw == "true")
        return true;
    if (raw == "false")
        return false;

    if (raw.front() == '"') {
        // JSON string: strconv.ParseBool(strings.ToLower(s)) semantics --
        // "1"/"t"/"true" (any case, already lowercased here) are truthy;
        // everything else (including "0"/"f"/"false" and non-bool text) is
        // not.
        std::string s = Guard::Json::decode_string(raw);
        for (char& c : s)
            c = detail::ascii_lower(c);
        return s == "1" || s == "t" || s == "true";
    }

    if (raw.front() == '-' || (raw.front() >= '0' && raw.front() <= '9')) {
        // JSON number: nonzero is truthy, matching gjson's `t.Num != 0`.
        const std::string s(raw);
        return std::strtod(s.c_str(), nullptr) != 0.0;
    }

    // null / object / array: falsy, matching gjson's default case.
    return false;
}

}  // namespace Guard::Extract
