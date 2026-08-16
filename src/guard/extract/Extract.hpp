/**
 * @file Extract.hpp
 * @brief Shared extraction contract for the three per-format extractors
 *        (`ChatCompletions.hpp`, `Messages.hpp`, `Responses.hpp` -- Tasks
 *        2.2-2.4), plus `wants_stream`, which needs no per-format
 *        dispatch and is fully implemented here.
 * @details `extract_request`/`extract_response` dispatch on `Guard::
 *          ApiFormat` to the three per-format headers (`ChatCompletions.hpp`,
 *          `Messages.hpp`, `Responses.hpp` -- Tasks 2.2-2.4), each landing in
 *          its own header/translation unit so the three tasks can proceed in
 *          parallel worktrees without colliding on this file (a controller
 *          ruling for Task 2.1, made to remove a three-writer collision
 *          otherwise created by all three extractor tasks needing to add
 *          cases to the same `switch`). Tasks 2.2 (`ChatCompletions`) and
 *          2.4 (`Responses`) have landed and are wired in below via REAL
 *          `#include`s of `ChatCompletions.hpp`/`Responses.hpp` (an earlier
 *          revision of this file instead forward-declared each format's
 *          functions to dodge a circular include -- that was ill-formed:
 *          see `Types.hpp`'s file-level doc comment for why, and why
 *          `ContentField`/`Unsupported`/`ExtractResult` now live there
 *          instead of here). `Messages` remains a DISPATCH STUB returning
 *          `Unsupported{}` until Task 2.3 lands, at which point it should
 *          `#include` its own header the same way `ChatCompletions.hpp`/
 *          `Responses.hpp` are included below. Returning `Unsupported{}`
 *          for a not-yet-implemented format is not a behavior regression in
 *          the interim: `ExtractResult`'s `Unsupported` sentinel is exactly
 *          the fail-open-plus-counter signal callers already must handle
 *          for a genuinely unsupported body schema (spec §5), so a caller
 *          built against this stub sees the same "nothing to mask, but
 *          don't fail closed" behavior it would see for real unsupported
 *          input -- just for every `Messages` input, until 2.3 replaces its
 *          stub with real logic.
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

#include "guard/ApiFormat.hpp"
#include "guard/extract/ChatCompletions.hpp"
#include "guard/extract/Responses.hpp"
#include "guard/extract/Types.hpp"
#include "guard/json/Json.hpp"

namespace Guard::Extract {

/// Dispatches to the per-format extractor. `ChatCompletions` is wired to
/// `ChatCompletions::extract_request` (Task 2.2); `Responses` is wired to
/// `Responses::extract_request` (Task 2.4); `Messages` remains an
/// `Unsupported{}` stub until Task 2.3 lands -- see the file-level doc
/// comment.
inline ExtractResult extract_request(std::string_view body, Guard::ApiFormat format) {
    switch (format) {
        case Guard::ApiFormat::ChatCompletions:
            return ChatCompletions::extract_request(body);
        case Guard::ApiFormat::Responses:
            return Responses::extract_request(body);
        case Guard::ApiFormat::Messages:
            break;
    }
    return Unsupported{};
}

/// Dispatches to the per-format extractor -- see `extract_request`'s doc
/// comment. `Responses::extract_response_output_fields` is called with an
/// empty `base` path: a bare top-level response object, not one embedded in
/// an SSE `response.completed` event (that call, with a non-empty `base`,
/// is the SSE phase's own responsibility, not this generic dispatcher's).
inline ExtractResult extract_response(std::string_view body, Guard::ApiFormat format) {
    switch (format) {
        case Guard::ApiFormat::ChatCompletions:
            return ChatCompletions::extract_response(body);
        case Guard::ApiFormat::Responses:
            return Responses::extract_response_output_fields(body, {});
        case Guard::ApiFormat::Messages:
            break;
    }
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
