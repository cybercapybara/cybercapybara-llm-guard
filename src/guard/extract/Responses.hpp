/**
 * @file Responses.hpp
 * @brief OpenAI Responses API (`/v1/responses`) content extractor -- Task 2.4.
 * @details Ports `pkg/llmutils/responses/extract.go` (request side) and
 *          `extract_response.go` (response side) from the Go reference
 *          (`_reference/guardrails-llm-filter`), including their `_test.go`
 *          corpora (ported into `tests/unit/test_guard_extract_resp.cpp`).
 *
 *          **Request side** (`extract_request`, from `ExtractRequestContent`):
 *          `Unsupported{}` iff NEITHER top-level `input` NOR `instructions`
 *          is present at all (regardless of type or emptiness) -- otherwise
 *          always the vector alternative, even when it ends up empty (e.g.
 *          both present but blank, or `input` present but neither a string
 *          nor an array). Extracts, in document order: `instructions` (a
 *          non-empty string); `input` when it is a non-empty string;
 *          per `input[i]` when `input` is an array:
 *            - `function_call_output` items: `output` (string form) or
 *              `output[j].text` for `output_text`/`input_text`/`text` parts
 *              (content-array form) -- tool results often carry PII.
 *            - `function_call` items: `arguments` (a JSON string -- an
 *              assistant tool call replayed by the client in stateless
 *              multi-turn, scanned as text exactly like chat-completions'
 *              `tool_calls[].function.arguments`).
 *            - everything else (message-shaped items, `input_image`,
 *              `reasoning`, `item_reference`, ...): `content` (string form)
 *              or `content[j].text` for the same three part types
 *              (content-array form).
 *
 *          **Deliberately skipped, with NO explicit type-gating** (mirroring
 *          the Go reference exactly -- it never special-cases these either):
 *          `input_image`/`input_file` PARTS never match the
 *          `output_text`/`input_text`/`text` type check inside a content
 *          array, so they are silently skipped while surviving parts keep
 *          their REAL array index (pinned by the Go test "input_text parts
 *          mixed with input_image keep real indices" -- an `input_text` part
 *          at array index 1 produces path `...content.1.text`, not `...0`).
 *          `item_reference`/`reasoning` INPUT items are skipped because they
 *          simply have no plain `content` string/array field to match (a
 *          `reasoning` input item's payload lives under `summary`/
 *          `encrypted_content`, which this function never queries) -- not
 *          because of an explicit `if item.type == "reasoning": skip`
 *          anywhere, in either the Go or this port.
 *
 *          **Response side** (`extract_response_output_fields` /
 *          `extract_response_item_fields`, from `ExtractOutputFields` /
 *          `ExtractItemFields`): TWO entry points, mirrored as two separate
 *          functions rather than folded into one, because each has an
 *          independent caller. `extract_response_output_fields(body, base)`
 *          is the one wired into the generic `Guard::Extract::
 *          extract_response` dispatcher (`Extract.hpp`, `base = {}` for a
 *          bare top-level response object); the SSE phase (a later task)
 *          additionally calls it directly with `base =
 *          {PathSeg{"response", 0, false}}` for the response object embedded
 *          in a `response.completed` event, and calls
 *          `extract_response_item_fields` directly (one item, no enclosing
 *          `output` array) for `response.output_item.done` events. Per
 *          `output[i]` item:
 *            - `message`: `content[j].text` where `content[j].type ==
 *              "output_text"`.
 *            - `function_call`: `arguments` (a JSON string).
 *            - `reasoning`: `summary[j].text` where `summary[j].type ==
 *              "summary_text"`, AND `content[j].text` where `content[j].type
 *              == "reasoning_text"` (reasoning models can echo prompt text
 *              into their chain-of-thought -- both must be scanned).
 *              `encrypted_content` is a sibling field of `reasoning`'s
 *              `content` array and is NEVER read by any path this file
 *              builds (pinned by a dedicated test): opaque encrypted
 *              reasoning is not plain text to scan.
 *            - everything else (`web_search_call`, `computer_call`,
 *              `refusal` content parts, `annotations`, ...): untouched.
 *          Neither response function ever returns `Unsupported` -- a
 *          missing/non-array `output` just yields an empty vector, matching
 *          `ExtractOutputFields`'s Go signature (`[]ContentField`, no
 *          `error`).
 *
 *          **Why forward-declared, not `#include`d, in `Extract.hpp`:**
 *          `Guard::Extract::ContentField`/`Unsupported`/`ExtractResult` are
 *          complete types this file constructs instances of (aggregate-init,
 *          `variant` conversion), so this file must `#include
 *          "guard/extract/Extract.hpp"` for their full definitions -- a
 *          forward declaration would not do (you cannot aggregate-initialize
 *          an incomplete type). `Extract.hpp`'s dispatcher, conversely, only
 *          CALLS into this namespace's functions -- a plain forward
 *          declaration is sufficient for that, and deliberately used instead
 *          of an `#include "guard/extract/Responses.hpp"` there, because
 *          that second include direction would make the two files
 *          genuinely, unbreakably circular (each needs content from the
 *          other that is only available after the other has already
 *          finished processing), not just merely "each includes the other
 *          behind a `#pragma once` guard" (which is fine on its own, and is
 *          exactly what THIS file does with `Extract.hpp`).
 */

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "guard/ApiFormat.hpp"
#include "guard/extract/Extract.hpp"
#include "guard/json/Json.hpp"

namespace Guard::Extract::Responses {

namespace detail {

using Guard::Json::PathSeg;
using Guard::Json::ValueSpan;

inline PathSeg key(std::string k) {
    return PathSeg{std::move(k), 0, false};
}

inline PathSeg idx(std::size_t i) {
    return PathSeg{"", i, true};
}

inline std::vector<PathSeg> extend(std::vector<PathSeg> base, PathSeg seg) {
    base.push_back(std::move(seg));
    return base;
}

// True iff the value at `span` opens a JSON array -- the byte at its start
// offset is '[' for an array, vs. '{' (object), '"' (string), or a scalar's
// first byte (digit/'-'/'t'/'f'/'n') for anything else. `span` must be a
// span already resolved by `find_value` against `body`, so `span.start` is
// always a valid index into it.
inline bool is_array(std::string_view body, const ValueSpan& span) {
    return span.start < body.size() && body[span.start] == '[';
}

// The `type` string of the object at `path`, or "" if absent or not a JSON
// string -- matches gjson's `Result.Get("type").String()` for the missing/
// non-string case (empty string), which is what every per-item/per-part
// type switch in the Go reference compares against.
inline std::string type_of(std::string_view body, const std::vector<PathSeg>& path) {
    const auto span = Guard::Json::find_value(body, extend(path, key("type")));
    if (!span || !span->is_string)
        return {};
    return Guard::Json::decode_string(body.substr(span->start, span->end - span->start));
}

// Resolves `path` as a JSON string and, if it decodes to non-empty text,
// appends a ContentField for it. A no-op for a missing field, a non-string
// field, or a field that decodes to "" -- mirrors the repeated
// `X.Type == gjson.String && X.String() != ""` guard at every leaf in both
// Go files. `path` is consumed by value so it can be moved into the field.
inline void push_if_nonempty_string(std::string_view body,
                                    std::vector<PathSeg> path,
                                    std::vector<Guard::Extract::ContentField>& out) {
    const auto span = Guard::Json::find_value(body, path);
    if (!span || !span->is_string)
        return;
    std::string text = Guard::Json::decode_string(body.substr(span->start, span->end - span->start));
    if (text.empty())
        return;
    out.push_back(Guard::Extract::ContentField{std::move(path), *span, std::move(text), false});
}

// Appends one ContentField per element of the content-array at `base` whose
// `type` is `output_text`/`input_text`/`text` and whose `text` is a
// non-empty JSON string -- `collectResponsesTextParts` in extract.go. The
// loop walks every index regardless of type match, so surviving elements
// keep their real array index even when earlier/later siblings (e.g.
// `input_image`) are skipped.
inline void collect_text_parts(std::string_view body,
                               const std::vector<PathSeg>& base,
                               std::vector<Guard::Extract::ContentField>& out) {
    for (std::size_t j = 0;; ++j) {
        const auto part_path = extend(base, idx(j));
        if (!Guard::Json::find_value(body, part_path))
            break;  // index out of range: end of array
        const std::string type = type_of(body, part_path);
        if (type != "output_text" && type != "input_text" && type != "text")
            continue;
        push_if_nonempty_string(body, extend(part_path, key("text")), out);
    }
}

// One `input[i]` element -- `collectResponsesInputItemFields` in extract.go.
inline void collect_input_item_fields(std::string_view body,
                                      const std::vector<PathSeg>& item_path,
                                      std::vector<Guard::Extract::ContentField>& out) {
    const std::string type = type_of(body, item_path);

    if (type == "function_call_output") {
        const auto output_path = extend(item_path, key("output"));
        const auto output_span = Guard::Json::find_value(body, output_path);
        if (output_span && output_span->is_string)
            push_if_nonempty_string(body, output_path, out);
        else if (output_span && is_array(body, *output_span))
            collect_text_parts(body, output_path, out);
        return;
    }

    if (type == "function_call") {
        push_if_nonempty_string(body, extend(item_path, key("arguments")), out);
        return;
    }

    // Message-shaped items, and everything else: `content` simply doesn't
    // exist (or doesn't match) on item kinds with no plain-text payload
    // (`item_reference`, `reasoning`, ...), so this falls through as a
    // no-op for them exactly like the Go `default` case.
    const auto content_path = extend(item_path, key("content"));
    const auto content_span = Guard::Json::find_value(body, content_path);
    if (content_span && content_span->is_string)
        push_if_nonempty_string(body, content_path, out);
    else if (content_span && is_array(body, *content_span))
        collect_text_parts(body, content_path, out);
}

}  // namespace detail

/// Extracts scannable text fields from an OpenAI Responses API
/// (`/v1/responses`) REQUEST body -- `ExtractRequestContent` in extract.go.
/// See the file-level doc comment for the `Unsupported` gate and the
/// per-item-type extraction/skip rules.
inline Guard::Extract::ExtractResult extract_request(std::string_view body) {
    using Guard::Json::PathSeg;

    const std::vector<PathSeg> input_path{detail::key("input")};
    const std::vector<PathSeg> instructions_path{detail::key("instructions")};

    const auto input_span = Guard::Json::find_value(body, input_path);
    const auto instructions_span = Guard::Json::find_value(body, instructions_path);
    if (!input_span && !instructions_span)
        return Guard::Extract::Unsupported{};

    std::vector<Guard::Extract::ContentField> fields;

    detail::push_if_nonempty_string(body, instructions_path, fields);

    if (input_span && input_span->is_string) {
        detail::push_if_nonempty_string(body, input_path, fields);
    } else if (input_span && detail::is_array(body, *input_span)) {
        for (std::size_t i = 0;; ++i) {
            const auto item_path = detail::extend(input_path, detail::idx(i));
            if (!Guard::Json::find_value(body, item_path))
                break;  // index out of range: end of array
            detail::collect_input_item_fields(body, item_path, fields);
        }
    }

    return fields;
}

/// The demaskable text fields of a single Responses API output item, rooted
/// at `item_path` -- `ExtractItemFields` in extract_response.go. Called once
/// per `output[i]` by `extract_response_output_fields` below, and (later) by
/// the SSE `response.output_item.done` handler for a single item with no
/// enclosing `output` array. See the file-level doc comment for the
/// per-type rules; `encrypted_content` is never read (no path built here
/// ever names it).
inline std::vector<Guard::Extract::ContentField> extract_response_item_fields(
    std::string_view body, const std::vector<Guard::Json::PathSeg>& item_path) {
    using Guard::Json::PathSeg;
    std::vector<Guard::Extract::ContentField> fields;

    const std::string type = detail::type_of(body, item_path);

    if (type == "message") {
        const auto content_path = detail::extend(item_path, detail::key("content"));
        for (std::size_t j = 0;; ++j) {
            const auto part_path = detail::extend(content_path, detail::idx(j));
            if (!Guard::Json::find_value(body, part_path))
                break;
            if (detail::type_of(body, part_path) != "output_text")
                continue;
            detail::push_if_nonempty_string(body, detail::extend(part_path, detail::key("text")), fields);
        }
        return fields;
    }

    if (type == "function_call") {
        detail::push_if_nonempty_string(body, detail::extend(item_path, detail::key("arguments")), fields);
        return fields;
    }

    if (type == "reasoning") {
        // summary[].summary_text: the user-facing reasoning summary.
        const auto summary_path = detail::extend(item_path, detail::key("summary"));
        for (std::size_t j = 0;; ++j) {
            const auto part_path = detail::extend(summary_path, detail::idx(j));
            if (!Guard::Json::find_value(body, part_path))
                break;
            if (detail::type_of(body, part_path) != "summary_text")
                continue;
            detail::push_if_nonempty_string(body, detail::extend(part_path, detail::key("text")), fields);
        }
        // content[].reasoning_text: chain-of-thought text some reasoning
        // models echo prompt content into. `encrypted_content` is a sibling
        // field of this `content` array and is never itself read.
        const auto content_path = detail::extend(item_path, detail::key("content"));
        for (std::size_t j = 0;; ++j) {
            const auto part_path = detail::extend(content_path, detail::idx(j));
            if (!Guard::Json::find_value(body, part_path))
                break;
            if (detail::type_of(body, part_path) != "reasoning_text")
                continue;
            detail::push_if_nonempty_string(body, detail::extend(part_path, detail::key("text")), fields);
        }
        return fields;
    }

    // web_search_call, computer_call, refusal parts, annotations, item
    // references, ... : untouched, matching the Go `default: return nil`.
    return fields;
}

/// The demaskable text fields of a full Responses API response object,
/// rooted at `base` -- `ExtractOutputFields` in extract_response.go. Pass an
/// empty `base` for a bare top-level response body; the SSE phase passes
/// `{PathSeg{"response", 0, false}}` for the response object embedded in a
/// `response.completed` event. Never `Unsupported`: a missing or non-array
/// `output` field yields an empty vector.
inline std::vector<Guard::Extract::ContentField> extract_response_output_fields(
    std::string_view body, const std::vector<Guard::Json::PathSeg>& base) {
    const auto output_path = detail::extend(base, detail::key("output"));
    const auto output_span = Guard::Json::find_value(body, output_path);
    if (!output_span || !detail::is_array(body, *output_span))
        return {};

    std::vector<Guard::Extract::ContentField> fields;
    for (std::size_t i = 0;; ++i) {
        const auto item_path = detail::extend(output_path, detail::idx(i));
        if (!Guard::Json::find_value(body, item_path))
            break;  // index out of range: end of array
        auto item_fields = extract_response_item_fields(body, item_path);
        fields.insert(
            fields.end(), std::make_move_iterator(item_fields.begin()), std::make_move_iterator(item_fields.end()));
    }
    return fields;
}

}  // namespace Guard::Extract::Responses
