/**
 * @file Messages.hpp
 * @brief Anthropic Messages API (`/v1/messages`) content extractor -- Task 2.3.
 * @details Ports `pkg/llmutils/messages/extract.go` (request) and
 *          `extract_response.go` (response) from the Go reference
 *          (`_reference/guardrails-llm-filter`), field for field. See each
 *          function's doc comment below for the exact Go-side behavior it
 *          mirrors.
 *
 *          **Never returns `Unsupported`** (unlike the shared
 *          `Extract::extract_request`/`extract_response` dispatch this
 *          plugs into): a malformed or schema-mismatched body simply yields
 *          an empty field list, exactly like the Go functions returning
 *          `(nil, nil)` / `nil`. This is intentional fail-open behavior,
 *          pinned by the "malformed body yields no fields" tests in
 *          `tests/unit/test_guard_extract_msg.cpp` -- a future caller must
 *          not expect `Unsupported` for a bad Messages-format body.
 *
 *          **Array bounds are discovered by probing, not by decoding a
 *          length.** `Json::find_value` addresses one value at a time (see
 *          `Json.hpp`), so `detail::for_each_element` below walks index 0,
 *          1, 2, ... via repeated `find_value` calls on the ELEMENT itself
 *          (never a sub-field of it) and stops at the first `nullopt`.
 *          Probing the element -- not e.g. `elem.content` -- matters: a
 *          message that legitimately has no `content` key must not be
 *          mistaken for "end of the messages array".
 *
 *          **Empty-string filtering mirrors Go's `gjson.Result.String() !=
 *          ""` guard at every extraction site**, including
 *          `collectJSONStringLeaves` (`extract.go:99`) -- `Json::
 *          string_leaves` deliberately does NOT filter empty leaves itself
 *          (see `Json.hpp`'s doc comment), so every leaf this file pulls
 *          from it is filtered here, in `detail::collect_messages_content_
 *          blocks`'s `tool_use` branch, before becoming a `ContentField`.
 *
 *          **Path segments need no escaping.** Go's `gjson`/`sjson` address
 *          a field via one dotted-and-escaped string, so `escapePathKey` in
 *          `extract.go` guards against object keys that themselves contain
 *          `.`/`*`/etc. `Guard::Json::PathSeg` is a pre-split segment vector
 *          instead (see `Json.hpp`'s doc comment), so that escaping step has
 *          no C++ equivalent here -- keys are carried through verbatim, byte
 *          for byte, whatever characters they contain.
 */

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "guard/json/Json.hpp"

// This header uses `Guard::Extract::ContentField`, `Guard::Extract::
// Unsupported`, and `Guard::Extract::ExtractResult`, all defined in
// `Extract.hpp`. It deliberately does NOT `#include "guard/extract/
// Extract.hpp"` itself: `Extract.hpp` defines those types, then `#include`s
// THIS file (after defining them) to wire `ApiFormat::Messages` into its
// dispatch switch. A back-`#include` here would create a circular pair
// whose correctness depends on which header is included first -- fragile to
// get right without a local build to check it against (this task is CI-only,
// no local `cmake`/`make`). One-directional inclusion sidesteps the issue
// entirely: this file is only ever included transitively via `Extract.hpp`
// (or after an explicit prior `#include "guard/extract/Extract.hpp"`), never
// standalone -- attempting the latter fails to compile with an
// incomplete-type error on `ContentField`, which is the intended signal.

namespace Guard::Extract::Messages {

namespace detail {

using Guard::Json::PathSeg;
using Guard::Json::ValueSpan;

inline PathSeg key(std::string k) {
    return PathSeg{std::move(k), 0, false};
}

inline PathSeg idx(std::size_t i) {
    return PathSeg{"", i, true};
}

inline std::vector<PathSeg> with_seg(std::vector<PathSeg> path, PathSeg seg) {
    path.push_back(std::move(seg));
    return path;
}

// Reads and decodes a string-typed field's value if present; a non-string
// span and an empty decoded string both yield `nullopt`. The single
// chokepoint mirroring Go's `Result.Type == gjson.String && Result.String()
// != ""` guard used at every text-field extraction site in extract.go /
// extract_response.go.
inline std::optional<std::pair<ValueSpan, std::string>> string_field(std::string_view body,
                                                                     const std::vector<PathSeg>& path) {
    const auto span = Guard::Json::find_value(body, path);
    if (!span || !span->is_string)
        return std::nullopt;
    std::string decoded = Guard::Json::decode_string(body.substr(span->start, span->end - span->start));
    if (decoded.empty())
        return std::nullopt;
    return std::make_pair(*span, std::move(decoded));
}

// `block.Get("type").String()` -- the discriminator read at every content
// block (`text`/`tool_use`/`tool_result`/`thinking`/`redacted_thinking`/
// unknown). A missing or non-string `type` yields `""`, which -- as in the
// Go original -- simply never matches any of the known literals below, so
// falls through to "skip this block" without needing its own branch.
inline std::string block_type(std::string_view body, const std::vector<PathSeg>& path) {
    const auto span = Guard::Json::find_value(body, with_seg(path, key("type")));
    if (!span || !span->is_string)
        return {};
    return Guard::Json::decode_string(body.substr(span->start, span->end - span->start));
}

inline bool is_array_at(std::string_view body, const ValueSpan& span) {
    return !span.is_string && span.start < body.size() && body[span.start] == '[';
}

// Probes array elements `array_path[0]`, `array_path[1]`, ... via
// `find_value` on the ELEMENT itself until the first missing index, calling
// `fn(i, elem_path)` for each found one. Yields zero calls for a
// missing/non-array `array_path` (find_value's ordinary "not found" result
// for index 0 against a non-`[`-opening value) -- callers never need to
// pre-check "is this an array" separately.
template <typename Fn>
void for_each_element(std::string_view body, const std::vector<PathSeg>& array_path, Fn&& fn) {
    for (std::size_t i = 0;; ++i) {
        std::vector<PathSeg> elem_path = with_seg(array_path, idx(i));
        if (!Guard::Json::find_value(body, elem_path))
            break;
        fn(i, elem_path);
    }
}

// Ports `collectTypedTextParts` (extract.go): non-empty `{type:"text",
// text}` blocks of the array at `array_path`, as `<array_path>.<i>.text`
// fields. Used for both request-side `system` block arrays and
// `tool_result` block arrays (identical shape in the Go source).
inline std::vector<Guard::Extract::ContentField> collect_typed_text_parts(std::string_view body,
                                                                          const std::vector<PathSeg>& array_path) {
    std::vector<Guard::Extract::ContentField> fields;
    for_each_element(body, array_path, [&](std::size_t, const std::vector<PathSeg>& elem_path) {
        if (block_type(body, elem_path) != "text")
            return;
        const auto text_path = with_seg(elem_path, key("text"));
        if (auto sf = string_field(body, text_path))
            fields.push_back(Guard::Extract::ContentField{text_path, sf->first, std::move(sf->second), false});
    });
    return fields;
}

// Ports `collectMessagesContentBlocks` (extract.go): every scannable field
// inside one `messages[i].content` block array.
inline std::vector<Guard::Extract::ContentField> collect_messages_content_blocks(
    std::string_view body, const std::vector<PathSeg>& array_path) {
    std::vector<Guard::Extract::ContentField> fields;
    for_each_element(body, array_path, [&](std::size_t, const std::vector<PathSeg>& elem_path) {
        const std::string type = block_type(body, elem_path);
        if (type == "text") {
            const auto text_path = with_seg(elem_path, key("text"));
            if (auto sf = string_field(body, text_path))
                fields.push_back(Guard::Extract::ContentField{text_path, sf->first, std::move(sf->second), false});
        } else if (type == "tool_use") {
            // Every string leaf of `input`, decoded and individually
            // addressed -- ports `collectJSONStringLeaves`. Empty leaves are
            // filtered HERE (Json::string_leaves does not); see the
            // file-level doc comment.
            const auto input_path = with_seg(elem_path, key("input"));
            for (auto& leaf : Guard::Json::string_leaves(body, input_path)) {
                std::string decoded =
                    Guard::Json::decode_string(body.substr(leaf.span.start, leaf.span.end - leaf.span.start));
                if (!decoded.empty())
                    fields.push_back(Guard::Extract::ContentField{leaf.path, leaf.span, std::move(decoded), false});
            }
        } else if (type == "tool_result") {
            const auto content_path = with_seg(elem_path, key("content"));
            const auto cspan = Guard::Json::find_value(body, content_path);
            if (!cspan)
                return;
            if (cspan->is_string) {
                if (auto sf = string_field(body, content_path))
                    fields.push_back(
                        Guard::Extract::ContentField{content_path, sf->first, std::move(sf->second), false});
            } else if (is_array_at(body, *cspan)) {
                auto parts = collect_typed_text_parts(body, content_path);
                fields.insert(
                    fields.end(), std::make_move_iterator(parts.begin()), std::make_move_iterator(parts.end()));
            }
        }
        // Unknown block types: nothing extracted (same as Go's switch with
        // no matching case).
    });
    return fields;
}

}  // namespace detail

/// Ports `ExtractRequestContent` (extract.go). See the file-level doc
/// comment for the empty-filter and array-probing notes. Handles: top-level
/// `system` (a string, or an array of `{type:"text", text}` blocks);
/// `messages[i].content` (a string, or a block array of `text`/`tool_use`/
/// `tool_result`). Extraction order mirrors the Go function's document
/// order: `system` first (in full), then `messages` left to right. Never
/// returns `Unsupported` -- a malformed body simply yields an empty vector.
inline Guard::Extract::ExtractResult extract_request(std::string_view body) {
    std::vector<Guard::Extract::ContentField> fields;

    {
        const std::vector<Guard::Json::PathSeg> sys_path = {detail::key("system")};
        if (const auto span = Guard::Json::find_value(body, sys_path)) {
            if (span->is_string) {
                if (auto sf = detail::string_field(body, sys_path))
                    fields.push_back(Guard::Extract::ContentField{sys_path, sf->first, std::move(sf->second), false});
            } else if (detail::is_array_at(body, *span)) {
                auto parts = detail::collect_typed_text_parts(body, sys_path);
                fields.insert(
                    fields.end(), std::make_move_iterator(parts.begin()), std::make_move_iterator(parts.end()));
            }
        }
    }

    detail::for_each_element(
        body, {detail::key("messages")}, [&](std::size_t, const std::vector<Guard::Json::PathSeg>& msg_path) {
            const auto content_path = detail::with_seg(msg_path, detail::key("content"));
            const auto cspan = Guard::Json::find_value(body, content_path);
            if (!cspan)
                return;
            if (cspan->is_string) {
                if (auto sf = detail::string_field(body, content_path))
                    fields.push_back(
                        Guard::Extract::ContentField{content_path, sf->first, std::move(sf->second), false});
            } else if (detail::is_array_at(body, *cspan)) {
                auto parts = detail::collect_messages_content_blocks(body, content_path);
                fields.insert(
                    fields.end(), std::make_move_iterator(parts.begin()), std::make_move_iterator(parts.end()));
            }
        });

    return fields;
}

/// Ports `ExtractResponseFields` (extract_response.go): per `content[i]`
/// block, keyed on `type`: `text` -> `.text`; `thinking` -> `.thinking` (the
/// `signature` field is encrypted and deliberately left untouched, never
/// extracted); `tool_use` -> the RAW `.input` object (`is_raw_object=true`,
/// `span` covering the whole object, `text` holding its raw bytes
/// unmodified -- patched back raw by the demasker later); a `tool_use` whose
/// `input` is exactly `{}` is skipped, matching Go's `v.Raw != "" && v.Raw
/// != "{}"` guard. `redacted_thinking` and any unknown block type are
/// skipped entirely (forward-compatible byte-identical passthrough). Never
/// returns `Unsupported` -- a malformed body simply yields an empty vector.
inline Guard::Extract::ExtractResult extract_response(std::string_view body) {
    std::vector<Guard::Extract::ContentField> fields;

    detail::for_each_element(
        body, {detail::key("content")}, [&](std::size_t, const std::vector<Guard::Json::PathSeg>& elem_path) {
            const std::string type = detail::block_type(body, elem_path);
            if (type == "text") {
                const auto text_path = detail::with_seg(elem_path, detail::key("text"));
                if (auto sf = detail::string_field(body, text_path))
                    fields.push_back(Guard::Extract::ContentField{text_path, sf->first, std::move(sf->second), false});
            } else if (type == "thinking") {
                // `signature` is encrypted and NOT extracted -- see the
                // file-level doc comment.
                const auto thinking_path = detail::with_seg(elem_path, detail::key("thinking"));
                if (auto sf = detail::string_field(body, thinking_path))
                    fields.push_back(
                        Guard::Extract::ContentField{thinking_path, sf->first, std::move(sf->second), false});
            } else if (type == "tool_use") {
                const auto input_path = detail::with_seg(elem_path, detail::key("input"));
                const auto ispan = Guard::Json::find_value(body, input_path);
                if (ispan && !ispan->is_string && ispan->start < body.size() && body[ispan->start] == '{') {
                    std::string raw(body.substr(ispan->start, ispan->end - ispan->start));
                    if (raw != "{}")
                        fields.push_back(Guard::Extract::ContentField{input_path, *ispan, std::move(raw), true});
                }
            }
            // "redacted_thinking" and unknown types: nothing extracted.
        });

    return fields;
}

}  // namespace Guard::Extract::Messages
