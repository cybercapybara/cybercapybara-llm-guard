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
 *          **Depends on `Types.hpp`, not `Extract.hpp`.** `ContentField`/
 *          `Unsupported`/`ExtractResult` live in `Types.hpp` specifically so
 *          `Extract.hpp` can `#include` this file for real (calling
 *          `Messages::extract_request`/`extract_response` directly) without
 *          a circular pair -- see `Types.hpp`'s file-level doc comment and
 *          `Guard::Extract::ChatCompletions` (`ChatCompletions.hpp`, Task
 *          2.2), which established this shape first; this file follows it.
 *
 *          **Linear in document size, not quadratic in element count.**
 *          Every array this file walks (`system` block arrays, `messages`,
 *          `messages[i].content`, `tool_result` content arrays) is resolved
 *          via ONE `Guard::Json::array_elements` call -- a single forward
 *          pass over that array's bytes -- rather than per-index
 *          `find_value`/`find_value_in` probing, which re-scans an array
 *          from its own opening bracket on every single index and is
 *          quadratic in element count (measured and banned; see
 *          `ChatCompletions.hpp`'s file-level doc comment for the
 *          measurements that established this). Each element's own nested
 *          fields are then resolved via `Guard::Json::find_value_in`/
 *          `Guard::Json::string_leaves_in`, SCOPED to that element's own
 *          span, not re-walked from the document root. The whole pass
 *          costs O(document size).
 *
 *          **Empty-string filtering mirrors Go's `gjson.Result.String() !=
 *          ""` guard at every extraction site**, including
 *          `collectJSONStringLeaves` (`extract.go:99`) -- `Json::
 *          string_leaves`/`string_leaves_in` deliberately do NOT filter
 *          empty leaves themselves (see `Json.hpp`'s doc comment), so every
 *          leaf this file pulls from `string_leaves_in` is filtered here,
 *          in `detail::collect_messages_content_blocks`'s `tool_use`
 *          branch, before becoming a `ContentField`. Every OTHER text field
 *          goes through the single `detail::push_if_nonempty_string`
 *          chokepoint, which applies the same filter.
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

#include "guard/extract/Types.hpp"
#include "guard/json/Json.hpp"

namespace Guard::Extract::Messages {

namespace detail {

using Guard::Json::PathSeg;
using Guard::Json::ValueSpan;

inline PathSeg key_seg(std::string key) {
    return PathSeg{std::move(key), 0, false};
}

inline PathSeg idx_seg(std::size_t index) {
    return PathSeg{"", index, true};
}

// True iff `span` describes a JSON array value -- see `ChatCompletions.hpp`
// (`is_array_span`, same shape) for why a non-array value is treated as
// zero elements rather than gjson's one-element self-wrap.
inline bool is_array_span(std::string_view body, const ValueSpan& span) {
    return !span.is_string && span.start < span.end && body[span.start] == '[';
}

// The single choke point every plain-text extracted field passes through:
// mirrors the `Type == gjson.String && String() != ""` guard repeated at
// every text-field extraction site in extract.go / extract_response.go.
// Appends nothing for a missing field, a non-string field, or a JSON string
// that decodes to "".
inline void push_if_nonempty_string(std::string_view body,
                                    std::vector<ContentField>& out,
                                    std::vector<PathSeg> path,
                                    const std::optional<ValueSpan>& span) {
    if (!span || !span->is_string)
        return;
    std::string text = Guard::Json::decode_string(body.substr(span->start, span->end - span->start));
    if (text.empty())
        return;
    out.push_back(ContentField{std::move(path), *span, std::move(text), false});
}

// `block.Get("type").String()`, scoped to `block_span` -- the discriminator
// read at every content block (`text`/`tool_use`/`tool_result`/`thinking`/
// `redacted_thinking`/unknown). A missing or non-string `type` yields `""`,
// which -- as in the Go original -- simply never matches any of the known
// literals below, so falls through to "skip this block" without needing
// its own branch.
inline std::string block_type(std::string_view body, const ValueSpan& block_span) {
    const auto span = Guard::Json::find_value_in(body, block_span, {key_seg("type")});
    if (!span || !span->is_string)
        return {};
    return Guard::Json::decode_string(body.substr(span->start, span->end - span->start));
}

// Ports `collectTypedTextParts` (extract.go): non-empty `{type:"text",
// text}` blocks of the array at `array_span`, as `<array_path>.<i>.text`
// fields. Used for both request-side `system` block arrays and
// `tool_result` block arrays (identical shape in the Go source). `array_span`
// is walked via ONE `array_elements` call -- see the file-level doc comment.
inline void collect_typed_text_parts(std::string_view body,
                                     std::vector<ContentField>& out,
                                     const std::vector<PathSeg>& array_path,
                                     const ValueSpan& array_span) {
    const auto parts = Guard::Json::array_elements(body, array_span);
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const ValueSpan& part_span = parts[i];
        if (block_type(body, part_span) != "text")
            continue;
        std::vector<PathSeg> text_path = array_path;
        text_path.push_back(idx_seg(i));
        text_path.push_back(key_seg("text"));
        push_if_nonempty_string(body, out, text_path, Guard::Json::find_value_in(body, part_span, {key_seg("text")}));
    }
}

// Ports `collectMessagesContentBlocks` (extract.go): every scannable field
// inside one `messages[i].content` block array. `array_span` is walked via
// ONE `array_elements` call -- see the file-level doc comment.
inline void collect_messages_content_blocks(std::string_view body,
                                            std::vector<ContentField>& out,
                                            const std::vector<PathSeg>& array_path,
                                            const ValueSpan& array_span) {
    const auto blocks = Guard::Json::array_elements(body, array_span);
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const ValueSpan& block_span = blocks[i];
        std::vector<PathSeg> block_path = array_path;
        block_path.push_back(idx_seg(i));

        const std::string type = block_type(body, block_span);
        if (type == "text") {
            std::vector<PathSeg> text_path = block_path;
            text_path.push_back(key_seg("text"));
            push_if_nonempty_string(
                body, out, text_path, Guard::Json::find_value_in(body, block_span, {key_seg("text")}));
        } else if (type == "tool_use") {
            // Every string leaf of `input`, decoded and individually
            // addressed -- ports `collectJSONStringLeaves`. `string_leaves_in`
            // is scoped to `input`'s own span (found once via one
            // `find_value_in` call) rather than re-walked from the document
            // root. Empty leaves are filtered HERE (`string_leaves_in` does
            // not); see the file-level doc comment.
            const auto input_span = Guard::Json::find_value_in(body, block_span, {key_seg("input")});
            if (!input_span)
                continue;
            std::vector<PathSeg> input_path = block_path;
            input_path.push_back(key_seg("input"));
            for (auto& leaf : Guard::Json::string_leaves_in(body, *input_span, {})) {
                std::string decoded =
                    Guard::Json::decode_string(body.substr(leaf.span.start, leaf.span.end - leaf.span.start));
                if (decoded.empty())
                    continue;
                std::vector<PathSeg> leaf_path = input_path;
                leaf_path.insert(leaf_path.end(), leaf.path.begin(), leaf.path.end());
                out.push_back(ContentField{std::move(leaf_path), leaf.span, std::move(decoded), false});
            }
        } else if (type == "tool_result") {
            const auto content_span = Guard::Json::find_value_in(body, block_span, {key_seg("content")});
            if (!content_span)
                continue;
            std::vector<PathSeg> content_path = block_path;
            content_path.push_back(key_seg("content"));
            if (content_span->is_string) {
                push_if_nonempty_string(body, out, content_path, content_span);
            } else if (is_array_span(body, *content_span)) {
                collect_typed_text_parts(body, out, content_path, *content_span);
            }
        }
        // Unknown block types: nothing extracted (same as Go's switch with
        // no matching case).
    }
}

}  // namespace detail

/// Ports `ExtractRequestContent` (extract.go). See the file-level doc
/// comment for the empty-filter and linear-walk notes. Handles: top-level
/// `system` (a string, or an array of `{type:"text", text}` blocks);
/// `messages[i].content` (a string, or a block array of `text`/`tool_use`/
/// `tool_result`). Extraction order mirrors the Go function's document
/// order: `system` first (in full), then `messages` left to right. Never
/// returns `Unsupported` -- a malformed body simply yields an empty vector.
inline ExtractResult extract_request(std::string_view body) {
    using detail::idx_seg;
    using detail::key_seg;

    std::vector<ContentField> fields;

    {
        const std::vector<Guard::Json::PathSeg> sys_path{key_seg("system")};
        const auto sys_span = Guard::Json::find_value(body, sys_path);
        if (sys_span) {
            if (sys_span->is_string) {
                detail::push_if_nonempty_string(body, fields, sys_path, sys_span);
            } else if (detail::is_array_span(body, *sys_span)) {
                detail::collect_typed_text_parts(body, fields, sys_path, *sys_span);
            }
        }
    }

    const std::vector<Guard::Json::PathSeg> messages_path{key_seg("messages")};
    const auto messages_span = Guard::Json::find_value(body, messages_path);
    if (messages_span && detail::is_array_span(body, *messages_span)) {
        // ONE forward pass over `messages` -- see the file-level doc comment.
        const auto elements = Guard::Json::array_elements(body, *messages_span);
        for (std::size_t i = 0; i < elements.size(); ++i) {
            const auto content_span = Guard::Json::find_value_in(body, elements[i], {key_seg("content")});
            if (!content_span)
                continue;

            std::vector<Guard::Json::PathSeg> content_path = messages_path;
            content_path.push_back(idx_seg(i));
            content_path.push_back(key_seg("content"));

            if (content_span->is_string) {
                detail::push_if_nonempty_string(body, fields, content_path, content_span);
            } else if (detail::is_array_span(body, *content_span)) {
                detail::collect_messages_content_blocks(body, fields, content_path, *content_span);
            }
        }
    }

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
inline ExtractResult extract_response(std::string_view body) {
    using detail::idx_seg;
    using detail::key_seg;

    std::vector<ContentField> fields;

    const std::vector<Guard::Json::PathSeg> content_path{key_seg("content")};
    const auto content_span = Guard::Json::find_value(body, content_path);
    if (!content_span || !detail::is_array_span(body, *content_span))
        return fields;  // missing/non-array content: empty, not an error

    // ONE forward pass over `content` -- see the file-level doc comment.
    const auto blocks = Guard::Json::array_elements(body, *content_span);
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const Guard::Json::ValueSpan& block_span = blocks[i];
        std::vector<Guard::Json::PathSeg> block_path = content_path;
        block_path.push_back(idx_seg(i));

        const std::string type = detail::block_type(body, block_span);
        if (type == "text") {
            std::vector<Guard::Json::PathSeg> text_path = block_path;
            text_path.push_back(key_seg("text"));
            detail::push_if_nonempty_string(
                body, fields, text_path, Guard::Json::find_value_in(body, block_span, {key_seg("text")}));
        } else if (type == "thinking") {
            // `signature` is encrypted and NOT extracted -- see the
            // file-level doc comment.
            std::vector<Guard::Json::PathSeg> thinking_path = block_path;
            thinking_path.push_back(key_seg("thinking"));
            detail::push_if_nonempty_string(
                body, fields, thinking_path, Guard::Json::find_value_in(body, block_span, {key_seg("thinking")}));
        } else if (type == "tool_use") {
            const auto input_span = Guard::Json::find_value_in(body, block_span, {key_seg("input")});
            if (input_span && !input_span->is_string && input_span->start < input_span->end &&
                body[input_span->start] == '{') {
                std::string raw(body.substr(input_span->start, input_span->end - input_span->start));
                if (raw != "{}") {
                    std::vector<Guard::Json::PathSeg> input_path = block_path;
                    input_path.push_back(key_seg("input"));
                    fields.push_back(ContentField{std::move(input_path), *input_span, std::move(raw), true});
                }
            }
        }
        // "redacted_thinking" and unknown types: nothing extracted.
    }

    return fields;
}

}  // namespace Guard::Extract::Messages
