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
 *          nor an array). Extracts, in this FIXED emission order (NOT the
 *          document's own key order -- coincides with it below only because
 *          `instructions` is written before `input` in every example body):
 *          `instructions` (a non-empty string); `input` when it is a
 *          non-empty string; per `input[i]` when `input` is an array:
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
 *          **Depends on `Types.hpp`, NOT `Extract.hpp`** (Task 2.2's
 *          controller ruling, adopted here on merge): `ContentField`/
 *          `Unsupported`/`ExtractResult` moved out of `Extract.hpp` into
 *          `Types.hpp` specifically so per-format headers like this one
 *          could depend on the shared types WITHOUT depending on
 *          `Extract.hpp` itself, breaking what used to be a genuine
 *          circular #include (`Extract.hpp`'s dispatcher needs a REAL
 *          `#include` of this file to call its functions -- a forward
 *          declaration alone is ill-formed for an `inline` function per
 *          [dcl.inline]p7 when some translation unit calls it without ever
 *          including this file's actual definition -- and this file needs
 *          `Extract.hpp`'s types). See `Types.hpp`'s file-level doc comment
 *          for the full history.
 *
 *          **Linear in document size, not quadratic in element count** --
 *          same fix `ChatCompletions.hpp` (Task 2.2) applied, adopted here
 *          on merge. Every array this file walks (`input`, a content-part
 *          array, `output`, `summary`) is resolved via ONE
 *          `Guard::Json::array_elements` call -- a single forward pass
 *          returning every element's span, O(array size) total -- instead
 *          of probing `find_value`/`find_value_in` per index, which
 *          re-scans the array from its own opening bracket on every call
 *          and costs O(element count * array size) overall. Each element's
 *          own nested fields are then resolved via `Guard::Json::
 *          find_value_in`, scoped to that element's span, never the full
 *          document -- so the whole pass costs O(document size), not
 *          O(element count * document size) or O(element count * array
 *          size). This changes nothing observable: every `ContentField`'s
 *          `path`/`span`/`text` is identical to an unscoped, per-index
 *          `find_value`-based implementation; only the walk's own cost
 *          changed. `extract_response_output_fields` additionally resolves
 *          each `output[i]` element's span ONCE (via `array_elements`) and
 *          passes it straight into the same internal helper
 *          `extract_response_item_fields` uses, rather than re-resolving it
 *          via a second `find_value` call keyed by the constructed
 *          `output.N` path -- the public `extract_response_item_fields`
 *          entry point (for a caller that only has a path, e.g. the SSE
 *          `response.output_item.done` handler) still does exactly one
 *          `find_value` to locate its single item, since it has no
 *          already-resolved span to reuse.
 */

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "guard/extract/Types.hpp"
#include "guard/json/Json.hpp"

namespace Guard::Extract::Responses {

namespace detail {

using Guard::Json::PathSeg;
using Guard::Json::ValueSpan;

inline PathSeg key_seg(std::string key) {
    return PathSeg{std::move(key), 0, false};
}

inline PathSeg idx_seg(std::size_t index) {
    return PathSeg{"", index, true};
}

inline std::vector<PathSeg> extend(std::vector<PathSeg> base, PathSeg seg) {
    base.push_back(std::move(seg));
    return base;
}

// True iff `span` describes a JSON array value -- see `ChatCompletions.hpp`'s
// identically-named/-shaped helper for why a non-array value is treated as
// zero elements (this file's `array_elements` calls already degrade safely
// on their own, but an explicit check here keeps the shape of every call
// site consistent with that file's canonical pattern).
inline bool is_array_span(std::string_view body, const ValueSpan& span) {
    return !span.is_string && span.start < span.end && body[span.start] == '[';
}

// The `type` string of the value at `container`'s own `"type"` field -- or
// "" if absent or not a JSON string. Matches gjson's `Result.Get("type").
// String()` for the missing/non-string case (empty string), which is what
// every per-item/per-part type switch in the Go reference compares against.
inline std::string type_of(std::string_view body, const ValueSpan& container) {
    const auto span = Guard::Json::find_value_in(body, container, {key_seg("type")});
    if (!span || !span->is_string)
        return {};
    return Guard::Json::decode_string(body.substr(span->start, span->end - span->start));
}

// The single choke point every extracted field passes through: mirrors the
// repeated `X.Type == gjson.String && X.String() != ""` guard at every
// extraction site in both Go files. A no-op for a missing field, a
// non-string field, or a field that decodes to "".
inline void push_if_nonempty_string(std::string_view body, std::vector<ContentField>& out, std::vector<PathSeg> path,
                                    const std::optional<ValueSpan>& span) {
    if (!span || !span->is_string)
        return;
    std::string text = Guard::Json::decode_string(body.substr(span->start, span->end - span->start));
    if (text.empty())
        return;
    out.push_back(ContentField{std::move(path), *span, std::move(text), false});
}

// Appends one ContentField per element of the content-array at
// `array_span` (rooted at `base_path`) whose `type` is
// `output_text`/`input_text`/`text` and whose `text` is a non-empty JSON
// string -- `collectResponsesTextParts` in extract.go. Resolves every
// element via ONE `array_elements` call (see the file-level doc comment's
// linear-time note), so surviving elements keep their real array index
// even when earlier/later siblings (e.g. `input_image`) are skipped.
inline void collect_text_parts(std::string_view body, std::vector<ContentField>& out,
                               const std::vector<PathSeg>& base_path, const ValueSpan& array_span) {
    const auto parts = Guard::Json::array_elements(body, array_span);
    for (std::size_t j = 0; j < parts.size(); ++j) {
        const ValueSpan& part_span = parts[j];
        const std::string type = type_of(body, part_span);
        if (type != "output_text" && type != "input_text" && type != "text")
            continue;
        std::vector<PathSeg> text_path = extend(base_path, idx_seg(j));
        text_path.push_back(key_seg("text"));
        push_if_nonempty_string(body, out, text_path, Guard::Json::find_value_in(body, part_span, {key_seg("text")}));
    }
}

// One `input[i]` element, already resolved to `item_span` -- ports
// `collectResponsesInputItemFields`.
inline void collect_input_item_fields(std::string_view body, std::vector<ContentField>& out,
                                      const std::vector<PathSeg>& item_path, const ValueSpan& item_span) {
    const std::string type = type_of(body, item_span);

    if (type == "function_call_output") {
        const auto output_span = Guard::Json::find_value_in(body, item_span, {key_seg("output")});
        std::vector<PathSeg> output_path = extend(item_path, key_seg("output"));
        if (output_span && output_span->is_string)
            push_if_nonempty_string(body, out, output_path, output_span);
        else if (output_span && is_array_span(body, *output_span))
            collect_text_parts(body, out, output_path, *output_span);
        return;
    }

    if (type == "function_call") {
        push_if_nonempty_string(body, out, extend(item_path, key_seg("arguments")),
                                Guard::Json::find_value_in(body, item_span, {key_seg("arguments")}));
        return;
    }

    // Message-shaped items, and everything else: `content` simply doesn't
    // exist (or doesn't match) on item kinds with no plain-text payload
    // (`item_reference`, `reasoning`, ...), so this falls through as a
    // no-op for them exactly like the Go `default` case.
    const auto content_span = Guard::Json::find_value_in(body, item_span, {key_seg("content")});
    std::vector<PathSeg> content_path = extend(item_path, key_seg("content"));
    if (content_span && content_span->is_string)
        push_if_nonempty_string(body, out, content_path, content_span);
    else if (content_span && is_array_span(body, *content_span))
        collect_text_parts(body, out, content_path, *content_span);
}

// Appends one ContentField per element of `array_span` (rooted at
// `base_path`) whose `type` equals `allowed_type` and whose `text` is a
// non-empty JSON string -- shared by `reasoning`'s `summary`
// (`summary_text`) and `content` (`reasoning_text`) arrays below, each with
// a single allowed part type (unlike the request side's three-type
// `collect_text_parts`).
inline void collect_typed_text_parts(std::string_view body, std::vector<ContentField>& out,
                                     const std::vector<PathSeg>& base_path, const ValueSpan& array_span,
                                     std::string_view allowed_type) {
    const auto parts = Guard::Json::array_elements(body, array_span);
    for (std::size_t j = 0; j < parts.size(); ++j) {
        const ValueSpan& part_span = parts[j];
        if (type_of(body, part_span) != allowed_type)
            continue;
        std::vector<PathSeg> text_path = extend(base_path, idx_seg(j));
        text_path.push_back(key_seg("text"));
        push_if_nonempty_string(body, out, text_path, Guard::Json::find_value_in(body, part_span, {key_seg("text")}));
    }
}

// One Responses API output item, already resolved to `item_span` -- ports
// `ExtractItemFields`. Shared by both public entry points below:
// `extract_response_output_fields` calls this directly with each
// `array_elements`-resolved `output[i]` span (no re-lookup); the public
// `extract_response_item_fields` resolves its single item via `find_value`
// first, then delegates here.
inline void collect_item_fields(std::string_view body, std::vector<ContentField>& out,
                                const std::vector<PathSeg>& item_path, const ValueSpan& item_span) {
    const std::string type = type_of(body, item_span);

    if (type == "message") {
        const auto content_span = Guard::Json::find_value_in(body, item_span, {key_seg("content")});
        if (content_span && is_array_span(body, *content_span))
            collect_typed_text_parts(body, out, extend(item_path, key_seg("content")), *content_span, "output_text");
        return;
    }

    if (type == "function_call") {
        push_if_nonempty_string(body, out, extend(item_path, key_seg("arguments")),
                                Guard::Json::find_value_in(body, item_span, {key_seg("arguments")}));
        return;
    }

    if (type == "reasoning") {
        // summary[].summary_text: the user-facing reasoning summary.
        const auto summary_span = Guard::Json::find_value_in(body, item_span, {key_seg("summary")});
        if (summary_span && is_array_span(body, *summary_span))
            collect_typed_text_parts(body, out, extend(item_path, key_seg("summary")), *summary_span, "summary_text");

        // content[].reasoning_text: chain-of-thought text some reasoning
        // models echo prompt content into. `encrypted_content` is a sibling
        // field of this `content` array and is never itself read.
        const auto content_span = Guard::Json::find_value_in(body, item_span, {key_seg("content")});
        if (content_span && is_array_span(body, *content_span))
            collect_typed_text_parts(body, out, extend(item_path, key_seg("content")), *content_span,
                                     "reasoning_text");
        return;
    }

    // web_search_call, computer_call, refusal parts, annotations, item
    // references, ... : untouched, matching the Go `default: return nil`.
}

}  // namespace detail

/// Extracts scannable text fields from an OpenAI Responses API
/// (`/v1/responses`) REQUEST body -- `ExtractRequestContent` in extract.go.
/// See the file-level doc comment for the `Unsupported` gate and the
/// per-item-type extraction/skip rules.
inline ExtractResult extract_request(std::string_view body) {
    using detail::key_seg;

    const std::vector<Guard::Json::PathSeg> input_path{key_seg("input")};
    const std::vector<Guard::Json::PathSeg> instructions_path{key_seg("instructions")};

    const auto input_span = Guard::Json::find_value(body, input_path);
    const auto instructions_span = Guard::Json::find_value(body, instructions_path);
    if (!input_span && !instructions_span)
        return Unsupported{};

    std::vector<ContentField> fields;

    detail::push_if_nonempty_string(body, fields, instructions_path, instructions_span);

    if (input_span && input_span->is_string) {
        detail::push_if_nonempty_string(body, fields, input_path, input_span);
    } else if (input_span && detail::is_array_span(body, *input_span)) {
        // ONE forward pass over `input` (see the file-level doc comment) --
        // NOT per-index `find_value`/`find_value_in` probing.
        const auto elements = Guard::Json::array_elements(body, *input_span);
        for (std::size_t i = 0; i < elements.size(); ++i) {
            std::vector<Guard::Json::PathSeg> item_path = detail::extend(input_path, detail::idx_seg(i));
            detail::collect_input_item_fields(body, fields, item_path, elements[i]);
        }
    }

    return fields;
}

/// The demaskable text fields of a single Responses API output item, rooted
/// at `item_path` -- `ExtractItemFields` in extract_response.go. Called
/// directly by the SSE `response.output_item.done` handler (a later task)
/// for a single item with no enclosing `output` array; internally resolves
/// `item_path` via one `find_value` call, then delegates to
/// `detail::collect_item_fields`. See the file-level doc comment for the
/// per-type rules; `encrypted_content` is never read (no path built here
/// ever names it).
inline std::vector<ContentField> extract_response_item_fields(std::string_view body,
                                                               const std::vector<Guard::Json::PathSeg>& item_path) {
    std::vector<ContentField> fields;
    const auto item_span = Guard::Json::find_value(body, item_path);
    if (item_span)
        detail::collect_item_fields(body, fields, item_path, *item_span);
    return fields;
}

/// The demaskable text fields of a full Responses API response object,
/// rooted at `base` -- `ExtractOutputFields` in extract_response.go. Pass an
/// empty `base` for a bare top-level response body; the SSE phase passes
/// `{PathSeg{"response", 0, false}}` for the response object embedded in a
/// `response.completed` event. Never `Unsupported`: a missing or non-array
/// `output` field yields an empty vector. Resolves `output`'s elements via
/// ONE `array_elements` call and passes each element's span straight into
/// `detail::collect_item_fields` -- see the file-level doc comment's
/// linear-time note for why this does NOT call the public
/// `extract_response_item_fields` per element (that would re-resolve each
/// item's span via a second `find_value` call from the document root).
inline std::vector<ContentField> extract_response_output_fields(std::string_view body,
                                                                 const std::vector<Guard::Json::PathSeg>& base) {
    const auto output_path = detail::extend(base, detail::key_seg("output"));
    const auto output_span = Guard::Json::find_value(body, output_path);
    if (!output_span || !detail::is_array_span(body, *output_span))
        return {};

    std::vector<ContentField> fields;
    const auto elements = Guard::Json::array_elements(body, *output_span);
    for (std::size_t i = 0; i < elements.size(); ++i) {
        std::vector<Guard::Json::PathSeg> item_path = detail::extend(output_path, detail::idx_seg(i));
        detail::collect_item_fields(body, fields, item_path, elements[i]);
    }
    return fields;
}

}  // namespace Guard::Extract::Responses
