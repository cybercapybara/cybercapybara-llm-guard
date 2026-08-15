/**
 * @file ChatCompletions.hpp
 * @brief Content extractor for the OpenAI-compatible `/v1/chat/completions`
 *        wire format (`Guard::ApiFormat::ChatCompletions`) -- Task 2.2.
 * @details Ports `pkg/llmutils/chatcompletions/{extract,extract_response}.go`
 *          from the Go reference (`_reference/guardrails-llm-filter`),
 *          read-only authority for exact field semantics.
 *
 *          **Request** (`extract_request`, ports `ExtractRequestContent`):
 *          the top-level `messages` array is REQUIRED -- absent or not a
 *          JSON array returns `Unsupported{}` (mirrors
 *          `llmutils.ErrUnsupportedBodySchema`). Per `messages[i]`, in
 *          document order:
 *            1. `content` -- a JSON string (non-empty) is one field, OR a
 *               JSON array of parts, each contributing a field for
 *               `content[j].text` where `part.type == "text"` (any other
 *               `type`, including a missing one, is skipped; the array is
 *               walked in full, not stopped at the first non-text part).
 *            2. `function_call.arguments` (the deprecated single-call form).
 *            3. `tool_calls[j].function.arguments`, for every element of
 *               `tool_calls` (skipped entirely if `tool_calls` is missing or
 *               not an array; a present-but-empty `arguments` string on one
 *               element does not stop the others from being visited).
 *          The extractor is role-agnostic: every message role is scanned
 *          identically (`ExtractRequestContent`'s doc comment says so
 *          explicitly, and `TestExtractRequestContent`'s first case pins
 *          system/user/assistant/tool/function all being extracted).
 *          `messages` present, array, but zero extractable fields still
 *          returns the (empty) field list, never `Unsupported{}` -- only a
 *          missing/non-array `messages` does that.
 *
 *          **Response** (`extract_response`, ports `ExtractOutputFields`,
 *          NOT the narrower `ExtractResponseContent`): the Go reference has
 *          two response-side functions in the same file, but only
 *          `ExtractOutputFields` is reachable from production code
 *          (`internal/controller/gateway/response.go`'s `demaskFull`);
 *          `ExtractResponseContent` has no callers outside its own test and
 *          is effectively dead code. The task brief's field list --
 *          `content`, `reasoning`, `reasoning_content`, `refusal`,
 *          `function_call.arguments`, `tool_calls[j].function.arguments` --
 *          is exactly `ExtractOutputFields`'s, so that is what this ports.
 *          Per `choices[i].message`, in Go's FIXED iteration order (a
 *          literal `[]string{"content", "reasoning", "reasoning_content",
 *          "refusal"}` loop, NOT the document's own key order -- the two
 *          coincide in every test body below only by chance of how those
 *          bodies happen to be written), then `function_call.arguments`,
 *          then `tool_calls[j].function.arguments` in array order. A
 *          missing/non-array top-level `choices`, or a choice missing
 *          `message`, contributes no fields for that scope but is never an
 *          error -- `extract_response` NEVER returns `Unsupported{}` (Go's
 *          `ExtractOutputFields` has no error return at all; it degrades to
 *          an empty/nil field list for any shape it doesn't recognize,
 *          exactly like `gjson.GetBytes(body, "choices").Array()` degrading
 *          to zero iterations for a missing or non-array `choices`).
 *
 *          **Empty-string policy**: every extraction site in both Go
 *          functions guards with `Type == gjson.String && String() != ""`
 *          (the `content[j].type == "text"` comparison is the one exception
 *          -- see `collect_message_content` below -- but it reduces to
 *          the same thing in practice). A present JSON string that decodes
 *          to `""` is silently skipped, same as if the field were absent;
 *          this is mirrored exactly via `push_if_nonempty_string` below,
 *          the single choke point every field push goes through.
 *
 *          **`ContentField::is_raw_object`** stays `false` for every field
 *          this extractor produces, including the `.arguments` ones: unlike
 *          the `messages` format's `tool_use.input` (a raw JSON object),
 *          chat_completions' `function_call.arguments` /
 *          `tool_calls[].function.arguments` are JSON STRINGS holding
 *          (usually) JSON text -- gjson's `Type == gjson.String` guard on
 *          them in the Go reference confirms this -- so they are patched as
 *          strings like any other text field, not as raw objects.
 *
 *          **Paths only ever address the fields this file itself extracts.**
 *          `find_value` is called with the FULL path from the document root
 *          on every lookup (there is no cheaper "resume from here" API in
 *          `Guard::Json`), so an array is walked by probing index 0, 1, 2,
 *          ... until `find_value` reports the index out of range
 *          (`std::nullopt`) -- exactly mirroring gjson's `Array()` semantics
 *          for well-formed JSON arrays, which is the only shape every
 *          Go-reference test body ever hands this code path.
 */

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "guard/extract/Extract.hpp"
#include "guard/json/Json.hpp"

namespace Guard::Extract::ChatCompletions {

namespace detail {

using Guard::Json::PathSeg;
using Guard::Json::ValueSpan;

inline PathSeg key_seg(std::string key) {
    return PathSeg{std::move(key), 0, false};
}

inline PathSeg idx_seg(std::size_t index) {
    return PathSeg{"", index, true};
}

// True iff `span` describes a JSON array value: `find_value` already tells
// us it isn't a string (`is_string`), so the only thing left to check is
// whether its first byte opens an array rather than an object/number/
// true/false/null.
inline bool is_array_span(std::string_view body, const ValueSpan& span) {
    return !span.is_string && span.start < span.end && body[span.start] == '[';
}

// The single choke point every extracted field passes through: mirrors the
// `Type == gjson.String && String() != ""` guard repeated at every
// extraction site in the Go reference (see the file-level doc comment's
// "empty-string policy" note). Appends nothing for a missing field, a
// non-string field, or a JSON string that decodes to "".
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

// `messages[i].content`: a string field, OR an array of parts each
// contributing `content[j].text` when `part.type == "text"`. Ports
// `collectMessageContentFields`.
inline void collect_message_content(std::string_view body,
                                    std::vector<ContentField>& out,
                                    const std::vector<PathSeg>& msg_path) {
    std::vector<PathSeg> content_path = msg_path;
    content_path.push_back(key_seg("content"));
    const auto content_span = Guard::Json::find_value(body, content_path);
    if (!content_span)
        return;

    if (content_span->is_string) {
        push_if_nonempty_string(body, out, content_path, content_span);
        return;
    }

    if (!is_array_span(body, *content_span))
        return;  // object/number/bool/null content: not scannable, matches Go's `default: return nil`

    for (std::size_t j = 0;; ++j) {
        std::vector<PathSeg> part_path = content_path;
        part_path.push_back(idx_seg(j));
        const auto part_span = Guard::Json::find_value(body, part_path);
        if (!part_span)
            break;  // index out of range: end of the array

        std::vector<PathSeg> type_path = part_path;
        type_path.push_back(key_seg("type"));
        const auto type_span = Guard::Json::find_value(body, type_path);
        if (!type_span || !type_span->is_string)
            continue;  // missing/non-string `type`: Go's `part.Get("type").String()` is never "text" either
        const std::string type_val =
            Guard::Json::decode_string(body.substr(type_span->start, type_span->end - type_span->start));
        if (type_val != "text")
            continue;

        std::vector<PathSeg> text_path = part_path;
        text_path.push_back(key_seg("text"));
        push_if_nonempty_string(body, out, text_path, Guard::Json::find_value(body, text_path));
    }
}

// `messages[i].function_call.arguments`. Ports `collectFunctionCallFields`.
inline void collect_function_call(std::string_view body,
                                  std::vector<ContentField>& out,
                                  const std::vector<PathSeg>& msg_path) {
    std::vector<PathSeg> path = msg_path;
    path.push_back(key_seg("function_call"));
    path.push_back(key_seg("arguments"));
    push_if_nonempty_string(body, out, path, Guard::Json::find_value(body, path));
}

// `messages[i].tool_calls[j].function.arguments`. Ports
// `collectToolCallArgumentFields`.
inline void collect_tool_calls(std::string_view body,
                               std::vector<ContentField>& out,
                               const std::vector<PathSeg>& msg_path) {
    std::vector<PathSeg> tc_path = msg_path;
    tc_path.push_back(key_seg("tool_calls"));
    const auto tc_span = Guard::Json::find_value(body, tc_path);
    if (!tc_span || !is_array_span(body, *tc_span))
        return;  // missing/non-array tool_calls: Go's `!Exists() || !IsArray()` guard

    for (std::size_t j = 0;; ++j) {
        std::vector<PathSeg> elem_path = tc_path;
        elem_path.push_back(idx_seg(j));
        const auto elem_span = Guard::Json::find_value(body, elem_path);
        if (!elem_span)
            break;  // index out of range: end of the array

        std::vector<PathSeg> args_path = elem_path;
        args_path.push_back(key_seg("function"));
        args_path.push_back(key_seg("arguments"));
        push_if_nonempty_string(body, out, args_path, Guard::Json::find_value(body, args_path));
    }
}

// The fixed field-name order `ExtractOutputFields` iterates for
// `choices[i].message` -- a literal Go slice, NOT the document's own key
// order (see the file-level doc comment).
inline constexpr std::string_view kPlainResponseFields[] = {"content", "reasoning", "reasoning_content", "refusal"};

}  // namespace detail

/// Ports `ExtractRequestContent`. See the file-level doc comment for exact
/// semantics.
inline ExtractResult extract_request(std::string_view body) {
    using detail::idx_seg;
    using detail::key_seg;

    const std::vector<Guard::Json::PathSeg> messages_path{key_seg("messages")};
    const auto messages_span = Guard::Json::find_value(body, messages_path);
    if (!messages_span || !detail::is_array_span(body, *messages_span))
        return Unsupported{};  // absent/not-array `messages`: mirrors ErrUnsupportedBodySchema

    std::vector<ContentField> fields;
    for (std::size_t i = 0;; ++i) {
        std::vector<Guard::Json::PathSeg> msg_path = messages_path;
        msg_path.push_back(idx_seg(i));
        const auto msg_span = Guard::Json::find_value(body, msg_path);
        if (!msg_span)
            break;  // index out of range: end of the array

        detail::collect_message_content(body, fields, msg_path);
        detail::collect_function_call(body, fields, msg_path);
        detail::collect_tool_calls(body, fields, msg_path);
    }

    return fields;  // possibly empty -- `messages` present+array is enough to avoid Unsupported{}
}

/// Ports `ExtractOutputFields` (NOT `ExtractResponseContent` -- see the
/// file-level doc comment for why). Never returns `Unsupported{}`: a
/// missing/non-array `choices`, or a choice missing `message`, simply
/// contributes no fields.
inline ExtractResult extract_response(std::string_view body) {
    using detail::idx_seg;
    using detail::key_seg;

    std::vector<ContentField> fields;

    const std::vector<Guard::Json::PathSeg> choices_path{key_seg("choices")};
    const auto choices_span = Guard::Json::find_value(body, choices_path);
    if (!choices_span || !detail::is_array_span(body, *choices_span))
        return fields;  // missing/non-array choices: empty, not an error

    for (std::size_t i = 0;; ++i) {
        std::vector<Guard::Json::PathSeg> choice_path = choices_path;
        choice_path.push_back(idx_seg(i));
        const auto choice_span = Guard::Json::find_value(body, choice_path);
        if (!choice_span)
            break;  // index out of range: end of the array

        std::vector<Guard::Json::PathSeg> msg_path = choice_path;
        msg_path.push_back(key_seg("message"));

        for (const std::string_view name : detail::kPlainResponseFields) {
            std::vector<Guard::Json::PathSeg> field_path = msg_path;
            field_path.push_back(key_seg(std::string(name)));
            detail::push_if_nonempty_string(body, fields, field_path, Guard::Json::find_value(body, field_path));
        }

        std::vector<Guard::Json::PathSeg> fc_path = msg_path;
        fc_path.push_back(key_seg("function_call"));
        fc_path.push_back(key_seg("arguments"));
        detail::push_if_nonempty_string(body, fields, fc_path, Guard::Json::find_value(body, fc_path));

        detail::collect_tool_calls(body, fields, msg_path);
    }

    return fields;
}

}  // namespace Guard::Extract::ChatCompletions
