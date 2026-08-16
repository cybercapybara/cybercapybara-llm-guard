/**
 * @file test_guard_extract_cc.cpp
 * @brief Unit tests for `Guard::Extract::ChatCompletions` (`src/guard/
 *        extract/ChatCompletions.hpp` -- Task 2.2) plus a thin check that
 *        `Guard::Extract::extract_request`/`extract_response`
 *        (`src/guard/extract/Extract.hpp`) dispatch the `ChatCompletions`
 *        case into it.
 *
 * Go-table -> test mapping (read-only authority: `_reference/
 * guardrails-llm-filter/pkg/llmutils/chatcompletions/{extract,
 * extract_response}_test.go`):
 *   - `TestExtractRequestContent` (8 cases) ports 1:1 into
 *     `GuardExtractChatCompletionsRequest.*` below, same order, same
 *     bodies/expectations (its "returns nil" case becomes "returns an
 *     empty, non-Unsupported vector" -- see that test's comment for why).
 *   - `TestExtractResponseContent` (14 cases) ports 1:1 into
 *     `GuardExtractChatCompletionsResponse.*` below. This is deliberate
 *     even though `extract_response` here ports `ExtractOutputFields`, a
 *     DIFFERENT (broader) Go function than `ExtractResponseContent`: every
 *     body in that 14-case table only exercises `content`/`reasoning`/
 *     `reasoning_content`, which both Go functions handle identically
 *     (same path strings, same non-empty-string guard) -- see
 *     `ChatCompletions.hpp`'s file-level doc comment for why
 *     `ExtractOutputFields` (not `ExtractResponseContent`, which has no
 *     caller outside its own test) is the one actually ported.
 *   - `refusal`, `function_call.arguments`, and response-side
 *     `tool_calls[].function.arguments` are `ExtractOutputFields`-only
 *     fields with NO Go test coverage in this package (its own
 *     `_test.go` files never exercise them) -- `RefusalExtracted`,
 *     `FunctionCallArgumentsExtracted`, `ToolCallArgumentsExtracted`,
 *     `EmptyFunctionCallAndToolCallArgumentsSkipped`, and
 *     `AllFieldsInFixedOrderPerChoice` below are this port's own
 *     supplementary coverage, written directly against the brief/Go
 *     source rather than an existing Go test table.
 *   - The remaining tests (14 supplementary `GuardExtractChatCompletionsRequest.*`,
 *     7 supplementary `GuardExtractChatCompletionsResponse.*`, plus 3
 *     `GuardExtractChatCompletionsDispatch.*`): array/object-typed
 *     `messages`/`choices`, missing `message`, path/span round-tripping,
 *     dispatch wiring, the fixed-order pins, and probe-verified edge cases
 *     (content part missing/non-string `type`, non-string `text`, a
 *     scalar/null `messages` element, non-string `arguments`) -- likewise
 *     supplementary: edge cases implied by the contract (`Guard::Json::
 *     find_value`/`find_value_in`'s documented semantics, `ContentField`'s
 *     path+span+text contract) but not spelled out by an existing Go test.
 *
 * Empty-string policy: every Go extraction site guards with
 * `Type == gjson.String && String() != ""`; a present JSON string that
 * decodes to "" is skipped exactly like an absent field. Pinned directly
 * by `ContentEmptyStringSkipped` / `EmptyReasoningContentSkipped` /
 * `EmptyFunctionCallAndToolCallArgumentsSkipped` below, and implicitly by
 * every ported "X skipped" case from the Go tables.
 *
 * Iteration-order note: response fields are NOT walked in the document's
 * own key order -- `ExtractOutputFields` iterates a FIXED Go slice
 * (`content`, `reasoning`, `reasoning_content`, `refusal`), then
 * `function_call.arguments`, then `tool_calls[]` in array order, appended
 * in that order regardless of how the source JSON object orders its own
 * keys. `AllFieldsInFixedOrderPerChoice` pins this with a body that
 * deliberately orders its keys backwards from that fixed sequence.
 */

#include <cstddef>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "guard/ApiFormat.hpp"
#include "guard/extract/ChatCompletions.hpp"
#include "guard/extract/Extract.hpp"
#include "guard/json/Json.hpp"

namespace {

using Guard::Extract::ContentField;
using Guard::Extract::ExtractResult;
using Guard::Extract::Unsupported;
using Guard::Json::PathSeg;

// Renders a path back to a dotted string purely for readable test
// assertions/failure messages -- NOT used by the extractor itself, which
// only ever consumes/produces `std::vector<PathSeg>`.
std::string path_str(const std::vector<PathSeg>& path) {
    std::string out;
    for (const auto& seg : path) {
        if (!out.empty())
            out += '.';
        out += seg.is_index ? std::to_string(seg.index) : seg.key;
    }
    return out;
}

bool is_unsupported(const ExtractResult& r) {
    return std::holds_alternative<Unsupported>(r);
}

const std::vector<ContentField>& fields_of(const ExtractResult& r) {
    return std::get<std::vector<ContentField>>(r);
}

}  // namespace

// ── extract_request ─────────────────────────────────────────────────────

TEST(GuardExtractChatCompletionsRequest, ExtractsAllMessageRolesWithStringContent) {
    const std::string body = R"({
        "messages":[
            {"role":"system","content":"system secret"},
            {"role":"user","content":"user secret"},
            {"role":"assistant","content":"assistant secret"},
            {"role":"tool","content":"tool secret"},
            {"role":"function","content":"function secret"}
        ]
    })";

    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 5u);

    const char* expected_text[] = {
        "system secret", "user secret", "assistant secret", "tool secret", "function secret"};
    for (std::size_t i = 0; i < 5; ++i) {
        // Built with `+=`, not chained `+` (`"messages." + std::to_string(i) +
        // ".content"`): the latter is a confirmed GCC 13 `-Warray-bounds=`
        // false positive on chained SSO `std::string` concatenation at -O3
        // (same class of issue as `Guard::Json`'s documented
        // `-Wstringop-overflow` false positive), not anything about this
        // expression's actual bounds.
        std::string expected_path = "messages.";
        expected_path += std::to_string(i);
        expected_path += ".content";
        EXPECT_EQ(path_str(got[i].path), expected_path);
        EXPECT_EQ(got[i].text, expected_text[i]);
        EXPECT_FALSE(got[i].is_raw_object);
    }
}

TEST(GuardExtractChatCompletionsRequest, ExtractsTextPartsOnly) {
    const std::string body = R"({
        "messages":[
            {
                "role":"user",
                "content":[
                    {"type":"text","text":"part one"},
                    {"type":"input_image","image_url":"https://example.com/x.png"},
                    {"type":"text","text":"part two"}
                ]
            }
        ]
    })";

    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.content.0.text");
    EXPECT_EQ(got[0].text, "part one");
    EXPECT_EQ(path_str(got[1].path), "messages.0.content.2.text");
    EXPECT_EQ(got[1].text, "part two");
}

TEST(GuardExtractChatCompletionsRequest, ExtractsToolCallArguments) {
    const std::string body = R"({
        "messages":[
            {
                "role":"assistant",
                "tool_calls":[
                    {"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"/tmp/.env\"}"}},
                    {"id":"call_2","type":"function","function":{"name":"run_cmd","arguments":"{\"cmd\":\"cat ~/.npmrc\"}"}}
                ]
            }
        ]
    })";

    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.tool_calls.0.function.arguments");
    EXPECT_EQ(got[0].text, R"({"path":"/tmp/.env"})");
    EXPECT_EQ(path_str(got[1].path), "messages.0.tool_calls.1.function.arguments");
    EXPECT_EQ(got[1].text, R"({"cmd":"cat ~/.npmrc"})");
}

TEST(GuardExtractChatCompletionsRequest, ExtractsDeprecatedFunctionCallArguments) {
    const std::string body = R"({
        "messages":[
            {
                "role":"assistant",
                "function_call":{"name":"read_file","arguments":"{\"path\":\"/tmp/.env\"}"}
            }
        ]
    })";

    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.function_call.arguments");
    EXPECT_EQ(got[0].text, R"({"path":"/tmp/.env"})");
}

TEST(GuardExtractChatCompletionsRequest, PreservesRealMessageIndexes) {
    const std::string body = R"({
        "messages":[
            {"role":"user","content":null},
            {"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"/tmp/a\"}"}}]},
            {"role":"tool","content":"tool output"}
        ]
    })";

    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "messages.1.tool_calls.0.function.arguments");
    EXPECT_EQ(got[0].text, R"({"path":"/tmp/a"})");
    EXPECT_EQ(path_str(got[1].path), "messages.2.content");
    EXPECT_EQ(got[1].text, "tool output");
}

TEST(GuardExtractChatCompletionsRequest, UnsupportedSchema) {
    const std::string body = R"({"model":"gpt-4o-mini"})";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    EXPECT_TRUE(is_unsupported(result));
}

TEST(GuardExtractChatCompletionsRequest, LegacyCompletionsPromptBodyUnsupported) {
    // Legacy /v1/completions prompt-style body: no `messages` array ->
    // Unsupported{} (fail-open passthrough), mirroring
    // llmutils.ErrUnsupportedBodySchema.
    const std::string body = R"({"model":"gpt-3.5-turbo-instruct","prompt":"my email is a@b.com"})";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    EXPECT_TRUE(is_unsupported(result));
}

TEST(GuardExtractChatCompletionsRequest, NoExtractableFieldsReturnsEmpty) {
    // Go: `len(fields) == 0` returns `(nil, nil)` -- a nil slice, but NOT
    // ErrUnsupportedBodySchema, since `messages` itself is present and an
    // array. The C++ port surfaces this as an empty (not Unsupported)
    // vector -- there is no separate "nil vs empty-but-non-nil" distinction
    // to preserve on this side.
    const std::string body = R"({
        "messages":[
            {"role":"user","content":null},
            {"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":""}}]}
        ]
    })";

    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    EXPECT_TRUE(fields_of(result).empty());
}

TEST(GuardExtractChatCompletionsRequest, MessagesNotArrayIsUnsupported) {
    for (const std::string_view body :
         {R"({"messages":{}})", R"({"messages":"nope"})", R"({"messages":null})", R"({"messages":42})"}) {
        SCOPED_TRACE(body);
        const auto result = Guard::Extract::ChatCompletions::extract_request(body);
        EXPECT_TRUE(is_unsupported(result));
    }
}

TEST(GuardExtractChatCompletionsRequest, MessagesEmptyArrayReturnsEmpty) {
    const std::string body = R"({"messages":[]})";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    EXPECT_TRUE(fields_of(result).empty());
}

TEST(GuardExtractChatCompletionsRequest, ContentEmptyStringSkipped) {
    const std::string body = R"({"messages":[{"role":"user","content":""}]})";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    EXPECT_TRUE(fields_of(result).empty());
}

TEST(GuardExtractChatCompletionsRequest, ContentPartsEmptyTextSkipped) {
    const std::string body = R"({
        "messages":[
            {"role":"user","content":[{"type":"text","text":""},{"type":"text","text":"kept"}]}
        ]
    })";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.content.1.text");
    EXPECT_EQ(got[0].text, "kept");
}

TEST(GuardExtractChatCompletionsRequest, ToolCallsNotArraySkippedGracefully) {
    const std::string body = R"({"messages":[{"role":"assistant","tool_calls":"nope"}]})";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    EXPECT_TRUE(fields_of(result).empty());
}

TEST(GuardExtractChatCompletionsRequest, ToolCallsSparseEmptyArgumentsDoesNotStopLaterElements) {
    const std::string body = R"({
        "messages":[{
            "role":"assistant",
            "tool_calls":[
                {"function":{"arguments":""}},
                {"function":{"arguments":"{\"x\":1}"}}
            ]
        }]
    })";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.tool_calls.1.function.arguments");
    EXPECT_EQ(got[0].text, R"({"x":1})");
}

TEST(GuardExtractChatCompletionsRequest, PathAndSpanRoundTripToOriginalBody) {
    const std::string body =
        R"({"messages":[{"role":"assistant","tool_calls":[{"function":{"arguments":"{\"k\":\"v\"}"}}]}]})";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);

    // `path` must re-resolve (via find_value) to exactly `span`, and `span`
    // must decode to `text` -- the two ways a demasker consumer could use a
    // ContentField must agree. Deliberately re-resolved with the UNSCOPED
    // `find_value` (not `find_value_in`) here: `path` is meant to be usable
    // by a downstream demasker consumer that only has `body` and the
    // `ContentField`, not the intermediate container spans this extractor
    // used internally to compute it.
    const auto refound = Guard::Json::find_value(body, got[0].path);
    ASSERT_TRUE(refound.has_value());
    EXPECT_EQ(refound->start, got[0].span.start);
    EXPECT_EQ(refound->end, got[0].span.end);
    EXPECT_EQ(Guard::Json::decode_string(body.substr(got[0].span.start, got[0].span.end - got[0].span.start)),
              got[0].text);
}

TEST(GuardExtractChatCompletionsRequest, AllFieldsInFixedOrderPerMessage) {
    // Keys are deliberately ordered BACKWARDS from the fixed extraction
    // sequence (tool_calls, function_call, content) to pin that the
    // emission order -- content -> function_call.arguments -> tool_calls
    // (ascending) -- comes from the fixed sequence of `collect_*` calls in
    // `extract_request`, NOT from the document's own key order. Mirrors the
    // response-side `AllFieldsInFixedOrderPerChoice`.
    const std::string body = R"({
        "messages":[{
            "tool_calls":[{"function":{"arguments":"{\"tc\":1}"}}],
            "function_call":{"arguments":"{\"fc\":1}"},
            "content":"c"
        }]
    })";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.content");
    EXPECT_EQ(got[0].text, "c");
    EXPECT_EQ(path_str(got[1].path), "messages.0.function_call.arguments");
    EXPECT_EQ(got[1].text, R"({"fc":1})");
    EXPECT_EQ(path_str(got[2].path), "messages.0.tool_calls.0.function.arguments");
    EXPECT_EQ(got[2].text, R"({"tc":1})");
}

// ── extract_request: probe-verified edge cases ──────────────────────────

TEST(GuardExtractChatCompletionsRequest, ContentPartMissingTypeSkippedButWalkContinues) {
    const std::string body = R"({
        "messages":[{"role":"user","content":[{"text":"no type here"},{"type":"text","text":"kept"}]}]
    })";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.content.1.text");
    EXPECT_EQ(got[0].text, "kept");
}

TEST(GuardExtractChatCompletionsRequest, ContentPartNonStringTypeSkippedButWalkContinues) {
    const std::string body = R"({
        "messages":[{"role":"user","content":[{"type":5,"text":"skip me"},{"type":"text","text":"kept"}]}]
    })";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.content.1.text");
    EXPECT_EQ(got[0].text, "kept");
}

TEST(GuardExtractChatCompletionsRequest, ContentPartNonStringTextSkippedButWalkContinues) {
    const std::string body = R"({
        "messages":[{"role":"user","content":[{"type":"text","text":5},{"type":"text","text":"kept"}]}]
    })";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.content.1.text");
    EXPECT_EQ(got[0].text, "kept");
}

TEST(GuardExtractChatCompletionsRequest, MessagesElementScalarNullSkippedButWalkContinues) {
    const std::string body = R"({"messages":[null, {"role":"user","content":"hi"}]})";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "messages.1.content");
    EXPECT_EQ(got[0].text, "hi");
}

TEST(GuardExtractChatCompletionsRequest, NonStringFunctionCallArgumentsSkipped) {
    const std::string body = R"({"messages":[{"role":"assistant","function_call":{"arguments":123}}]})";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    EXPECT_TRUE(fields_of(result).empty());
}

TEST(GuardExtractChatCompletionsRequest, NonStringToolCallArgumentsSkippedButWalkContinues) {
    const std::string body = R"({
        "messages":[{
            "role":"assistant",
            "tool_calls":[{"function":{"arguments":123}}, {"function":{"arguments":"{\"x\":1}"}}]
        }]
    })";
    const auto result = Guard::Extract::ChatCompletions::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "messages.0.tool_calls.1.function.arguments");
    EXPECT_EQ(got[0].text, R"({"x":1})");
}

// ── extract_response ────────────────────────────────────────────────────

TEST(GuardExtractChatCompletionsResponse, ChatCompletionSingleChoice) {
    const std::string body = R"({
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello, how can I help?"},
            "finish_reason": "stop"
        }]
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.content");
    EXPECT_EQ(got[0].text, "Hello, how can I help?");
}

TEST(GuardExtractChatCompletionsResponse, ChatCompletionMultipleChoices) {
    const std::string body = R"({
        "choices": [
            {"message": {"content": "First response"}},
            {"message": {"content": "Second response"}}
        ]
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.content");
    EXPECT_EQ(got[0].text, "First response");
    EXPECT_EQ(path_str(got[1].path), "choices.1.message.content");
    EXPECT_EQ(got[1].text, "Second response");
}

TEST(GuardExtractChatCompletionsResponse, ChatCompletionNullContentSkipped) {
    const std::string body = R"({"choices": [{"message": {"role": "assistant", "content": null}}]})";
    EXPECT_TRUE(fields_of(Guard::Extract::ChatCompletions::extract_response(body)).empty());
}

TEST(GuardExtractChatCompletionsResponse, ChatCompletionEmptyContentSkipped) {
    const std::string body = R"({"choices": [{"message": {"content": ""}}]})";
    EXPECT_TRUE(fields_of(Guard::Extract::ChatCompletions::extract_response(body)).empty());
}

TEST(GuardExtractChatCompletionsResponse, ReasoningOnly) {
    const std::string body = R"({
        "choices": [{"message": {"content": null, "reasoning": "The user is asking for a password. Must refuse."}}]
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.reasoning");
    EXPECT_EQ(got[0].text, "The user is asking for a password. Must refuse.");
}

TEST(GuardExtractChatCompletionsResponse, ReasoningContentOnly) {
    const std::string body = R"({
        "choices": [{"message": {"content": null, "reasoning_content": "Let me think about this step by step..."}}]
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.reasoning_content");
    EXPECT_EQ(got[0].text, "Let me think about this step by step...");
}

TEST(GuardExtractChatCompletionsResponse, ContentAndReasoningContentBothPresent) {
    const std::string body = R"({
        "choices": [{"message": {"content": "The answer is 42.", "reasoning_content": "I calculated this by..."}}]
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.content");
    EXPECT_EQ(got[0].text, "The answer is 42.");
    EXPECT_EQ(path_str(got[1].path), "choices.0.message.reasoning_content");
    EXPECT_EQ(got[1].text, "I calculated this by...");
}

TEST(GuardExtractChatCompletionsResponse, EmptyReasoningContentSkipped) {
    const std::string body = R"({"choices": [{"message": {"content": "Hello", "reasoning_content": ""}}]})";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.content");
    EXPECT_EQ(got[0].text, "Hello");
}

TEST(GuardExtractChatCompletionsResponse, EmptyChoicesArray) {
    EXPECT_TRUE(fields_of(Guard::Extract::ChatCompletions::extract_response(R"({"choices": []})")).empty());
}

TEST(GuardExtractChatCompletionsResponse, NoChoicesField) {
    EXPECT_TRUE(
        fields_of(Guard::Extract::ChatCompletions::extract_response(R"({"id": "123", "model": "gpt-4"})")).empty());
}

TEST(GuardExtractChatCompletionsResponse, EmptyJsonObject) {
    EXPECT_TRUE(fields_of(Guard::Extract::ChatCompletions::extract_response(R"({})")).empty());
}

TEST(GuardExtractChatCompletionsResponse, RealChatCompletionsExampleFromGlm46) {
    const std::string body = R"({
        "id": "chatcmpl-18240ca2",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Я языковая модель GLM.",
                "reasoning_content": null
            },
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 14, "completion_tokens": 95}
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.content");
    EXPECT_EQ(got[0].text, "Я языковая модель GLM.");
}

TEST(GuardExtractChatCompletionsResponse, SseStyleChunkWithDeltaNotExtracted) {
    // delta.content is intentionally not extracted -- SSE chunks use a
    // separate demasking path (structural extraction is only for a full,
    // non-streamed body).
    const std::string body =
        R"({"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "1"}}]})";
    EXPECT_TRUE(fields_of(Guard::Extract::ChatCompletions::extract_response(body)).empty());
}

TEST(GuardExtractChatCompletionsResponse, UnicodeContentPreserved) {
    const std::string body = R"({"choices": [{"message": {"content": "Hello 世界 🌍"}}]})";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].text, "Hello 世界 🌍");
}

// ── extract_response: ExtractOutputFields-only fields (no Go test table) ─

TEST(GuardExtractChatCompletionsResponse, RefusalExtracted) {
    const std::string body = R"({"choices": [{"message": {"content": null, "refusal": "I can't help with that."}}]})";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.refusal");
    EXPECT_EQ(got[0].text, "I can't help with that.");
}

TEST(GuardExtractChatCompletionsResponse, FunctionCallArgumentsExtracted) {
    const std::string body = R"({
        "choices": [{"message": {"function_call": {"name": "lookup", "arguments": "{\"q\":\"x\"}"}}}]
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.function_call.arguments");
    EXPECT_EQ(got[0].text, R"({"q":"x"})");
    EXPECT_FALSE(got[0].is_raw_object);
}

TEST(GuardExtractChatCompletionsResponse, ToolCallArgumentsExtracted) {
    const std::string body = R"({
        "choices": [{"message": {"tool_calls": [
            {"function": {"arguments": "{\"a\":1}"}},
            {"function": {"arguments": "{\"b\":2}"}}
        ]}}]
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.tool_calls.0.function.arguments");
    EXPECT_EQ(got[0].text, R"({"a":1})");
    EXPECT_EQ(path_str(got[1].path), "choices.0.message.tool_calls.1.function.arguments");
    EXPECT_EQ(got[1].text, R"({"b":2})");
}

TEST(GuardExtractChatCompletionsResponse, EmptyFunctionCallAndToolCallArgumentsSkipped) {
    const std::string body = R"({
        "choices": [{"message": {
            "function_call": {"arguments": ""},
            "tool_calls": [{"function": {"arguments": ""}}]
        }}]
    })";
    EXPECT_TRUE(fields_of(Guard::Extract::ChatCompletions::extract_response(body)).empty());
}

TEST(GuardExtractChatCompletionsResponse, ChoiceMissingMessageSkippedGracefully) {
    const std::string body = R"({"choices": [{"index": 0, "finish_reason": "stop"}]})";
    EXPECT_TRUE(fields_of(Guard::Extract::ChatCompletions::extract_response(body)).empty());
}

TEST(GuardExtractChatCompletionsResponse, ChoicesNotArraySkippedGracefully) {
    // Deliberate divergence from gjson: `Result.Array()` on a non-array
    // value self-wraps it as a one-element array instead of yielding zero
    // elements (see `ChatCompletions.hpp`'s file-level doc comment) --
    // this port always treats non-array `choices` as zero elements, the
    // safer direction, and one that's practically moot for Go's behavior
    // too (a field resolved through that quirk can't be sjson-patched back
    // into a body where `choices` isn't structurally an array).
    for (const std::string_view body :
         {R"({"choices": {}})", R"({"choices": "nope"})", R"({"choices": null})", R"({"choices": 1})"}) {
        SCOPED_TRACE(body);
        EXPECT_TRUE(fields_of(Guard::Extract::ChatCompletions::extract_response(body)).empty());
    }
}

TEST(GuardExtractChatCompletionsResponse, AllFieldsInFixedOrderPerChoice) {
    // Keys are deliberately ordered BACKWARDS from the fixed extraction
    // sequence (refusal, reasoning_content, reasoning, content, then
    // tool_calls before function_call) to pin that field order comes from
    // Go's fixed `[]string{"content","reasoning","reasoning_content",
    // "refusal"}` slice plus the fixed function_call-then-tool_calls
    // sequence -- NOT from the document's own key order.
    const std::string body = R"({
        "choices": [{
            "message": {
                "tool_calls": [{"function": {"arguments": "{\"tc\":1}"}}],
                "function_call": {"arguments": "{\"fc\":1}"},
                "refusal": "r",
                "reasoning_content": "rc",
                "reasoning": "re",
                "content": "c"
            }
        }]
    })";
    const auto got = fields_of(Guard::Extract::ChatCompletions::extract_response(body));
    ASSERT_EQ(got.size(), 6u);
    EXPECT_EQ(path_str(got[0].path), "choices.0.message.content");
    EXPECT_EQ(path_str(got[1].path), "choices.0.message.reasoning");
    EXPECT_EQ(path_str(got[2].path), "choices.0.message.reasoning_content");
    EXPECT_EQ(path_str(got[3].path), "choices.0.message.refusal");
    EXPECT_EQ(path_str(got[4].path), "choices.0.message.function_call.arguments");
    EXPECT_EQ(path_str(got[5].path), "choices.0.message.tool_calls.0.function.arguments");
}

// ── Extract.hpp dispatch wiring ─────────────────────────────────────────

TEST(GuardExtractChatCompletionsDispatch, RequestRoutesToChatCompletions) {
    const std::string body = R"({"messages":[{"role":"user","content":"hi"}]})";
    const auto result = Guard::Extract::extract_request(body, Guard::ApiFormat::ChatCompletions);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].text, "hi");
}

TEST(GuardExtractChatCompletionsDispatch, ResponseRoutesToChatCompletions) {
    const std::string body = R"({"choices":[{"message":{"content":"hi"}}]})";
    const auto result = Guard::Extract::extract_response(body, Guard::ApiFormat::ChatCompletions);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].text, "hi");
}

// `OtherFormatsStillUnsupportedStubs` used to live here, asserting that a
// chat_completions-shaped body through the OTHER two formats' dispatch
// still hit the interim `Unsupported{}` stub. All three formats now have
// real dispatch (Messages: Task 2.3, `test_guard_extract_msg.cpp`'s
// `MessagesDispatch.*`; Responses: Task 2.4, `test_guard_extract_resp.cpp`'s
// `GuardExtractRespDispatch.*`) -- there is no "still a stub" left to pin.
// The one assertion that stayed true under real dispatch (a
// chat_completions-shaped body has neither "input" nor "instructions", so
// `extract_request(body, Responses)` is genuinely `Unsupported`) is exactly
// `GuardExtractRespDispatch.RequestUnsupportedPassesThrough`'s own
// assertion, byte-for-byte the same body -- so nothing was carried forward
// here rather than duplicating that coverage under a now-misleading test
// name.
