/**
 * @file test_guard_extract_resp.cpp
 * @brief Unit tests for `Guard::Extract::Responses` (`src/guard/extract/
 *        Responses.hpp` -- Task 2.4) plus a thin check that
 *        `Guard::Extract::extract_request`/`extract_response`
 *        (`src/guard/extract/Extract.hpp`) dispatch the `Responses` case
 *        into it. Mirrors `test_guard_extract_cc.cpp`'s structure/helpers
 *        (`path_str`/`is_unsupported`/`fields_of`, `GuardExtractResp*`
 *        suite naming) for consistency across the per-format test files.
 *
 * Test groups, each porting the corresponding Go reference corpus from
 * `_reference/guardrails-llm-filter/pkg/llmutils/responses/{extract,
 * extract_response}_test.go`, plus this port's own supplementary coverage
 * (probe-verified edge cases implied by the contract but not spelled out by
 * an existing Go test -- same category `test_guard_extract_cc.cpp` uses):
 *   - `GuardExtractRespRequest.*`: `TestExtractRequestContent` (every table
 *     case) + `TestExtractRequestContentPathsPatchable` (ported as a direct
 *     `Json::splice_all` round-trip -- this port's paths are already
 *     pre-split `PathSeg` vectors, so there is no sjson dotted-path string
 *     to round-trip through; the span-splice equivalent pins the same
 *     guarantee). Supplementary: an `item_reference`/`input_file` skip case
 *     with real-index preservation, present-but-wrong-type gates
 *     (`{"input":123}`/`null`/`true`/`{}`), an escaped+multibyte-unicode
 *     case, an iteration-robustness regression (null/scalar `input`
 *     elements between real items -- pins that `array_elements`-based
 *     iteration visits every element rather than stopping at the first
 *     non-object one), and one large mixed-type `input` array exercising
 *     every branch of the item-type dispatch in a single body.
 *   - `GuardExtractRespResponse.*`: `TestExtractOutputFields`,
 *     `TestExtractOutputFieldsWithBasePath`, `TestExtractOutputFieldsNoOutput`,
 *     `TestExtractItemFields`, `TestExtractResponsesReasoningContent`. Go's
 *     `ExtractItemFields` takes an already-parsed `gjson.Result` plus an
 *     arbitrary reporting-path string, decoupled from how that Result was
 *     located in its source document. This port's
 *     `extract_response_item_fields` is byte-surgical (`Json::find_value`-
 *     based, per Task 2.1's design): `item_path` must be a REAL path into
 *     `body`, not an arbitrary label. The two `ExtractItemFields` tests
 *     therefore wrap the Go fixture's bare item literal under a real
 *     `{"item": ...}` key so `item_path = {PathSeg{"item",...}}` is an
 *     actual, resolvable path -- the expected output paths/values are
 *     otherwise identical to the Go corpus. Supplementary: a span
 *     splice-round-trip test over `extract_response_output_fields` with a
 *     non-empty `base` (the SSE `response.completed`-embedded shape),
 *     verifying every masked placeholder lands strictly inside the
 *     embedded response object and the patched document stays valid JSON.
 *   - `GuardExtractRespDispatch.*`: confirms `Guard::Extract::
 *     extract_request`/`extract_response` (the generic, format-keyed
 *     dispatcher in `Extract.hpp`) route `Guard::ApiFormat::Responses` to
 *     this file's functions with identical results.
 */

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "guard/ApiFormat.hpp"
#include "guard/extract/Extract.hpp"
#include "guard/extract/Responses.hpp"
#include "guard/json/Json.hpp"

namespace {

using Guard::Extract::ContentField;
using Guard::Extract::ExtractResult;
using Guard::Extract::Unsupported;
using Guard::Json::PathSeg;
using Guard::Json::ValueSpan;

PathSeg key(std::string k) {
    return PathSeg{std::move(k), 0, false};
}

PathSeg idx(std::size_t i) {
    return PathSeg{"", i, true};
}

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

const char* const kResponsesBody = R"({
    "id": "resp_1",
    "status": "completed",
    "output": [
        {"type": "reasoning", "summary": [{"type": "summary_text", "text": "thinking about <EMAIL_1>"}]},
        {"type": "message", "role": "assistant", "content": [
            {"type": "output_text", "text": "hello <EMAIL_1>", "annotations": []},
            {"type": "refusal", "refusal": "no"}
        ]},
        {"type": "function_call", "call_id": "c1", "name": "send", "arguments": "{\"to\":\"<EMAIL_1>\"}"},
        {"type": "web_search_call", "status": "completed"}
    ]
})";

}  // namespace

// ── extract_request ─────────────────────────────────────────────────────

TEST(GuardExtractRespRequest, InputString) {
    const std::string body = R"({"model":"gpt-x","input":"my mail is user@example.com"})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "input");
    EXPECT_EQ(got[0].text, "my mail is user@example.com");
}

TEST(GuardExtractRespRequest, InstructionsOnly) {
    const std::string body = R"({"model":"gpt-x","instructions":"act as user@example.com"})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "instructions");
    EXPECT_EQ(got[0].text, "act as user@example.com");
}

TEST(GuardExtractRespRequest, InstructionsAndInputString) {
    const std::string body = R"({"instructions":"be helpful","input":"hello"})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "instructions");
    EXPECT_EQ(got[0].text, "be helpful");
    EXPECT_EQ(path_str(got[1].path), "input");
    EXPECT_EQ(got[1].text, "hello");
}

TEST(GuardExtractRespRequest, InputArrayWithStringContent) {
    const std::string body = R"({"input":[{"role":"user","content":"first"},{"role":"assistant","content":"second"}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "input.0.content");
    EXPECT_EQ(got[0].text, "first");
    EXPECT_EQ(path_str(got[1].path), "input.1.content");
    EXPECT_EQ(got[1].text, "second");
}

TEST(GuardExtractRespRequest, InputTextPartsMixedWithInputImageKeepRealIndices) {
    const std::string body = R"({"input":[{"role":"user","content":[
        {"type":"input_image","image_url":"https://x/img.png"},
        {"type":"input_text","text":"look at user@example.com"}]}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "input.0.content.1.text");
    EXPECT_EQ(got[0].text, "look at user@example.com");
}

TEST(GuardExtractRespRequest, FunctionCallOutputStringOutput) {
    const std::string body = R"({"input":[{"type":"function_call_output","call_id":"c1","output":"token=abc123"}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "input.0.output");
    EXPECT_EQ(got[0].text, "token=abc123");
}

TEST(GuardExtractRespRequest, FunctionCallOutputContentArrayOutput) {
    const std::string body =
        R"({"input":[{"type":"function_call_output","call_id":"c1","output":)"
        R"([{"type":"output_text","text":"email a@b.com"},{"type":"input_text","text":"card 4111"}]}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "input.0.output.0.text");
    EXPECT_EQ(got[0].text, "email a@b.com");
    EXPECT_EQ(path_str(got[1].path), "input.0.output.1.text");
    EXPECT_EQ(got[1].text, "card 4111");
}

TEST(GuardExtractRespRequest, AssistantOutputTextReplayIsScanned) {
    // Stateless multi-turn: the client replays a prior assistant turn's
    // output_text, which must be re-scanned/re-masked before reaching
    // upstream.
    const std::string body =
        R"({"input":[{"role":"assistant","content":[{"type":"output_text","text":"contact user@example.com"}]}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "input.0.content.0.text");
    EXPECT_EQ(got[0].text, "contact user@example.com");
}

TEST(GuardExtractRespRequest, FunctionCallArgumentsAreScanned) {
    const std::string body =
        R"({"input":[{"type":"function_call","call_id":"c1","name":"f","arguments":"{\"email\":\"user@example.com\"}"}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "input.0.arguments");
    EXPECT_EQ(got[0].text, R"({"email":"user@example.com"})");
}

TEST(GuardExtractRespRequest, FunctionCallEmptyArgumentsSkipped) {
    const std::string body = R"({"input":[{"type":"function_call","call_id":"c1","name":"f","arguments":""}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    EXPECT_TRUE(fields_of(result).empty());
}

TEST(GuardExtractRespRequest, EmptyStringsSkipped) {
    const std::string body = R"({"instructions":"","input":""})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    EXPECT_TRUE(fields_of(result).empty());
}

TEST(GuardExtractRespRequest, NeitherInputNorInstructionsIsUnsupported) {
    const std::string body = R"({"model":"gpt-x","messages":[{"role":"user","content":"hi"}]})";
    EXPECT_TRUE(is_unsupported(Guard::Extract::Responses::extract_request(body)));
}

// Item kinds/parts the Go doc comment calls out as deliberately skipped,
// with NO explicit type-gating (see the Responses.hpp file-level doc
// comment): an item_reference input item and an input_file part both
// simply have nothing matching their type's field, so they contribute no
// fields, exactly like the Go reference.
TEST(GuardExtractRespRequest, ItemReferenceAndInputFileAreSkippedWithoutSpecialCasing) {
    const std::string body = R"({"input":[
        {"type":"item_reference","id":"ref_1"},
        {"role":"user","content":[{"type":"input_file","file_id":"f1"},{"type":"input_text","text":"visible@example.com"}]}
    ]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "input.1.content.1.text");
    EXPECT_EQ(got[0].text, "visible@example.com");
}

// Round-trip: the returned path+span must identify exactly the substring
// sjson's dotted `Path` would patch in the Go original. This port has no
// dotted-path string, so the equivalent guarantee is pinned directly via
// `Json::splice_all` against the returned `ContentField::span`s.
TEST(GuardExtractRespRequest, FieldsPatchableViaSpliceAll) {
    const std::string body =
        R"({"instructions":"i","input":[{"role":"user","content":[{"type":"input_text","text":"secret"}]}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& fields = fields_of(result);
    ASSERT_EQ(fields.size(), 2u);

    std::vector<std::pair<ValueSpan, std::string>> edits;
    for (const auto& f : fields)
        edits.emplace_back(f.span, Guard::Json::encode_string("<MASKED>", true));
    const std::string patched = Guard::Json::splice_all(body, edits);

    EXPECT_EQ(patched,
              R"({"instructions":"<MASKED>","input":[{"role":"user","content":[{"type":"input_text","text":"<MASKED>"}]}]})");
}

// ── extract_request: probe-verified edge cases ──────────────────────────

TEST(GuardExtractRespRequest, InputPresentButWrongTypeIsEmptyNotUnsupported) {
    // "input" existing at all (any type) defeats the neither-present
    // Unsupported gate, but only a string or array value is actually
    // scannable -- a number/null/bool/object "input" degrades to zero
    // fields, not an error, exactly like a present-but-non-array
    // `messages`/`choices` does in ChatCompletions.hpp.
    for (const std::string_view body : {R"({"input":123})", R"({"input":null})", R"({"input":true})", R"({"input":{}})"}) {
        SCOPED_TRACE(body);
        const auto result = Guard::Extract::Responses::extract_request(body);
        ASSERT_FALSE(is_unsupported(result));
        EXPECT_TRUE(fields_of(result).empty());
    }
}

TEST(GuardExtractRespRequest, UnicodeAndEscapedContentPreserved) {
    // Multibyte UTF-8 (世界, 🌍) plus a \uXXXX escape and an escaped quote,
    // to pin that decode_string's real unescaping -- not just byte-copying
    // -- is exercised end to end through this extractor.
    const std::string body = R"({"input":"Hello 世界 \"quoted\" café 🌍"})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].text, "Hello 世界 \"quoted\" café 🌍");
}

// Regression: an earlier per-index find_value/find_value_in probing
// implementation of array iteration could, in principle, mis-stop at the
// first element whose shape doesn't match an expected item type. The
// `array_elements`-based rewrite resolves every element up front in one
// forward pass, so a null/scalar element between two real items must not
// prevent the later real item from being extracted.
TEST(GuardExtractRespRequest, InputArrayNullAndScalarElementsDoNotStopLaterItems) {
    const std::string body = R"({"input":[
        {"role":"user","content":"first"},
        null,
        42,
        "just a scalar array element",
        {"role":"assistant","content":"second"}
    ]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "input.0.content");
    EXPECT_EQ(got[0].text, "first");
    EXPECT_EQ(path_str(got[1].path), "input.4.content");
    EXPECT_EQ(got[1].text, "second");
}

// One large `input` array exercising every branch of the per-item type
// dispatch table in a single body, in document order: string content,
// content-array with a skipped part, function_call arguments,
// function_call_output string form, function_call_output content-array
// form, an item_reference (no matching field at all), and a reasoning
// input item (has `summary`/`encrypted_content` but no plain `content`, so
// contributes nothing -- see the file-level doc comment's "no explicit
// type-gating" note).
TEST(GuardExtractRespRequest, MixedTypeInputArrayPinsWholeDispatchTable) {
    const std::string body = R"({"input":[
        {"role":"user","content":"plain string content"},
        {"role":"user","content":[
            {"type":"input_text","text":"array text part"},
            {"type":"input_image","image_url":"https://x/img.png"}
        ]},
        {"type":"function_call","call_id":"c1","arguments":"{\"a\":1}"},
        {"type":"function_call_output","call_id":"c1","output":"tool result string"},
        {"type":"function_call_output","call_id":"c2","output":[{"type":"output_text","text":"tool result part"}]},
        {"type":"item_reference","id":"ref_1"},
        {"type":"reasoning","summary":[{"type":"summary_text","text":"not scanned on the request side"}],
         "encrypted_content":"opaque"}
    ]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 5u);
    EXPECT_EQ(path_str(got[0].path), "input.0.content");
    EXPECT_EQ(got[0].text, "plain string content");
    EXPECT_EQ(path_str(got[1].path), "input.1.content.0.text");
    EXPECT_EQ(got[1].text, "array text part");
    EXPECT_EQ(path_str(got[2].path), "input.2.arguments");
    EXPECT_EQ(got[2].text, R"({"a":1})");
    EXPECT_EQ(path_str(got[3].path), "input.3.output");
    EXPECT_EQ(got[3].text, "tool result string");
    EXPECT_EQ(path_str(got[4].path), "input.4.output.0.text");
    EXPECT_EQ(got[4].text, "tool result part");
}

// ── extract_response: ExtractOutputFields ───────────────────────────────

TEST(GuardExtractRespResponse, OutputFieldsTopLevel) {
    const auto got = Guard::Extract::Responses::extract_response_output_fields(kResponsesBody, {});
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(path_str(got[0].path), "output.0.summary.0.text");
    EXPECT_EQ(got[0].text, "thinking about <EMAIL_1>");
    EXPECT_EQ(path_str(got[1].path), "output.1.content.0.text");
    EXPECT_EQ(got[1].text, "hello <EMAIL_1>");
    EXPECT_EQ(path_str(got[2].path), "output.2.arguments");
    EXPECT_EQ(got[2].text, R"({"to":"<EMAIL_1>"})");
}

TEST(GuardExtractRespResponse, OutputFieldsWithBasePath) {
    // The SSE processor extracts from the object embedded in
    // response.completed events.
    const std::string embedded = std::string(R"({"type":"response.completed","response":)") + kResponsesBody + "}";
    const auto got = Guard::Extract::Responses::extract_response_output_fields(embedded, {key("response")});
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(path_str(got[1].path), "response.output.1.content.0.text");
}

TEST(GuardExtractRespResponse, OutputFieldsNoOutput) {
    EXPECT_TRUE(Guard::Extract::Responses::extract_response_output_fields(R"({"id":"resp_1"})", {}).empty());
    EXPECT_TRUE(Guard::Extract::Responses::extract_response_output_fields(R"({"output":"nope"})", {}).empty());
}

// Every extracted field's span must round-trip through `Json::splice_all`,
// AND every masked placeholder must land strictly inside the embedded
// "response" object's own byte range -- not leak into the enclosing SSE
// envelope (e.g. its "type" field) -- and the patched document must still
// be valid JSON.
TEST(GuardExtractRespResponse, OutputFieldsSpliceRoundTripWithBasePath) {
    const std::string embedded = std::string(R"({"type":"response.completed","response":)") + kResponsesBody + "}";
    const auto fields = Guard::Extract::Responses::extract_response_output_fields(embedded, {key("response")});
    ASSERT_EQ(fields.size(), 3u);

    std::vector<std::pair<ValueSpan, std::string>> edits;
    for (const auto& f : fields)
        edits.emplace_back(f.span, Guard::Json::encode_string("<MASKED>", true));
    const std::string patched = Guard::Json::splice_all(embedded, edits);

    ASSERT_TRUE(Guard::Json::valid(patched));

    const auto response_span = Guard::Json::find_value(patched, {key("response")});
    ASSERT_TRUE(response_span.has_value());

    static constexpr std::string_view kPlaceholder = "<MASKED>";
    std::size_t pos = 0;
    std::size_t count = 0;
    while ((pos = patched.find(kPlaceholder, pos)) != std::string::npos) {
        EXPECT_GE(pos, response_span->start) << "placeholder at " << pos << " leaked before the response object";
        EXPECT_LE(pos + kPlaceholder.size(), response_span->end)
            << "placeholder at " << pos << " leaked past the response object";
        ++count;
        pos += kPlaceholder.size();
    }
    EXPECT_EQ(count, 3u);

    // Re-resolving one of the patched fields by its ORIGINAL path must land
    // on the masked value, not the original -- confirms the path is still
    // usable against the PATCHED document too (paths are index-based, and
    // splice_all never changes element counts/ordering).
    const auto refound =
        Guard::Json::find_value(patched, {key("response"), key("output"), idx(2), key("arguments")});
    ASSERT_TRUE(refound.has_value());
    EXPECT_EQ(Guard::Json::decode_string(patched.substr(refound->start, refound->end - refound->start)), "<MASKED>");
}

// ── extract_response: ExtractItemFields ─────────────────────────────────
// item_path must be a real path into body (see the file-level doc
// comment), so these wrap the Go fixture's bare item literal under a real
// "item" key.

TEST(GuardExtractRespResponse, ItemFieldsMessage) {
    const std::string body = R"({"item":{"type":"message","content":[{"type":"output_text","text":"hi <EMAIL_1>"}]}})";
    const auto got = Guard::Extract::Responses::extract_response_item_fields(body, {key("item")});
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(path_str(got[0].path), "item.content.0.text");
    EXPECT_EQ(got[0].text, "hi <EMAIL_1>");
}

TEST(GuardExtractRespResponse, ItemFieldsUnknownTypeIsEmpty) {
    const std::string body = R"({"item":{"type":"computer_call","action":{}}})";
    EXPECT_TRUE(Guard::Extract::Responses::extract_response_item_fields(body, {key("item")}).empty());
}

// Reasoning items may carry chain-of-thought text in content[].reasoning_text
// (in addition to summary[].summary_text); both must be demasked,
// encrypted_content never touched. Regression for a placeholder leaking in
// the reasoning trace of a reasoning model.
TEST(GuardExtractRespResponse, ItemFieldsReasoningContentAndSummaryBothScannedEncryptedContentUntouched) {
    const std::string body = R"({"item":{"type":"reasoning",)"
                              R"("summary":[{"type":"summary_text","text":"sum <EMAIL_1>"}],)"
                              R"("content":[{"type":"reasoning_text","text":"cot <EMAIL_1>"}],)"
                              R"("encrypted_content":"opaque"}})";
    const auto got = Guard::Extract::Responses::extract_response_item_fields(body, {key("item")});
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(path_str(got[0].path), "item.summary.0.text");
    EXPECT_EQ(got[0].text, "sum <EMAIL_1>");
    EXPECT_EQ(path_str(got[1].path), "item.content.0.text");
    EXPECT_EQ(got[1].text, "cot <EMAIL_1>");
}

// ── Extract.hpp dispatch wiring ─────────────────────────────────────────

TEST(GuardExtractRespDispatch, RequestRoutesToResponses) {
    const std::string body = R"({"instructions":"be helpful"})";
    const auto result = Guard::Extract::extract_request(body, Guard::ApiFormat::Responses);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].text, "be helpful");
}

TEST(GuardExtractRespDispatch, RequestUnsupportedPassesThrough) {
    const std::string body = R"({"messages":[{"role":"user","content":"hi"}]})";
    EXPECT_TRUE(is_unsupported(Guard::Extract::extract_request(body, Guard::ApiFormat::Responses)));
}

TEST(GuardExtractRespDispatch, ResponseRoutesToResponsesWithEmptyBasePath) {
    const auto result = Guard::Extract::extract_response(kResponsesBody, Guard::ApiFormat::Responses);
    ASSERT_FALSE(is_unsupported(result));
    const auto& got = fields_of(result);
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(path_str(got[2].path), "output.2.arguments");
}
