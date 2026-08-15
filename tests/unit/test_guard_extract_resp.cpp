/**
 * @file test_guard_extract_resp.cpp
 * @brief Unit tests for `Guard::Extract::Responses` (`src/guard/extract/
 *        Responses.hpp`) -- Task 2.4, the OpenAI Responses API
 *        (`/v1/responses`) content extractor -- plus the two Responses
 *        dispatch lines this task adds to `Extract.hpp`.
 *
 * Test groups, each porting the corresponding Go reference corpus from
 * `_reference/guardrails-llm-filter/pkg/llmutils/responses/{extract,
 * extract_response}_test.go`:
 *   - ExtractRequest*: `TestExtractRequestContent` (request-side, every
 *     table case), plus `TestExtractRequestContentPathsPatchable` (ported
 *     as a direct `Json::splice_all` round-trip -- this port's paths are
 *     already pre-split `PathSeg` vectors, so there is no sjson dotted-path
 *     string to round-trip through; the span-splice equivalent pins the
 *     same guarantee: every returned field's path+span identifies exactly
 *     the substring that must be replaced).
 *   - ExtractResponseOutputFields*: `TestExtractOutputFields`,
 *     `TestExtractOutputFieldsWithBasePath`, `TestExtractOutputFieldsNoOutput`.
 *   - ExtractResponseItemFields*: `TestExtractItemFields`,
 *     `TestExtractResponsesReasoningContent`. Go's `ExtractItemFields` takes
 *     an already-parsed `gjson.Result` plus an arbitrary reporting-path
 *     string, decoupled from how that Result was located in its source
 *     document. This port's `extract_response_item_fields` is byte-surgical
 *     (`Json::find_value`-based, per Task 2.1's design): `item_path` must be
 *     a REAL path into `body`, not an arbitrary label. These two tests
 *     therefore wrap the Go fixture's bare item literal under a real
 *     `{"item": ...}` key so `item_path = {PathSeg{"item",...}}` is an
 *     actual, resolvable path -- the expected output paths/values are
 *     otherwise identical to the Go corpus.
 *   - Dispatch: confirms `Guard::Extract::extract_request`/`extract_response`
 *     (the generic, format-keyed dispatcher in `Extract.hpp`) route
 *     `Guard::ApiFormat::Responses` to this file's functions with identical
 *     results, i.e. the two dispatch lines this task adds are wired
 *     correctly (not just the standalone `Responses::` functions).
 */

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

// Renders a PathSeg vector as a dotted string -- readable assertion
// failures, and lets expected paths be written as plain literals (mirroring
// the Go corpus's own dotted `Path` strings almost verbatim).
std::string path_str(const std::vector<PathSeg>& path) {
    std::string out;
    for (const auto& seg : path) {
        if (!out.empty())
            out += '.';
        out += seg.is_index ? std::to_string(seg.index) : seg.key;
    }
    return out;
}

struct Got {
    std::string path;
    std::string text;
};

std::vector<Got> as_got(const std::vector<ContentField>& fields) {
    std::vector<Got> out;
    out.reserve(fields.size());
    for (const auto& f : fields)
        out.push_back(Got{path_str(f.path), f.text});
    return out;
}

bool operator==(const Got& a, const Got& b) {
    return a.path == b.path && a.text == b.text;
}

void PrintTo(const Got& g, std::ostream* os) {
    *os << "{path=\"" << g.path << "\", text=\"" << g.text << "\"}";
}

// Unwraps a request-side ExtractResult, asserting it is NOT Unsupported.
std::vector<Got> require_fields(const ExtractResult& result) {
    if (!std::holds_alternative<std::vector<ContentField>>(result)) {
        ADD_FAILURE() << "expected the vector alternative, got Unsupported";
        return {};
    }
    return as_got(std::get<std::vector<ContentField>>(result));
}

std::vector<Got> extract_request(std::string_view body) {
    return require_fields(Guard::Extract::Responses::extract_request(body));
}

}  // namespace

// ── ExtractRequestContent (extract.go) ──────────────────────────────────

TEST(GuardExtractResp, RequestInputString) {
    const std::string body = R"({"model":"gpt-x","input":"my mail is user@example.com"})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"input", "my mail is user@example.com"}}));
}

TEST(GuardExtractResp, RequestInstructionsOnly) {
    const std::string body = R"({"model":"gpt-x","instructions":"act as user@example.com"})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"instructions", "act as user@example.com"}}));
}

TEST(GuardExtractResp, RequestInstructionsAndInputString) {
    const std::string body = R"({"instructions":"be helpful","input":"hello"})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"instructions", "be helpful"}, {"input", "hello"}}));
}

TEST(GuardExtractResp, RequestInputArrayWithStringContent) {
    const std::string body = R"({"input":[{"role":"user","content":"first"},{"role":"assistant","content":"second"}]})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"input.0.content", "first"}, {"input.1.content", "second"}}));
}

TEST(GuardExtractResp, RequestInputTextPartsMixedWithInputImageKeepRealIndices) {
    const std::string body = R"({"input":[{"role":"user","content":[
        {"type":"input_image","image_url":"https://x/img.png"},
        {"type":"input_text","text":"look at user@example.com"}]}]})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"input.0.content.1.text", "look at user@example.com"}}));
}

TEST(GuardExtractResp, RequestFunctionCallOutputStringOutput) {
    const std::string body = R"({"input":[{"type":"function_call_output","call_id":"c1","output":"token=abc123"}]})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"input.0.output", "token=abc123"}}));
}

TEST(GuardExtractResp, RequestFunctionCallOutputContentArrayOutput) {
    const std::string body =
        R"({"input":[{"type":"function_call_output","call_id":"c1","output":)"
        R"([{"type":"output_text","text":"email a@b.com"},{"type":"input_text","text":"card 4111"}]}]})";
    EXPECT_EQ(extract_request(body),
              (std::vector<Got>{{"input.0.output.0.text", "email a@b.com"}, {"input.0.output.1.text", "card 4111"}}));
}

TEST(GuardExtractResp, RequestAssistantOutputTextReplayIsScanned) {
    // Stateless multi-turn: the client replays a prior assistant turn's
    // output_text, which must be re-scanned/re-masked before reaching
    // upstream.
    const std::string body =
        R"({"input":[{"role":"assistant","content":[{"type":"output_text","text":"contact user@example.com"}]}]})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"input.0.content.0.text", "contact user@example.com"}}));
}

TEST(GuardExtractResp, RequestFunctionCallArgumentsAreScanned) {
    const std::string body =
        R"({"input":[{"type":"function_call","call_id":"c1","name":"f","arguments":"{\"email\":\"user@example.com\"}"}]})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"input.0.arguments", R"({"email":"user@example.com"})"}}));
}

TEST(GuardExtractResp, RequestFunctionCallEmptyArgumentsSkipped) {
    const std::string body = R"({"input":[{"type":"function_call","call_id":"c1","name":"f","arguments":""}]})";
    EXPECT_TRUE(extract_request(body).empty());
}

TEST(GuardExtractResp, RequestEmptyStringsSkipped) {
    const std::string body = R"({"instructions":"","input":""})";
    EXPECT_TRUE(extract_request(body).empty());
}

TEST(GuardExtractResp, RequestNeitherInputNorInstructionsIsUnsupported) {
    const std::string body = R"({"model":"gpt-x","messages":[{"role":"user","content":"hi"}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    EXPECT_TRUE(std::holds_alternative<Unsupported>(result));
}

// Item kinds/parts the Go doc comment calls out as deliberately skipped,
// with NO explicit type-gating (see the Responses.hpp file-level doc
// comment): an item_reference input item and an input_file part both
// simply have nothing matching their type's field, so they contribute no
// fields, exactly like the Go reference.
TEST(GuardExtractResp, RequestItemReferenceAndInputFileAreSkippedWithoutSpecialCasing) {
    const std::string body = R"({"input":[
        {"type":"item_reference","id":"ref_1"},
        {"role":"user","content":[{"type":"input_file","file_id":"f1"},{"type":"input_text","text":"visible@example.com"}]}
    ]})";
    EXPECT_EQ(extract_request(body), (std::vector<Got>{{"input.1.content.1.text", "visible@example.com"}}));
}

// Round-trip: the returned path+span must identify exactly the substring
// sjson's dotted `Path` would patch in the Go original. This port has no
// dotted-path string, so the equivalent guarantee is pinned directly via
// `Json::splice_all` against the returned `ContentField::span`s.
TEST(GuardExtractResp, RequestFieldsPatchableViaSpliceAll) {
    const std::string body =
        R"({"instructions":"i","input":[{"role":"user","content":[{"type":"input_text","text":"secret"}]}]})";
    const auto result = Guard::Extract::Responses::extract_request(body);
    ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(result));
    const auto& fields = std::get<std::vector<ContentField>>(result);
    ASSERT_EQ(fields.size(), 2u);

    std::vector<std::pair<ValueSpan, std::string>> edits;
    for (const auto& f : fields)
        edits.emplace_back(f.span, Guard::Json::encode_string("<MASKED>", true));
    const std::string patched = Guard::Json::splice_all(body, edits);

    EXPECT_EQ(
        patched,
        R"({"instructions":"<MASKED>","input":[{"role":"user","content":[{"type":"input_text","text":"<MASKED>"}]}]})");
}

// ── ExtractOutputFields (extract_response.go) ───────────────────────────

namespace {

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

TEST(GuardExtractResp, ExtractOutputFieldsTopLevel) {
    const auto fields = Guard::Extract::Responses::extract_response_output_fields(kResponsesBody, {});
    EXPECT_EQ(as_got(fields),
              (std::vector<Got>{{"output.0.summary.0.text", "thinking about <EMAIL_1>"},
                                {"output.1.content.0.text", "hello <EMAIL_1>"},
                                {"output.2.arguments", R"({"to":"<EMAIL_1>"})"}}));
}

TEST(GuardExtractResp, ExtractOutputFieldsWithBasePath) {
    // The SSE processor extracts from the object embedded in
    // response.completed events.
    const std::string embedded = std::string(R"({"type":"response.completed","response":)") + kResponsesBody + "}";
    const auto fields = Guard::Extract::Responses::extract_response_output_fields(embedded, {key("response")});
    ASSERT_EQ(fields.size(), 3u);
    EXPECT_EQ(path_str(fields[1].path), "response.output.1.content.0.text");
}

TEST(GuardExtractResp, ExtractOutputFieldsNoOutput) {
    EXPECT_TRUE(Guard::Extract::Responses::extract_response_output_fields(R"({"id":"resp_1"})", {}).empty());
    EXPECT_TRUE(Guard::Extract::Responses::extract_response_output_fields(R"({"output":"nope"})", {}).empty());
}

// ── ExtractItemFields (extract_response.go) ─────────────────────────────
// See the file-level doc comment: item_path must be a real path into body,
// so these wrap the Go fixture's bare item literal under a real "item" key.

TEST(GuardExtractResp, ExtractItemFieldsMessage) {
    const std::string body = R"({"item":{"type":"message","content":[{"type":"output_text","text":"hi <EMAIL_1>"}]}})";
    const auto fields = Guard::Extract::Responses::extract_response_item_fields(body, {key("item")});
    EXPECT_EQ(as_got(fields), (std::vector<Got>{{"item.content.0.text", "hi <EMAIL_1>"}}));
}

TEST(GuardExtractResp, ExtractItemFieldsUnknownTypeIsEmpty) {
    const std::string body = R"({"item":{"type":"computer_call","action":{}}})";
    EXPECT_TRUE(Guard::Extract::Responses::extract_response_item_fields(body, {key("item")}).empty());
}

// Reasoning items may carry chain-of-thought text in content[].reasoning_text
// (in addition to summary[].summary_text); both must be demasked,
// encrypted_content never touched. Regression for a placeholder leaking in
// the reasoning trace of a reasoning model.
TEST(GuardExtractResp, ExtractItemFieldsReasoningContentAndSummaryBothScannedEncryptedContentUntouched) {
    const std::string body = R"({"item":{"type":"reasoning",)"
                             R"("summary":[{"type":"summary_text","text":"sum <EMAIL_1>"}],)"
                             R"("content":[{"type":"reasoning_text","text":"cot <EMAIL_1>"}],)"
                             R"("encrypted_content":"opaque"}})";
    const auto fields = Guard::Extract::Responses::extract_response_item_fields(body, {key("item")});
    EXPECT_EQ(as_got(fields),
              (std::vector<Got>{{"item.summary.0.text", "sum <EMAIL_1>"}, {"item.content.0.text", "cot <EMAIL_1>"}}));
}

// ── Guard::Extract::extract_request/extract_response dispatch wiring ───

TEST(GuardExtractResp, DispatchExtractRequestRoutesToResponses) {
    const std::string body = R"({"instructions":"be helpful"})";
    const auto dispatched = Guard::Extract::extract_request(body, Guard::ApiFormat::Responses);
    const auto direct = Guard::Extract::Responses::extract_request(body);
    ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(dispatched));
    ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(direct));
    EXPECT_EQ(as_got(std::get<std::vector<ContentField>>(dispatched)),
              as_got(std::get<std::vector<ContentField>>(direct)));
    EXPECT_EQ(as_got(std::get<std::vector<ContentField>>(dispatched)),
              (std::vector<Got>{{"instructions", "be helpful"}}));
}

TEST(GuardExtractResp, DispatchExtractRequestUnsupportedPassesThrough) {
    const std::string body = R"({"messages":[{"role":"user","content":"hi"}]})";
    const auto dispatched = Guard::Extract::extract_request(body, Guard::ApiFormat::Responses);
    EXPECT_TRUE(std::holds_alternative<Unsupported>(dispatched));
}

TEST(GuardExtractResp, DispatchExtractResponseRoutesToResponsesWithEmptyBasePath) {
    const auto dispatched = Guard::Extract::extract_response(kResponsesBody, Guard::ApiFormat::Responses);
    const auto direct = Guard::Extract::Responses::extract_response_output_fields(kResponsesBody, {});
    ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(dispatched));
    EXPECT_EQ(as_got(std::get<std::vector<ContentField>>(dispatched)), as_got(direct));
}
