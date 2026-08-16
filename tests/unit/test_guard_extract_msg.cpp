/**
 * @file test_guard_extract_msg.cpp
 * @brief Unit tests for `Guard::Extract::Messages` (`src/guard/extract/
 *        Messages.hpp`) -- the Anthropic Messages API (`/v1/messages`)
 *        content extractor -- plus the `ApiFormat::Messages` dispatch case
 *        wired into `Guard::Extract::extract_request`/`extract_response`
 *        (`src/guard/extract/Extract.hpp`).
 *
 * Ports the Go reference's `pkg/llmutils/messages/extract_test.go` corpus
 * (there is no separate `extract_response_test.go` in the Go reference;
 * response coverage here is original, written against `extract_response.go`
 * read directly) plus C++-specific pins that have no Go analogue:
 *   - `ContentField::span` resolves against the ORIGINAL body bytes.
 *   - `Guard::Json::PathSeg` needs no dotted-path escaping (unlike gjson).
 *   - Never returns `Unsupported` (Go: never returns an `error`).
 *
 * Test groups:
 *   - MessagesRequest: ports extract_test.go's `TestExtractRequestContent`
 *     subtests, plus order/malformed/span pins.
 *   - MessagesResponse: extract_response.go coverage (no Go test file to
 *     port from).
 *   - MessagesDispatch: `ApiFormat::Messages` wired into the shared
 *     `Extract::extract_request`/`extract_response` switch.
 */

#include <cstddef>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "guard/ApiFormat.hpp"
#include "guard/extract/Extract.hpp"
#include "guard/extract/Messages.hpp"
#include "guard/json/Json.hpp"

namespace {

using Guard::Extract::ContentField;
using Guard::Extract::ExtractResult;
using Guard::Json::PathSeg;
using Guard::Json::ValueSpan;

PathSeg key(std::string k) {
    return PathSeg{std::move(k), 0, false};
}

PathSeg idx(std::size_t i) {
    return PathSeg{"", i, true};
}

bool path_eq(const std::vector<PathSeg>& a, const std::vector<PathSeg>& b) {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i].is_index != b[i].is_index)
            return false;
        if (a[i].is_index) {
            if (a[i].index != b[i].index)
                return false;
        } else {
            if (a[i].key != b[i].key)
                return false;
        }
    }
    return true;
}

const ContentField* find_field(const std::vector<ContentField>& fields, const std::vector<PathSeg>& path) {
    for (const auto& f : fields) {
        if (path_eq(f.path, path))
            return &f;
    }
    return nullptr;
}

// Every test result is asserted to hold `vector<ContentField>` (never
// `Unsupported` -- see the file-level doc comment) before unwrapping, so a
// regression to the Unsupported branch fails loudly instead of silently
// producing an empty vector some other way.
std::vector<ContentField> unwrap(const ExtractResult& result) {
    EXPECT_TRUE(std::holds_alternative<std::vector<ContentField>>(result))
        << "Messages extractor must never return Unsupported";
    if (auto* fields = std::get_if<std::vector<ContentField>>(&result))
        return *fields;
    return {};
}

std::string span_text(std::string_view doc, const ValueSpan& span) {
    return std::string(doc.substr(span.start, span.end - span.start));
}

}  // namespace

// ── MessagesRequest ─────────────────────────────────────────────────────

TEST(MessagesRequest, SystemStringIsExtracted) {
    const std::string body =
        R"({"model":"claude","system":"SSN 123-45-6789","messages":[{"role":"user","content":"hi"}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    ASSERT_EQ(fields.size(), 2u);
    const auto* sys = find_field(fields, {key("system")});
    ASSERT_NE(sys, nullptr);
    EXPECT_EQ(sys->text, "SSN 123-45-6789");
    EXPECT_FALSE(sys->is_raw_object);
    EXPECT_EQ(span_text(body, sys->span), R"("SSN 123-45-6789")");

    // Order mirrors the Go original: system first, then messages left to
    // right (masker numbering depends on this).
    EXPECT_TRUE(path_eq(fields[0].path, {key("system")}));
    EXPECT_TRUE(path_eq(fields[1].path, {key("messages"), idx(0), key("content")}));
}

TEST(MessagesRequest, SystemBlockArrayIsExtracted) {
    const std::string body =
        R"({"system":[{"type":"text","text":"first"},{"type":"text","text":"second"}],"messages":[]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    ASSERT_EQ(fields.size(), 2u);
    EXPECT_TRUE(path_eq(fields[0].path, {key("system"), idx(0), key("text")}));
    EXPECT_EQ(fields[0].text, "first");
    EXPECT_TRUE(path_eq(fields[1].path, {key("system"), idx(1), key("text")}));
    EXPECT_EQ(fields[1].text, "second");
}

TEST(MessagesRequest, ContentBlocksTextToolUseToolResult) {
    const std::string body = R"({"messages":[{"role":"user","content":[
        {"type":"text","text":"hello"},
        {"type":"tool_use","id":"t1","name":"f","input":{"q":"secret"}},
        {"type":"tool_result","tool_use_id":"t1","content":"result text"}
    ]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    ASSERT_EQ(fields.size(), 3u);
    EXPECT_TRUE(path_eq(fields[0].path, {key("messages"), idx(0), key("content"), idx(0), key("text")}));
    EXPECT_EQ(fields[0].text, "hello");

    const auto* input_q = find_field(fields, {key("messages"), idx(0), key("content"), idx(1), key("input"), key("q")});
    ASSERT_NE(input_q, nullptr);
    EXPECT_EQ(input_q->text, "secret");

    const auto* tool_result_content =
        find_field(fields, {key("messages"), idx(0), key("content"), idx(2), key("content")});
    ASSERT_NE(tool_result_content, nullptr);
    EXPECT_EQ(tool_result_content->text, "result text");
}

TEST(MessagesRequest, ToolUseInputStringLeavesNestedEscapedNonStringSkipped) {
    // Scanning decoded leaves lets rules match values that JSON escaping
    // would otherwise hide, and leaf-level patching keeps the object valid.
    const std::string body =
        R"({"messages":[{"role":"user","content":[)"
        R"({"type":"tool_use","id":"t1","name":"f","input":)"
        R"({"note":"say \"hi\"","nested":{"path":"C:\\tmp\\key"},"list":["x",7],"count":42,"ok":true,"blank":""}})"
        R"(]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    const std::vector<PathSeg> base = {key("messages"), idx(0), key("content"), idx(0), key("input")};

    auto with = [&](std::vector<PathSeg> extra) {
        std::vector<PathSeg> p = base;
        for (auto& s : extra)
            p.push_back(std::move(s));
        return p;
    };

    const auto* note = find_field(fields, with({key("note")}));
    ASSERT_NE(note, nullptr);
    EXPECT_EQ(note->text, R"(say "hi")") << "leaf values are decoded, not raw-escaped";

    const auto* nested_path = find_field(fields, with({key("nested"), key("path")}));
    ASSERT_NE(nested_path, nullptr);
    EXPECT_EQ(nested_path->text, R"(C:\tmp\key)");

    EXPECT_NE(find_field(fields, with({key("list"), idx(0)})), nullptr) << "array string elements are leaves";

    EXPECT_EQ(find_field(fields, with({key("count")})), nullptr) << "number leaf must not be extracted";
    EXPECT_EQ(find_field(fields, with({key("ok")})), nullptr) << "bool leaf must not be extracted";
    EXPECT_EQ(find_field(fields, with({key("list"), idx(1)})), nullptr)
        << "non-string array element must not be extracted";
    EXPECT_EQ(find_field(fields, with({key("blank")})), nullptr)
        << "empty-string leaf must be filtered (extract.go:99's collectJSONStringLeaves guard, "
           "replicated in Messages.hpp since Json::string_leaves_in deliberately does not filter)";
}

TEST(MessagesRequest, ToolUseInputPlainStringIsOneLeafAtInputPath) {
    // Go's collectJSONStringLeaves recurses generically over ANY JSON
    // value, not just objects (extract.go:87-103's switch has no
    // "must be an object" precondition): when `input` itself is a plain
    // string rather than the usual object, the string IS the one leaf,
    // addressed at `.input` itself with no further path segment --
    // extract.go:99's `case v.Type == gjson.String && v.String() != ""`
    // matches `input` directly on the recursive call where `v == input`.
    const std::string body = R"({"messages":[{"role":"user","content":[)"
                             R"({"type":"tool_use","id":"t1","name":"f","input":"just a string"})"
                             R"(]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    ASSERT_EQ(fields.size(), 1u);
    EXPECT_TRUE(path_eq(fields[0].path, {key("messages"), idx(0), key("content"), idx(0), key("input")}));
    EXPECT_EQ(fields[0].text, "just a string");
    EXPECT_FALSE(fields[0].is_raw_object) << "request-side tool_use input is always a string leaf, never raw";
}

TEST(MessagesRequest, ToolUseInputTopLevelArrayLeafAtInputIndex) {
    // Same generic-recursion behavior for a top-level array `input`: its
    // one string element is a leaf addressed at `.input.0`.
    const std::string body = R"({"messages":[{"role":"user","content":[)"
                             R"({"type":"tool_use","id":"t1","name":"f","input":["secret"]})"
                             R"(]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    ASSERT_EQ(fields.size(), 1u);
    EXPECT_TRUE(path_eq(fields[0].path, {key("messages"), idx(0), key("content"), idx(0), key("input"), idx(0)}));
    EXPECT_EQ(fields[0].text, "secret");
}

TEST(MessagesRequest, ToolUseNestedLeafSpanResolvesAgainstOriginalBytes) {
    // Pins `string_leaves_in`'s offset-readdition: a leaf found via a
    // SCOPED sub-walk (`find_value_in` resolves `input`'s own span, then
    // `string_leaves_in` walks THAT span) must still report a span
    // expressed in the ORIGINAL body's byte offsets, not the intermediate
    // substring's own 0-based offsets -- a regression here would still pass
    // every text-content assertion (the decoded text is unaffected) while
    // silently breaking every consumer that patches the body back via the
    // span (the whole point of `ContentField::span`).
    const std::string body = R"({"messages":[{"role":"user","content":[)"
                             R"({"type":"tool_use","id":"t1","name":"f",)"
                             R"("input":{"outer":{"inner":"deep secret"}}})"
                             R"(]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    const auto* leaf =
        find_field(fields, {key("messages"), idx(0), key("content"), idx(0), key("input"), key("outer"), key("inner")});
    ASSERT_NE(leaf, nullptr);
    EXPECT_EQ(leaf->text, "deep secret");
    EXPECT_EQ(span_text(body, leaf->span), R"("deep secret")")
        << "leaf span must resolve against the ORIGINAL body bytes, not a scoped substring's own offsets";
}

TEST(MessagesRequest, ToolUseInputKeysWithPathMetacharactersNeedNoEscaping) {
    // Go's gjson/sjson address a field via one dotted-and-escaped string, so
    // extract.go's escapePathKey guards keys containing '.'/'*'/etc. This
    // port's PathSeg is a pre-split segment vector instead (Json.hpp's doc
    // comment): the raw key is carried through verbatim, with no escaping
    // step and no dotted-string round-trip to get wrong.
    const std::string body = R"({"messages":[{"role":"user","content":[)"
                             R"({"type":"tool_use","id":"t1","name":"f","input":{"a.b":"dotted","c*d":"starred"}})"
                             R"(]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    const std::vector<PathSeg> base = {key("messages"), idx(0), key("content"), idx(0), key("input")};

    const auto* dotted = find_field(fields, {base[0], base[1], base[2], base[3], base[4], key("a.b")});
    ASSERT_NE(dotted, nullptr) << "literal dotted key must be found unescaped";
    EXPECT_EQ(dotted->text, "dotted");

    const auto* starred = find_field(fields, {base[0], base[1], base[2], base[3], base[4], key("c*d")});
    ASSERT_NE(starred, nullptr) << "literal starred key must be found unescaped";
    EXPECT_EQ(starred->text, "starred");
}

TEST(MessagesRequest, ToolResultContentAsTextBlocks) {
    const std::string body = R"({"messages":[{"role":"user","content":[{"type":"tool_result","content":[)"
                             R"({"type":"text","text":"a"},{"type":"text","text":"b"}]}]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));

    ASSERT_EQ(fields.size(), 2u);
    EXPECT_TRUE(path_eq(fields[0].path,
                        {key("messages"), idx(0), key("content"), idx(0), key("content"), idx(0), key("text")}));
    EXPECT_EQ(fields[0].text, "a");
    EXPECT_TRUE(path_eq(fields[1].path,
                        {key("messages"), idx(0), key("content"), idx(0), key("content"), idx(1), key("text")}));
    EXPECT_EQ(fields[1].text, "b");
}

TEST(MessagesRequest, EmptyBodyYieldsNoFields) {
    const std::string body = R"({"model":"claude"})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));
    EXPECT_TRUE(fields.empty());
}

TEST(MessagesRequest, EmptyToolUseInputIsSkipped) {
    const std::string body =
        R"({"messages":[{"role":"user","content":[{"type":"tool_use","id":"t1","name":"f","input":{}}]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));
    EXPECT_TRUE(fields.empty());
}

TEST(MessagesRequest, EmptyStringValuesAreFiltered) {
    // system/content/text/tool_result values that ARE strings but decode to
    // "" are filtered, mirroring Go's `Result.String() != ""` guard at
    // every extraction site (not just collectJSONStringLeaves).
    const std::string body = R"({"system":"","messages":[
        {"role":"user","content":""},
        {"role":"user","content":[{"type":"text","text":""}]}
    ]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));
    EXPECT_TRUE(fields.empty());
}

TEST(MessagesRequest, MalformedBodyYieldsNoFieldsNeverUnsupported) {
    for (std::string_view body : {
             std::string_view(""),
             std::string_view("not json"),
             std::string_view(R"({"system":123,"messages":"not an array"})"),
             std::string_view(R"({"messages":[{"content":{"not":"a string or array"}}]})"),
             std::string_view(R"({"messages":[1,2,3])"),  // truncated/invalid trailing
         }) {
        const auto result = Guard::Extract::Messages::extract_request(body);
        ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(result)) << "body: " << body;
        EXPECT_TRUE(std::get<std::vector<ContentField>>(result).empty()) << "body: " << body;
    }
}

TEST(MessagesRequest, SpansResolveAgainstOriginalBodyBytes) {
    const std::string body = R"({"model":"m","system":"top secret","messages":[]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_request(body));
    ASSERT_EQ(fields.size(), 1u);
    // The span, sliced directly out of the ORIGINAL body, must be the
    // still-quoted JSON string literal -- not a re-serialization.
    EXPECT_EQ(span_text(body, fields[0].span), R"("top secret")");
}

// ── MessagesResponse ────────────────────────────────────────────────────

TEST(MessagesResponse, TextBlockIsExtracted) {
    const std::string body = R"({"content":[{"type":"text","text":"hello there"}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_TRUE(path_eq(fields[0].path, {key("content"), idx(0), key("text")}));
    EXPECT_EQ(fields[0].text, "hello there");
    EXPECT_FALSE(fields[0].is_raw_object);
}

TEST(MessagesResponse, ThinkingBlockExtractedSignatureNotExtracted) {
    const std::string body =
        R"({"content":[{"type":"thinking","thinking":"reasoning steps","signature":"enc-abc123"}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));

    ASSERT_EQ(fields.size(), 1u);
    EXPECT_TRUE(path_eq(fields[0].path, {key("content"), idx(0), key("thinking")}));
    EXPECT_EQ(fields[0].text, "reasoning steps");
    EXPECT_EQ(find_field(fields, {key("content"), idx(0), key("signature")}), nullptr)
        << "signature is encrypted and must never be extracted";
}

TEST(MessagesResponse, ToolUseRawInputIsExtracted) {
    const std::string body =
        R"({"content":[{"type":"tool_use","id":"t1","name":"lookup","input":{"query":"secret","n":3}}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));

    ASSERT_EQ(fields.size(), 1u);
    EXPECT_TRUE(path_eq(fields[0].path, {key("content"), idx(0), key("input")}));
    EXPECT_TRUE(fields[0].is_raw_object) << "tool_use input must be flagged raw-object, not decoded as a string";
    EXPECT_EQ(fields[0].text, R"({"query":"secret","n":3})");
    EXPECT_EQ(span_text(body, fields[0].span), R"({"query":"secret","n":3})");
}

TEST(MessagesResponse, ToolUseEmptyObjectInputIsSkipped) {
    const std::string body = R"({"content":[{"type":"tool_use","id":"t1","name":"f","input":{}}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));
    EXPECT_TRUE(fields.empty());
}

TEST(MessagesResponse, ToolUseArrayInputIsSkipped) {
    // extract_response.go's guard is `v.IsObject() && ...`: a non-object
    // `input` (an array here) fails that gate and is skipped, both in Go
    // and in this port's `body[input_span->start] == '{'` check.
    const std::string body = R"({"content":[{"type":"tool_use","id":"t1","name":"f","input":["a","b"]}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));
    EXPECT_TRUE(fields.empty());
}

TEST(MessagesResponse, ToolUseWhitespaceObjectInputIsExtracted) {
    // Go's empty-input guard is a byte-EXACT `v.Raw != "{}"` string
    // comparison, not a semantic "is this object empty" check: `"{ }"`
    // (with an internal space) is a different 3-byte string than the
    // literal 2-byte `"{}"`, so it passes the guard and IS extracted, even
    // though it is semantically still an empty object. This pins that
    // quirk-faithful port rather than a "smarter" semantic-emptiness check
    // neither Go nor this port actually performs.
    const std::string body = R"({"content":[{"type":"tool_use","id":"t1","name":"f","input":{ }}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));

    ASSERT_EQ(fields.size(), 1u);
    EXPECT_TRUE(fields[0].is_raw_object);
    EXPECT_EQ(fields[0].text, "{ }");
}

TEST(MessagesResponse, RedactedThinkingBlockIsSkipped) {
    const std::string body = R"({"content":[{"type":"redacted_thinking","data":"opaque-encrypted-blob"}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));
    EXPECT_TRUE(fields.empty());
}

TEST(MessagesResponse, UnknownBlockTypeIsSkipped) {
    const std::string body = R"({"content":[{"type":"some_future_block_type","payload":"whatever"}]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));
    EXPECT_TRUE(fields.empty());
}

TEST(MessagesResponse, OrderMatchesContentArrayDocumentOrder) {
    const std::string body = R"({"content":[
        {"type":"text","text":"first"},
        {"type":"redacted_thinking","data":"x"},
        {"type":"thinking","thinking":"second","signature":"sig"},
        {"type":"some_unknown_type"},
        {"type":"tool_use","id":"t1","name":"f","input":{"a":1}}
    ]})";
    const auto fields = unwrap(Guard::Extract::Messages::extract_response(body));

    ASSERT_EQ(fields.size(), 3u);
    EXPECT_TRUE(path_eq(fields[0].path, {key("content"), idx(0), key("text")}));
    EXPECT_TRUE(path_eq(fields[1].path, {key("content"), idx(2), key("thinking")}));
    EXPECT_TRUE(path_eq(fields[2].path, {key("content"), idx(4), key("input")}));
}

TEST(MessagesResponse, MalformedBodyYieldsNoFieldsNeverUnsupported) {
    for (std::string_view body : {
             std::string_view(""),
             std::string_view("not json"),
             std::string_view(R"({"content":"not an array"})"),
             std::string_view(R"({"no_content_field":true})"),
             std::string_view(R"({"content":[{"type":"text","text":123}]})"),  // wrong type for text
         }) {
        const auto result = Guard::Extract::Messages::extract_response(body);
        ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(result)) << "body: " << body;
        EXPECT_TRUE(std::get<std::vector<ContentField>>(result).empty()) << "body: " << body;
    }
}

// ── MessagesDispatch ────────────────────────────────────────────────────

TEST(MessagesDispatch, ExtractRequestDispatchesToMessagesForMessagesFormat) {
    const std::string body = R"({"system":"secret value","messages":[]})";
    const auto direct = Guard::Extract::Messages::extract_request(body);
    const auto dispatched = Guard::Extract::extract_request(body, Guard::ApiFormat::Messages);

    ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(dispatched));
    ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(direct));
    const auto& dispatched_fields = std::get<std::vector<ContentField>>(dispatched);
    const auto& direct_fields = std::get<std::vector<ContentField>>(direct);
    ASSERT_EQ(dispatched_fields.size(), direct_fields.size());
    ASSERT_EQ(dispatched_fields.size(), 1u);
    EXPECT_EQ(dispatched_fields[0].text, direct_fields[0].text);
    EXPECT_EQ(dispatched_fields[0].text, "secret value");
}

TEST(MessagesDispatch, ExtractResponseDispatchesToMessagesForMessagesFormat) {
    const std::string body = R"({"content":[{"type":"text","text":"reply text"}]})";
    const auto dispatched = Guard::Extract::extract_response(body, Guard::ApiFormat::Messages);

    ASSERT_TRUE(std::holds_alternative<std::vector<ContentField>>(dispatched));
    const auto& fields = std::get<std::vector<ContentField>>(dispatched);
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_EQ(fields[0].text, "reply text");
}
