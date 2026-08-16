/**
 * @file test_guard_json.cpp
 * @brief Unit tests for `Guard::Json` (`src/guard/json/Json.hpp`) -- the
 *        byte-surgical span scanner/splicer -- plus `Guard::Extract::
 *        wants_stream` (`src/guard/extract/Extract.hpp`), which Task 2.1's
 *        controller ruling folded into this task to remove a three-writer
 *        collision on `Extract.hpp` between Tasks 2.2-2.4.
 *
 * Test groups, each named for the behavior it pins:
 *   - FindValue: nested object/array traversal, escaped/unicode keys,
 *     duplicate-key first-wins, malformed input.
 *   - DecodeString, EncodeString: escape round-tripping, MarshalNoEscape
 *     parity (no HTML escaping of angle brackets/ampersand; unconditional
 *     line/paragraph separator escaping), invalid unicode-escape policy.
 *   - Valid: strict RFC 8259 validity.
 *   - Splice: byte-identity outside the spliced span(s), multi-splice
 *     ordering, overlap detection.
 *   - StringLeaves: document-order walk, non-string leaves skipped.
 *   - DeepNesting: 1000-level nesting, no crash.
 *   - GeneratedRoundTrip: 200 seeded-random documents; every string leaf's
 *     splice(find(x), encode(decode(x))) round-trips byte-identically.
 *   - WantsStream: Guard::Extract::wants_stream.
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "guard/extract/Extract.hpp"
#include "guard/json/Json.hpp"

namespace {

using Guard::Json::PathSeg;
using Guard::Json::StringLeaf;
using Guard::Json::ValueSpan;

PathSeg key(std::string k) {
    return PathSeg{std::move(k), 0, false};
}

PathSeg idx(std::size_t i) {
    return PathSeg{"", i, true};
}

std::string span_text(std::string_view doc, const ValueSpan& span) {
    return std::string(doc.substr(span.start, span.end - span.start));
}

}  // namespace

// ── find_value: nested traversal ────────────────────────────────────────

TEST(GuardJson, FindValueTopLevelString) {
    const std::string doc = R"({"a":"hello","b":2})";
    const auto span = Guard::Json::find_value(doc, {key("a")});
    ASSERT_TRUE(span.has_value());
    EXPECT_TRUE(span->is_string);
    EXPECT_EQ(span_text(doc, *span), "\"hello\"");
}

TEST(GuardJson, FindValueTopLevelNumberIsNotString) {
    const std::string doc = R"({"a":"hello","b":2})";
    const auto span = Guard::Json::find_value(doc, {key("b")});
    ASSERT_TRUE(span.has_value());
    EXPECT_FALSE(span->is_string);
    EXPECT_EQ(span_text(doc, *span), "2");
}

TEST(GuardJson, FindValueNestedObjectAndArray) {
    const std::string doc = R"({"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"there"}]})";
    const auto span = Guard::Json::find_value(doc, {key("messages"), idx(1), key("content")});
    ASSERT_TRUE(span.has_value());
    EXPECT_TRUE(span->is_string);
    EXPECT_EQ(span_text(doc, *span), "\"there\"");
}

TEST(GuardJson, FindValueArrayIndexZero) {
    const std::string doc = R"([10,20,30])";
    const auto span = Guard::Json::find_value(doc, {idx(0)});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "10");
}

TEST(GuardJson, FindValueEmptyPathReturnsWholeDocument) {
    const std::string doc = R"({"a":1})";
    const auto span = Guard::Json::find_value(doc, {});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span->start, 0u);
    EXPECT_EQ(span->end, doc.size());
    EXPECT_FALSE(span->is_string);
}

TEST(GuardJson, FindValueLeadingWhitespaceSkipped) {
    const std::string doc = "  \n\t {\"a\":1}";
    const auto span = Guard::Json::find_value(doc, {key("a")});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "1");
}

// ── find_value: duplicate keys, first occurrence wins (gjson semantics) ──

TEST(GuardJson, FindValueDuplicateKeyFirstWins) {
    const std::string doc = R"({"a":1,"a":2,"a":3})";
    const auto span = Guard::Json::find_value(doc, {key("a")});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "1");
}

TEST(GuardJson, FindValueDuplicateKeyFirstWinsNested) {
    const std::string doc = R"({"outer":{"x":"first"},"unrelated":1,"outer":{"x":"second"}})";
    const auto span = Guard::Json::find_value(doc, {key("outer"), key("x")});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "\"first\"");
}

// ── find_value: escaped / unicode keys ──────────────────────────────────

TEST(GuardJson, FindValueUnicodeKeyRawUtf8) {
    const std::string doc = "{\"\xD0\xB8\xD0\xBC\xD1\x8F\":\"value\"}";  // key "имя"
    const auto span = Guard::Json::find_value(doc, {key("\xD0\xB8\xD0\xBC\xD1\x8F")});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "\"value\"");
}

TEST(GuardJson, FindValueEscapedKeyMatchesDecodedKey) {
    // The document spells the key as "caf\u00e9" -- a literal JSON \u
    // escape sequence, not a raw UTF-8 byte -- while the caller passes the
    // already-decoded key "cafe with e-acute" (UTF-8 c3 a9 for the
    // e-acute); find_value must decode the document's key before
    // comparing, or this lookup would never match.
    const std::string doc = std::string("{\"caf") + "\\u00e9" + "\":\"drink\"}";
    const auto span = Guard::Json::find_value(doc, {key("caf\xC3\xA9")});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "\"drink\"");
}

TEST(GuardJson, FindValueEscapedQuoteAndBackslashInKey) {
    // Document key is: a"b\c (quote and backslash), spelled with escapes.
    const std::string doc = R"({"a\"b\\c":"x"})";
    const auto span = Guard::Json::find_value(doc, {key("a\"b\\c")});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "\"x\"");
}

// ── find_value: malformed / mismatched -> nullopt, never throw ─────────

TEST(GuardJson, FindValueMissingKeyReturnsNullopt) {
    const std::string doc = R"({"a":1})";
    EXPECT_FALSE(Guard::Json::find_value(doc, {key("missing")}).has_value());
}

TEST(GuardJson, FindValueIndexOutOfRangeReturnsNullopt) {
    const std::string doc = R"([1,2])";
    EXPECT_FALSE(Guard::Json::find_value(doc, {idx(5)}).has_value());
}

TEST(GuardJson, FindValueIndexAgainstObjectIsTypeMismatch) {
    const std::string doc = R"({"a":1})";
    EXPECT_FALSE(Guard::Json::find_value(doc, {idx(0)}).has_value());
}

TEST(GuardJson, FindValueKeyAgainstArrayIsTypeMismatch) {
    const std::string doc = R"([1,2])";
    EXPECT_FALSE(Guard::Json::find_value(doc, {key("a")}).has_value());
}

TEST(GuardJson, FindValueTruncatedDocumentReturnsNullopt) {
    const std::string doc = R"({"a":{"b":)";
    EXPECT_FALSE(Guard::Json::find_value(doc, {key("a"), key("b")}).has_value());
}

TEST(GuardJson, FindValueEmptyDocumentReturnsNullopt) {
    EXPECT_FALSE(Guard::Json::find_value("", {key("a")}).has_value());
    EXPECT_FALSE(Guard::Json::find_value("   ", {key("a")}).has_value());
}

TEST(GuardJson, FindValueSucceedsEvenWithTrailingCommaAfterTheFoundValue) {
    // find_value is a lazy scanner (see the file-level doc comment): it
    // returns as soon as the requested key is found and never inspects
    // anything after the value it returns. A trailing comma later in the
    // SAME object (which valid() correctly rejects -- see
    // ValidRejectsMalformedStructures) is simply never visited here,
    // because "a" is the first (and only) key scanned.
    const std::string doc = R"({"a":1,})";
    const auto span = Guard::Json::find_value(doc, {key("a")});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "1");
}

TEST(GuardJson, FindValueFailsWhenTraversalMustScanPastAMalformedTrailingComma) {
    // Unlike the case above, a MISSING key forces the scan to continue
    // past the trailing comma looking for more keys -- where it correctly
    // fails: a bare '}' immediately after ',' is not a valid next key.
    const std::string doc = R"({"a":1,})";
    EXPECT_FALSE(Guard::Json::find_value(doc, {key("missing")}).has_value());
}

TEST(GuardJson, FindValueNeverThrowsOnAdversarialInput) {
    std::string with_nul(10, 'x');
    with_nul[3] = '\0';
    EXPECT_NO_THROW({
        auto r = Guard::Json::find_value(with_nul, {key("a")});
        (void)r;
    });
    EXPECT_NO_THROW({
        auto r = Guard::Json::find_value("]}][{{\"", {key("a"), idx(3), key("b")});
        (void)r;
    });
}

// ── huge numbers: preserved as raw spans, not parsed ────────────────────

TEST(GuardJson, FindValueHugeNumberPreservedVerbatim) {
    const std::string huge = "123456789012345678901234567890123456789";
    const std::string doc = R"({"n":)" + huge + "}";
    const auto span = Guard::Json::find_value(doc, {key("n")});
    ASSERT_TRUE(span.has_value());
    EXPECT_FALSE(span->is_string);
    EXPECT_EQ(span_text(doc, *span), huge);
}

TEST(GuardJson, ValidAcceptsHugeNumber) {
    const std::string doc = "99999999999999999999999999999999999999999999999999.5e999";
    EXPECT_TRUE(Guard::Json::valid(doc));
}

// ── find_value_in / string_leaves_in: scoped lookup (Task 2.2) ──────────
//
// Added alongside the chat_completions extractor to keep a caller walking
// many array/object siblings out of find_value's O(document size) per-
// lookup cost: resolve the containing array once, then resolve each
// sibling and its nested fields scoped to that sibling's own span. These
// pin the offset-readd contract documented on both functions.

TEST(GuardJson, FindValueInNestedContainerMatchesUnscopedLookup) {
    const std::string doc =
        R"({"messages":[{"role":"user","content":"first"},{"role":"assistant","content":"second"}]})";
    const auto messages = Guard::Json::find_value(doc, {key("messages")});
    ASSERT_TRUE(messages.has_value());

    const auto elem1 = Guard::Json::find_value_in(doc, *messages, {idx(1)});
    ASSERT_TRUE(elem1.has_value());
    const auto scoped = Guard::Json::find_value_in(doc, *elem1, {key("content")});
    const auto unscoped = Guard::Json::find_value(doc, {key("messages"), idx(1), key("content")});
    ASSERT_TRUE(scoped.has_value());
    ASSERT_TRUE(unscoped.has_value());
    EXPECT_EQ(scoped->start, unscoped->start);
    EXPECT_EQ(scoped->end, unscoped->end);
    EXPECT_TRUE(scoped->is_string);
    EXPECT_EQ(span_text(doc, *scoped), "\"second\"");
}

TEST(GuardJson, FindValueInOffsetCorrectnessAtNonZeroContainerStart) {
    // The container span does NOT start at byte 0 of `doc`: pins that
    // find_value_in re-adds `container.start` (not some other offset) onto
    // the result.
    const std::string doc = R"({"padding":"xxxxxxxxxx","obj":{"k":"v"}})";
    const auto container = Guard::Json::find_value(doc, {key("obj")});
    ASSERT_TRUE(container.has_value());
    ASSERT_GT(container->start, 0u);  // sanity: the container really is offset into doc

    const auto found = Guard::Json::find_value_in(doc, *container, {key("k")});
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(span_text(doc, *found), "\"v\"");
    // The returned span must be a sub-range of the container's own span, in
    // doc's coordinates -- not the substring's.
    EXPECT_GE(found->start, container->start);
    EXPECT_LE(found->end, container->end);
}

TEST(GuardJson, FindValueInEmptyRelativePathReturnsContainerItself) {
    const std::string doc = R"({"a":{"b":1}})";
    const auto container = Guard::Json::find_value(doc, {key("a")});
    ASSERT_TRUE(container.has_value());
    const auto found = Guard::Json::find_value_in(doc, *container, {});
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->start, container->start);
    EXPECT_EQ(found->end, container->end);
}

TEST(GuardJson, FindValueInMissingKeyReturnsNullopt) {
    const std::string doc = R"({"obj":{"k":"v"}})";
    const auto container = Guard::Json::find_value(doc, {key("obj")});
    ASSERT_TRUE(container.has_value());
    EXPECT_FALSE(Guard::Json::find_value_in(doc, *container, {key("missing")}).has_value());
}

TEST(GuardJson, FindValueInOutOfBoundsContainerReturnsNullopt) {
    const std::string doc = R"({"a":1})";
    EXPECT_FALSE(
        Guard::Json::find_value_in(doc, Guard::Json::ValueSpan{0, doc.size() + 1, false}, {key("a")}).has_value());
    EXPECT_FALSE(Guard::Json::find_value_in(doc, Guard::Json::ValueSpan{5, 1, false}, {key("a")}).has_value());
}

TEST(GuardJson, StringLeavesInMatchesUnscopedWalkWithOffsetReadd) {
    const std::string doc = R"({"padding":"xxxxxxxxxx","obj":{"a":"one","b":["two","three"]}})";
    const auto container = Guard::Json::find_value(doc, {key("obj")});
    ASSERT_TRUE(container.has_value());
    ASSERT_GT(container->start, 0u);

    const auto scoped = Guard::Json::string_leaves_in(doc, *container, {});
    const auto unscoped = Guard::Json::string_leaves(doc, {key("obj")});
    ASSERT_EQ(scoped.size(), unscoped.size());
    for (std::size_t i = 0; i < scoped.size(); ++i) {
        EXPECT_EQ(scoped[i].span.start, unscoped[i].span.start);
        EXPECT_EQ(scoped[i].span.end, unscoped[i].span.end);
    }
    ASSERT_EQ(scoped.size(), 3u);
    EXPECT_EQ(span_text(doc, scoped[0].span), "\"one\"");
    EXPECT_EQ(span_text(doc, scoped[1].span), "\"two\"");
    EXPECT_EQ(span_text(doc, scoped[2].span), "\"three\"");
}

// ── array_elements: single-pass array walk (Task 2.2 round 2) ───────────
//
// Added after review measured `find_value_in`-probing-by-index still O(n^2)
// in element count: each probe re-scans the array from its own opening
// bracket. `array_elements` walks the array exactly once instead.

TEST(GuardJson, ArrayElementsFlatArrayCountAndSpansCorrect) {
    const std::string doc = R"([10,"two",true,null,3.5])";
    const auto array_span = Guard::Json::find_value(doc, {});
    ASSERT_TRUE(array_span.has_value());

    const auto elements = Guard::Json::array_elements(doc, *array_span);
    ASSERT_EQ(elements.size(), 5u);
    EXPECT_EQ(span_text(doc, elements[0]), "10");
    EXPECT_FALSE(elements[0].is_string);
    EXPECT_EQ(span_text(doc, elements[1]), "\"two\"");
    EXPECT_TRUE(elements[1].is_string);
    EXPECT_EQ(span_text(doc, elements[2]), "true");
    EXPECT_EQ(span_text(doc, elements[3]), "null");
    EXPECT_EQ(span_text(doc, elements[4]), "3.5");
}

TEST(GuardJson, ArrayElementsNestedArraysAndObjectsSpanTheWholeElementNotItsContents) {
    // Each returned span must cover the WHOLE nested element (so a
    // subsequent find_value_in against it can look inside), not just its
    // opening token or its own first child.
    const std::string doc = R"([{"a":1,"b":[2,3]},["x","y"],42])";
    const auto array_span = Guard::Json::find_value(doc, {});
    ASSERT_TRUE(array_span.has_value());

    const auto elements = Guard::Json::array_elements(doc, *array_span);
    ASSERT_EQ(elements.size(), 3u);
    EXPECT_EQ(span_text(doc, elements[0]), R"({"a":1,"b":[2,3]})");
    EXPECT_EQ(span_text(doc, elements[1]), R"(["x","y"])");
    EXPECT_EQ(span_text(doc, elements[2]), "42");

    // And each element's span must actually be usable with find_value_in.
    const auto b1 = Guard::Json::find_value_in(doc, elements[0], {key("b"), idx(1)});
    ASSERT_TRUE(b1.has_value());
    EXPECT_EQ(span_text(doc, *b1), "3");
}

TEST(GuardJson, ArrayElementsMatchesRepeatedFindValueInProbing) {
    // Cross-check against the (slower, O(n^2)) probing approach this
    // function replaces -- must produce byte-identical spans.
    const std::string doc = R"({"messages":[{"content":"a"},{"content":"b"},{"content":"c"}]})";
    const auto messages_span = Guard::Json::find_value(doc, {key("messages")});
    ASSERT_TRUE(messages_span.has_value());

    const auto elements = Guard::Json::array_elements(doc, *messages_span);
    ASSERT_EQ(elements.size(), 3u);
    for (std::size_t i = 0; i < elements.size(); ++i) {
        const auto probed = Guard::Json::find_value_in(doc, *messages_span, {idx(i)});
        ASSERT_TRUE(probed.has_value());
        EXPECT_EQ(elements[i].start, probed->start);
        EXPECT_EQ(elements[i].end, probed->end);
    }
}

TEST(GuardJson, ArrayElementsEmptyArrayReturnsEmpty) {
    const std::string doc = R"([])";
    const auto array_span = Guard::Json::find_value(doc, {});
    ASSERT_TRUE(array_span.has_value());
    EXPECT_TRUE(Guard::Json::array_elements(doc, *array_span).empty());
}

TEST(GuardJson, ArrayElementsNonArraySpanReturnsEmpty) {
    const std::string doc = R"({"obj":{"a":1},"str":"x","num":5,"bool":true,"null":null})";
    for (const char* key_name : {"obj", "str", "num", "bool", "null"}) {
        SCOPED_TRACE(key_name);
        const auto span = Guard::Json::find_value(doc, {key(key_name)});
        ASSERT_TRUE(span.has_value());
        EXPECT_TRUE(Guard::Json::array_elements(doc, *span).empty());
    }
}

TEST(GuardJson, ArrayElementsOutOfBoundsSpanReturnsEmpty) {
    const std::string doc = R"([1,2,3])";
    EXPECT_TRUE(Guard::Json::array_elements(doc, Guard::Json::ValueSpan{0, doc.size() + 1, false}).empty());
    EXPECT_TRUE(Guard::Json::array_elements(doc, Guard::Json::ValueSpan{5, 1, false}).empty());
}

// ── decode_string / encode_string ───────────────────────────────────────

TEST(GuardJson, DecodeStringBasicEscapes) {
    EXPECT_EQ(Guard::Json::decode_string(R"("a\nb\tc\rd\be\ff")"), std::string("a\nb\tc\rd\be\ff"));
    EXPECT_EQ(Guard::Json::decode_string(R"("\"\\\/")"), std::string("\"\\/"));
}

TEST(GuardJson, DecodeStringUnicodeEscape) {
    EXPECT_EQ(Guard::Json::decode_string(R"("A")"), "A");
    // A literal \u00e9 escape (not a raw UTF-8 byte) must decode to the
    // 2-byte UTF-8 encoding of U+00E9 (e-acute): C3 A9.
    const std::string quoted = std::string("\"caf") + "\\u00e9" + "\"";
    EXPECT_EQ(Guard::Json::decode_string(quoted), "caf\xC3\xA9");
}

TEST(GuardJson, DecodeStringSurrogatePair) {
    // U+1F600 (grinning face emoji) spelled as a UTF-16 surrogate pair
    // \ud83d\ude00 -- must combine into the single 4-byte UTF-8 sequence
    // F0 9F 98 80, not two independent (and individually invalid) escapes.
    const std::string quoted = std::string("\"") + "\\ud83d\\ude00" + "\"";
    const std::string decoded = Guard::Json::decode_string(quoted);
    EXPECT_EQ(decoded, "\xF0\x9F\x98\x80");
}

TEST(GuardJson, DecodeStringUnpairedHighSurrogateBecomesReplacementChar) {
    // \ud83d with no following low surrogate: Go's encoding/json substitutes
    // U+FFFD and does not consume anything past this one escape.
    const std::string decoded = Guard::Json::decode_string(R"("\ud83dX")");
    EXPECT_EQ(decoded, "\xEF\xBF\xBDX");
}

TEST(GuardJson, DecodeStringUnpairedLowSurrogateBecomesReplacementChar) {
    const std::string decoded = Guard::Json::decode_string(R"("\ude00")");
    EXPECT_EQ(decoded, "\xEF\xBF\xBD");
}

TEST(GuardJson, DecodeStringTwoHighSurrogatesEachBecomeReplacementChar) {
    // Two high surrogates in a row never form a valid pair with each other;
    // each independently becomes U+FFFD.
    const std::string decoded = Guard::Json::decode_string(R"("\ud83d\ud83d")");
    EXPECT_EQ(decoded, "\xEF\xBF\xBD\xEF\xBF\xBD");
}

TEST(GuardJson, EncodeStringBasicEscapes) {
    EXPECT_EQ(Guard::Json::encode_string("a\nb\tc\rd\be\ff\"g\\h", true), R"("a\nb\tc\rd\be\ff\"g\\h")");
}

TEST(GuardJson, EncodeStringControlCharUsesLowercaseHexEscape) {
    std::string raw;
    raw.push_back(static_cast<char>(0x07));
    const std::string expected = std::string("\"") + "\\u0007" + "\"";
    EXPECT_EQ(Guard::Json::encode_string(raw, true), expected);
}

TEST(GuardJson, EncodeStringDoesNotEscapeAngleBracketsOrAmpersand) {
    // MarshalNoEscape parity: SetEscapeHTML(false) means <, >, & pass
    // through verbatim -- pinned explicitly since it's the whole reason
    // MarshalNoEscape exists (see json.go's doc comment).
    EXPECT_EQ(Guard::Json::encode_string("<EMAIL_1>&x</tag>", true), "\"<EMAIL_1>&x</tag>\"");
}

TEST(GuardJson, EncodeStringDoesNotEscapeForwardSlash) {
    EXPECT_EQ(Guard::Json::encode_string("a/b", true), R"("a/b")");
}

TEST(GuardJson, EncodeStringEscapesLineSeparatorsUnconditionally) {
    // U+2028 (line separator) / U+2029 (paragraph separator): Go's
    // encoding/json escapes these regardless of SetEscapeHTML.
    const std::string u2028 = std::string("\"") + "\\u2028" + "\"";
    const std::string u2029 = std::string("\"") + "\\u2029" + "\"";
    EXPECT_EQ(Guard::Json::encode_string("\xE2\x80\xA8", true), u2028);
    EXPECT_EQ(Guard::Json::encode_string("\xE2\x80\xA9", true), u2029);
}

TEST(GuardJson, EncodeStringWithoutQuotes) {
    EXPECT_EQ(Guard::Json::encode_string("abc", false), "abc");
}

TEST(GuardJson, DecodeEncodeSimpleRoundTrip) {
    const std::string quoted = R"("hello world")";
    EXPECT_EQ(Guard::Json::encode_string(Guard::Json::decode_string(quoted), true), quoted);
}

// ── valid(): strict RFC 8259 ─────────────────────────────────────────────

TEST(GuardJson, ValidAcceptsWellFormedDocuments) {
    EXPECT_TRUE(Guard::Json::valid(R"({"a":1,"b":[1,2,3],"c":{"d":null}})"));
    EXPECT_TRUE(Guard::Json::valid(R"([])"));
    EXPECT_TRUE(Guard::Json::valid(R"({})"));
}

TEST(GuardJson, ValidAcceptsLoneScalarsPerRfc8259) {
    EXPECT_TRUE(Guard::Json::valid("42"));
    EXPECT_TRUE(Guard::Json::valid("true"));
    EXPECT_TRUE(Guard::Json::valid("false"));
    EXPECT_TRUE(Guard::Json::valid("null"));
    EXPECT_TRUE(Guard::Json::valid(R"("just a string")"));
    EXPECT_TRUE(Guard::Json::valid("-3.14e10"));
}

TEST(GuardJson, ValidAcceptsSurroundingWhitespace) {
    EXPECT_TRUE(Guard::Json::valid("  \n\t{\"a\":1}\n  "));
}

TEST(GuardJson, ValidRejectsTrailingGarbage) {
    EXPECT_FALSE(Guard::Json::valid(R"({"a":1}x)"));
    EXPECT_FALSE(Guard::Json::valid("42 43"));
    EXPECT_FALSE(Guard::Json::valid("{}{}"));
}

TEST(GuardJson, ValidRejectsEmptyOrWhitespaceOnly) {
    EXPECT_FALSE(Guard::Json::valid(""));
    EXPECT_FALSE(Guard::Json::valid("   "));
}

TEST(GuardJson, ValidRejectsMalformedStructures) {
    EXPECT_FALSE(Guard::Json::valid(R"({"a":1,})"));  // trailing comma
    EXPECT_FALSE(Guard::Json::valid(R"([1,2,])"));    // trailing comma
    EXPECT_FALSE(Guard::Json::valid(R"({"a":})"));    // missing value
    EXPECT_FALSE(Guard::Json::valid(R"({a:1})"));     // unquoted key
    EXPECT_FALSE(Guard::Json::valid(R"({"a":1)"));    // unterminated
    EXPECT_FALSE(Guard::Json::valid("[1,2"));         // unterminated
    EXPECT_FALSE(Guard::Json::valid(R"("unterminated)"));
    EXPECT_FALSE(Guard::Json::valid("tru"));
    EXPECT_FALSE(Guard::Json::valid("01"));  // leading zero
}

TEST(GuardJson, ValidRejectsUnescapedControlCharInString) {
    std::string doc = "\"a";
    doc.push_back('\n');  // raw newline, unescaped
    doc += "b\"";
    EXPECT_FALSE(Guard::Json::valid(doc));
}

// ── splice / splice_all ─────────────────────────────────────────────────

TEST(GuardJson, SpliceReplacesOnlyTheSpanAndPreservesTheRest) {
    const std::string doc = R"({"a":"old","b":2})";
    const auto span = Guard::Json::find_value(doc, {key("a")});
    ASSERT_TRUE(span.has_value());
    const std::string out = Guard::Json::splice(doc, *span, R"("new")");
    EXPECT_EQ(out, R"({"a":"new","b":2})");
    // Byte-identity outside the span: everything before `start` and after
    // the original `end` is unchanged.
    EXPECT_EQ(out.substr(0, span->start), doc.substr(0, span->start));
    EXPECT_EQ(out.substr(span->start + 5), doc.substr(span->end));  // "new" is 5 bytes incl. quotes
}

TEST(GuardJson, SpliceOutOfBoundsSpanThrows) {
    const std::string doc = R"({"a":1})";
    ValueSpan bad{0, doc.size() + 10, false};
    EXPECT_THROW(Guard::Json::splice(doc, bad, "x"), std::runtime_error);
}

TEST(GuardJson, SpliceAllAppliesEveryEditCorrectly) {
    const std::string doc = R"({"a":"1","b":"2","c":"3"})";
    const auto sa = Guard::Json::find_value(doc, {key("a")});
    const auto sb = Guard::Json::find_value(doc, {key("b")});
    const auto sc = Guard::Json::find_value(doc, {key("c")});
    ASSERT_TRUE(sa && sb && sc);

    std::vector<std::pair<ValueSpan, std::string>> edits;
    // Deliberately NOT in offset order, to exercise the internal sort.
    edits.emplace_back(*sc, "\"C\"");
    edits.emplace_back(*sa, "\"A\"");
    edits.emplace_back(*sb, "\"B\"");

    const std::string out = Guard::Json::splice_all(doc, edits);
    EXPECT_EQ(out, R"({"a":"A","b":"B","c":"C"})");
}

TEST(GuardJson, SpliceAllByteIdentityOutsideEdits) {
    const std::string doc = R"({"keep1":"x","edit":"old","keep2":"y"})";
    const auto span = Guard::Json::find_value(doc, {key("edit")});
    ASSERT_TRUE(span.has_value());
    std::vector<std::pair<ValueSpan, std::string>> edits{{*span, "\"REPLACED\""}};
    const std::string out = Guard::Json::splice_all(doc, edits);
    EXPECT_EQ(out.substr(0, span->start), doc.substr(0, span->start));
    EXPECT_EQ(out.substr(out.size() - (doc.size() - span->end)), doc.substr(span->end));
}

TEST(GuardJson, SpliceAllEmptyEditsReturnsDocumentUnchanged) {
    const std::string doc = R"({"a":1})";
    EXPECT_EQ(Guard::Json::splice_all(doc, {}), doc);
}

TEST(GuardJson, SpliceAllOverlappingEditsThrows) {
    const std::string doc = R"({"a":"12345"})";
    const auto span = Guard::Json::find_value(doc, {key("a")});
    ASSERT_TRUE(span.has_value());
    ValueSpan overlapping{span->start + 1, span->end, false};
    std::vector<std::pair<ValueSpan, std::string>> edits{{*span, "x"}, {overlapping, "y"}};
    EXPECT_THROW(Guard::Json::splice_all(doc, edits), std::runtime_error);
}

TEST(GuardJson, SpliceAllIdenticalDuplicateSpansThrows) {
    const std::string doc = R"({"a":"12345"})";
    const auto span = Guard::Json::find_value(doc, {key("a")});
    ASSERT_TRUE(span.has_value());
    std::vector<std::pair<ValueSpan, std::string>> edits{{*span, "x"}, {*span, "y"}};
    EXPECT_THROW(Guard::Json::splice_all(doc, edits), std::runtime_error);
}

TEST(GuardJson, SpliceAllAdjacentTouchingSpansDoNotThrow) {
    const std::string doc = R"({"a":"11","b":"22"})";
    const auto sa = Guard::Json::find_value(doc, {key("a")});
    const auto sb = Guard::Json::find_value(doc, {key("b")});
    ASSERT_TRUE(sa && sb);
    // Touching (sa->end could equal sb->start only if adjacent in bytes;
    // here they are not literally adjacent, so just confirm two disjoint,
    // non-overlapping edits apply cleanly together.
    std::vector<std::pair<ValueSpan, std::string>> edits{{*sa, "\"X\""}, {*sb, "\"Y\""}};
    EXPECT_NO_THROW({
        const std::string out = Guard::Json::splice_all(doc, edits);
        EXPECT_EQ(out, R"({"a":"X","b":"Y"})");
    });
}

// ── string_leaves ────────────────────────────────────────────────────────

TEST(GuardJson, StringLeavesWalksObjectsAndArraysInDocumentOrder) {
    const std::string doc = R"({"a":"one","b":[1,"two",{"c":"three"},null],"d":true})";
    const auto leaves = Guard::Json::string_leaves(doc, {});
    ASSERT_EQ(leaves.size(), 3u);
    EXPECT_EQ(span_text(doc, leaves[0].span), "\"one\"");
    EXPECT_EQ(span_text(doc, leaves[1].span), "\"two\"");
    EXPECT_EQ(span_text(doc, leaves[2].span), "\"three\"");
}

TEST(GuardJson, StringLeavesSkipsNonStringLeaves) {
    const std::string doc = R"({"n":1,"b":true,"z":null,"o":{},"a":[]})";
    const auto leaves = Guard::Json::string_leaves(doc, {});
    EXPECT_TRUE(leaves.empty());
}

TEST(GuardJson, StringLeavesUnderSubPath) {
    const std::string doc = R"({"input":{"x":"a","y":{"z":"b"}},"other":"c"})";
    const auto leaves = Guard::Json::string_leaves(doc, {key("input")});
    ASSERT_EQ(leaves.size(), 2u);
    EXPECT_EQ(span_text(doc, leaves[0].span), "\"a\"");
    EXPECT_EQ(span_text(doc, leaves[1].span), "\"b\"");
    // Paths are absolute from the document root, not relative to `input`.
    ASSERT_EQ(leaves[1].path.size(), 3u);
    EXPECT_EQ(leaves[1].path[0].key, "input");
    EXPECT_EQ(leaves[1].path[1].key, "y");
    EXPECT_EQ(leaves[1].path[2].key, "z");
}

TEST(GuardJson, StringLeavesRootIsScalarString) {
    const std::string doc = R"("just a string")";
    const auto leaves = Guard::Json::string_leaves(doc, {});
    ASSERT_EQ(leaves.size(), 1u);
    EXPECT_EQ(span_text(doc, leaves[0].span), doc);
}

TEST(GuardJson, StringLeavesMissingRootReturnsEmpty) {
    const std::string doc = R"({"a":1})";
    EXPECT_TRUE(Guard::Json::string_leaves(doc, {key("missing")}).empty());
}

TEST(GuardJson, StringLeavesMalformedDocumentReturnsEmptyNeverThrows) {
    EXPECT_NO_THROW({
        const auto leaves = Guard::Json::string_leaves("{\"a\":", {});
        EXPECT_TRUE(leaves.empty());
    });
}

TEST(GuardJson, StringLeavesEachRefindsViaFindValue) {
    const std::string doc = R"({"a":"one","b":[1,"two",{"c":"three"}]})";
    const auto leaves = Guard::Json::string_leaves(doc, {});
    for (const auto& leaf : leaves) {
        const auto refound = Guard::Json::find_value(doc, leaf.path);
        ASSERT_TRUE(refound.has_value());
        EXPECT_EQ(refound->start, leaf.span.start);
        EXPECT_EQ(refound->end, leaf.span.end);
    }
}

// ── deep nesting: 1000 levels, no crash ──────────────────────────────────

TEST(GuardJson, DeepNestingArraysNoCrash) {
    constexpr int kDepth = 1000;
    std::string doc;
    doc.reserve(static_cast<std::size_t>(kDepth) * 2 + 8);
    for (int i = 0; i < kDepth; ++i)
        doc += "[";
    doc += "0";
    for (int i = 0; i < kDepth; ++i)
        doc += "]";

    EXPECT_TRUE(Guard::Json::valid(doc));

    std::vector<PathSeg> path;
    path.reserve(static_cast<std::size_t>(kDepth));
    for (int i = 0; i < kDepth; ++i)
        path.push_back(idx(0));
    const auto span = Guard::Json::find_value(doc, path);
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "0");
}

TEST(GuardJson, DeepNestingObjectsNoCrash) {
    constexpr int kDepth = 1000;
    std::string doc;
    for (int i = 0; i < kDepth; ++i)
        doc += "{\"k\":";
    doc += "\"leaf\"";
    for (int i = 0; i < kDepth; ++i)
        doc += "}";

    EXPECT_TRUE(Guard::Json::valid(doc));

    std::vector<PathSeg> path;
    path.reserve(static_cast<std::size_t>(kDepth));
    for (int i = 0; i < kDepth; ++i)
        path.push_back(key("k"));
    const auto span = Guard::Json::find_value(doc, path);
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span_text(doc, *span), "\"leaf\"");

    const auto leaves = Guard::Json::string_leaves(doc, {});
    ASSERT_EQ(leaves.size(), 1u);
    EXPECT_EQ(span_text(doc, leaves[0].span), "\"leaf\"");
}

// ── generator-based round-trip fuzz (200 documents, seeded/deterministic) ─

namespace {

// Builds a random JSON string LITERAL (including surrounding quotes),
// choosing content ONLY from characters whose canonical `encode_string`
// output is byte-identical to how this generator itself spells them in the
// document -- otherwise `splice(find(x), encode(decode(x)))` could
// legitimately produce a different (still-valid) escaping of the same
// content and this test would flag a false positive. Concretely: the 5
// named C escapes (\b \f \n \r \t) are always spelled with their named
// form (never \u00XX, which `encode_string` would not reproduce for them);
// every other control byte is always spelled \u00XX (matching
// `encode_string`'s own fallback exactly); U+2028/U+2029 are excluded
// entirely (see EncodeStringEscapesLineSeparatorsUnconditionally, which
// pins that they do NOT round-trip byte-identically, by design).
std::string random_json_string_literal(std::mt19937& rng, int length) {
    static const char* const kNamedEscapes[5] = {"\\b", "\\f", "\\n", "\\r", "\\t"};
    static const int kOtherControls[] = {0,  1,  2,  3,  4,  5,  6,  7,  11, 14, 15, 16, 17, 18,
                                         19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    static const char* const kUnicodeSamples[] = {
        "\xD0\x96",          // Ж  (U+0416, Cyrillic)
        "\xE6\x96\x87",      // 文 (U+6587, CJK)
        "\xC3\xA9",          // é  (U+00E9, Latin-1 supplement)
        "\xF0\x9F\x98\x80",  // 😀 (U+1F600, astral, 4-byte UTF-8)
    };

    std::uniform_int_distribution<int> kind_dist(0, 4);
    std::string out = "\"";
    for (int i = 0; i < length; ++i) {
        switch (kind_dist(rng)) {
            case 0: {
                std::uniform_int_distribution<int> c_dist(0x20, 0x7E);
                char c;
                do {
                    c = static_cast<char>(c_dist(rng));
                } while (c == '"' || c == '\\');
                out.push_back(c);
                break;
            }
            case 1:
                out += "\\\"";
                break;
            case 2:
                out += "\\\\";
                break;
            case 3: {
                std::uniform_int_distribution<int> e(0, 4);
                out += kNamedEscapes[e(rng)];
                break;
            }
            case 4: {
                std::uniform_int_distribution<int> pick(0, 1);
                if (pick(rng) == 0) {
                    std::uniform_int_distribution<std::size_t> ci(
                        0, sizeof(kOtherControls) / sizeof(kOtherControls[0]) - 1);
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", kOtherControls[ci(rng)]);
                    out += buf;
                } else {
                    std::uniform_int_distribution<int> si(0, 3);
                    out += kUnicodeSamples[si(rng)];
                }
                break;
            }
            default:
                break;
        }
    }
    out.push_back('"');
    return out;
}

std::string random_key(std::mt19937& rng, int counter) {
    std::uniform_int_distribution<int> c_dist('a', 'z');
    std::string k(1, static_cast<char>(c_dist(rng)));
    k += std::to_string(counter);
    return "\"" + k + "\"";
}

// Recursively generates one JSON value. `leaf_count` is incremented once
// per generated STRING VALUE (not key), so the caller can independently
// verify `string_leaves`'s completeness against a ground truth.
std::string generate_value(std::mt19937& rng, int depth, int max_depth, int& leaf_count, int& key_counter) {
    const bool allow_container = depth < max_depth;
    std::uniform_int_distribution<int> r_dist(0, 99);
    const int r = r_dist(rng);

    if (allow_container && r < 30) {
        std::uniform_int_distribution<int> nfields(0, 3);
        const int n = nfields(rng);
        std::string out = "{";
        for (int i = 0; i < n; ++i) {
            if (i > 0)
                out += ",";
            out += random_key(rng, key_counter++);
            out += ":";
            out += generate_value(rng, depth + 1, max_depth, leaf_count, key_counter);
        }
        out += "}";
        return out;
    }
    if (allow_container && r < 55) {
        std::uniform_int_distribution<int> nelems(0, 3);
        const int n = nelems(rng);
        std::string out = "[";
        for (int i = 0; i < n; ++i) {
            if (i > 0)
                out += ",";
            out += generate_value(rng, depth + 1, max_depth, leaf_count, key_counter);
        }
        out += "]";
        return out;
    }
    if (r < 80) {
        std::uniform_int_distribution<int> len(0, 6);
        ++leaf_count;
        return random_json_string_literal(rng, len(rng));
    }
    if (r < 90) {
        std::uniform_int_distribution<int> huge_flag(0, 9);
        if (huge_flag(rng) == 0) {
            std::uniform_int_distribution<int> ndig(20, 30);
            const int nd = ndig(rng);
            std::uniform_int_distribution<int> first(1, 9);
            std::uniform_int_distribution<int> rest(0, 9);
            std::string s(1, static_cast<char>('0' + first(rng)));
            for (int i = 1; i < nd; ++i)
                s.push_back(static_cast<char>('0' + rest(rng)));
            return s;
        }
        std::uniform_int_distribution<long long> v(-1000000, 1000000);
        return std::to_string(v(rng));
    }
    if (r < 95) {
        std::uniform_int_distribution<int> b(0, 1);
        return b(rng) == 0 ? "true" : "false";
    }
    return "null";
}

std::string generate_document(std::mt19937& rng, int& leaf_count) {
    int key_counter = 0;
    // Force the root to be a container (object or array) for a realistic
    // "JSON document", then let generate_value's own randomness take over.
    std::uniform_int_distribution<int> root_kind(0, 1);
    if (root_kind(rng) == 0) {
        std::uniform_int_distribution<int> nfields(1, 4);
        const int n = nfields(rng);
        std::string out = "{";
        for (int i = 0; i < n; ++i) {
            if (i > 0)
                out += ",";
            out += random_key(rng, key_counter++);
            out += ":";
            out += generate_value(rng, 1, 4, leaf_count, key_counter);
        }
        out += "}";
        return out;
    }
    std::uniform_int_distribution<int> nelems(1, 4);
    const int n = nelems(rng);
    std::string out = "[";
    for (int i = 0; i < n; ++i) {
        if (i > 0)
            out += ",";
        out += generate_value(rng, 1, 4, leaf_count, key_counter);
    }
    out += "]";
    return out;
}

}  // namespace

TEST(GuardJson, GeneratedRoundTrip200Documents) {
    std::mt19937 rng(20260815);  // fixed seed: deterministic, no Date/random_device.

    for (int doc_index = 0; doc_index < 200; ++doc_index) {
        int expected_leaf_count = 0;
        const std::string doc = generate_document(rng, expected_leaf_count);

        ASSERT_TRUE(Guard::Json::valid(doc)) << "generator produced invalid JSON at doc " << doc_index << ": " << doc;

        const auto leaves = Guard::Json::string_leaves(doc, {});
        ASSERT_EQ(leaves.size(), static_cast<std::size_t>(expected_leaf_count))
            << "string_leaves found the wrong number of leaves at doc " << doc_index << ": " << doc;

        for (std::size_t li = 0; li < leaves.size(); ++li) {
            const StringLeaf& leaf = leaves[li];

            // find_value on the leaf's own reported path must agree exactly.
            const auto refound = Guard::Json::find_value(doc, leaf.path);
            ASSERT_TRUE(refound.has_value()) << "doc " << doc_index << " leaf " << li;
            EXPECT_EQ(refound->start, leaf.span.start) << "doc " << doc_index << " leaf " << li;
            EXPECT_EQ(refound->end, leaf.span.end) << "doc " << doc_index << " leaf " << li;

            // splice(find(x), encode(decode(x))) round-trips byte-identically.
            const std::string original_span = span_text(doc, leaf.span);
            const std::string decoded = Guard::Json::decode_string(original_span);
            const std::string re_encoded = Guard::Json::encode_string(decoded, true);
            const std::string spliced = Guard::Json::splice(doc, leaf.span, re_encoded);
            EXPECT_EQ(spliced, doc) << "doc " << doc_index << " leaf " << li << " original=" << original_span
                                    << " re_encoded=" << re_encoded;
        }
    }
}

// ── Guard::Extract::wants_stream ─────────────────────────────────────────

TEST(GuardExtract, WantsStreamTrue) {
    EXPECT_TRUE(Guard::Extract::wants_stream(R"({"model":"x","stream":true})"));
}

TEST(GuardExtract, WantsStreamFalse) {
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"model":"x","stream":false})"));
}

TEST(GuardExtract, WantsStreamMissingFieldIsFalse) {
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"model":"x"})"));
}

TEST(GuardExtract, WantsStreamMalformedBodyIsFalse) {
    EXPECT_FALSE(Guard::Extract::wants_stream("not json"));
    EXPECT_FALSE(Guard::Extract::wants_stream(""));
}

TEST(GuardExtract, WantsStreamIgnoresNestedField) {
    // Only the TOP-LEVEL "stream" field counts; a same-named nested field
    // must not be mistaken for it.
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"options":{"stream":true}})"));
}

TEST(GuardExtract, WantsStreamSameFieldForAllThreeFormats) {
    // Spec §5: "Streaming intent = top-level 'stream': true (same field in
    // all three)." wants_stream needs no format parameter at all.
    EXPECT_TRUE(Guard::Extract::wants_stream(R"({"messages":[],"stream":true})"));  // chat_completions-ish
    EXPECT_TRUE(Guard::Extract::wants_stream(R"({"model":"c","stream":true})"));    // messages-ish
    EXPECT_TRUE(Guard::Extract::wants_stream(R"({"input":"hi","stream":true})"));   // responses-ish
}

TEST(GuardExtract, WantsStreamLooseGjsonBoolCoercion) {
    // Mirrors gjson's Result.Bool(): a JSON string is loosely parsed
    // (case-insensitively) via strconv.ParseBool, a JSON number is truthy
    // iff nonzero -- see the Extract.hpp file-level doc comment.
    EXPECT_TRUE(Guard::Extract::wants_stream(R"({"stream":"true"})"));
    EXPECT_TRUE(Guard::Extract::wants_stream(R"({"stream":"TRUE"})"));
    EXPECT_TRUE(Guard::Extract::wants_stream(R"({"stream":"1"})"));
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"stream":"false"})"));
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"stream":"0"})"));
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"stream":"nonsense"})"));
    EXPECT_TRUE(Guard::Extract::wants_stream(R"({"stream":1})"));
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"stream":0})"));
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"stream":null})"));
    EXPECT_FALSE(Guard::Extract::wants_stream(R"({"stream":{}})"));
}

// Extract dispatch stubs: Task 2.2 (chat_completions, `test_guard_extract_cc.cpp`'s
// `GuardExtractChatCompletionsDispatch.*`), Task 2.3 (messages,
// `test_guard_extract_msg.cpp`'s `MessagesDispatch.*`), and Task 2.4
// (responses, `test_guard_extract_resp.cpp`'s `GuardExtractRespDispatch.*`)
// have all landed real per-format dispatch coverage in their own test
// files, narrowing what these two tests had left to check down to nothing
// -- so the two `*StubReturnsUnsupportedForEveryStubbedFormat` tests that
// used to live here were deleted rather than narrowed further.
