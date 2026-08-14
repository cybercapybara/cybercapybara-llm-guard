/**
 * @file test_guard_placeholder_regex.cpp
 * @brief Unit tests for Guard::build_placeholder_pattern / Guard::regex_max_len.
 *
 * Mirrors the Go reference's registry tests
 * (pkg/guardrails/regex/registry/registry_test.go):
 * TestRegistry_PlaceholderRegex and TestRegexpMaxLen, plus the tolerant
 * matching / escaping behavior described in phase1-interfaces.md and
 * task-1.4-brief.md for build_placeholder_pattern specifically.
 *
 * TestMaxRuneLenInClass_InvalidRuneFallsBackToUTFMax from the Go suite is
 * NOT ported: it feeds a synthetic out-of-Unicode-range rune directly to
 * the internal maxRuneLenInClass helper, a state RE2's own parser can never
 * produce from a textual pattern (Regexp::Parse rejects/clamps runes above
 * 0x10FFFF), so there is no way to reach that branch through the public
 * surface this file tests against.
 */

#include <cstddef>
#include <cstdint>
#include <string>

#include <gtest/gtest.h>
#include <re2/re2.h>

#include "guard/Errors.hpp"
#include "guard/PlaceholderRegex.hpp"

// ── build_placeholder_pattern: tolerant placeholder matching ────────────────

TEST(GuardPlaceholderRegex, EmailMatchesCanonicalPlaceholder) {
    auto p = Guard::build_placeholder_pattern("EMAIL");
    RE2 re(p.pattern);
    ASSERT_TRUE(re.ok()) << re.error();
    EXPECT_TRUE(RE2::PartialMatch("<EMAIL_1>", re));
}

TEST(GuardPlaceholderRegex, EmailIsTolerantToCaseSpaceAndSeparatorDrift) {
    auto p = Guard::build_placeholder_pattern("EMAIL");
    RE2 re(p.pattern);
    ASSERT_TRUE(re.ok()) << re.error();

    EXPECT_TRUE(RE2::PartialMatch("< email - 12 >", re));  // case, spaces, '-' vs '_'
    EXPECT_TRUE(RE2::PartialMatch("<EMAIL-1>", re));
    EXPECT_TRUE(RE2::PartialMatch("<eMaIl_1>", re));
    EXPECT_TRUE(RE2::PartialMatch("<  EMAIL   1  >", re));
}

TEST(GuardPlaceholderRegex, EmailWithoutNumberDoesNotMatch) {
    auto p = Guard::build_placeholder_pattern("EMAIL");
    RE2 re(p.pattern);
    ASSERT_TRUE(re.ok()) << re.error();

    EXPECT_FALSE(RE2::PartialMatch("<EMAIL>", re));
}

TEST(GuardPlaceholderRegex, EmailCapturesTheNumericIndex) {
    // Mirrors Go's TestRegistry_PlaceholderRegex email case: matches
    // "< eMaIl-002 >" with capture group 1 == "002".
    auto p = Guard::build_placeholder_pattern("EMAIL");
    RE2 re(p.pattern);
    ASSERT_TRUE(re.ok()) << re.error();
    ASSERT_EQ(re.NumberOfCapturingGroups(), 1);

    std::string number;
    ASSERT_TRUE(RE2::PartialMatch("before < eMaIl-002 > after", re, &number));
    EXPECT_EQ(number, "002");
}

TEST(GuardPlaceholderRegex, MultiTokenNameSplitsOnUnderscoreAndTolerates) {
    auto p = Guard::build_placeholder_pattern("DB_DSN");
    RE2 re(p.pattern);
    ASSERT_TRUE(re.ok()) << re.error();

    EXPECT_TRUE(RE2::PartialMatch("<DB_DSN_3>", re));
    EXPECT_TRUE(RE2::PartialMatch("<db-dsn-3>", re));
    EXPECT_TRUE(RE2::PartialMatch("<DB DSN 3>", re));
    EXPECT_TRUE(RE2::PartialMatch("<DBDSN3>", re));  // separators are optional (0..3)
}

TEST(GuardPlaceholderRegex, MultiTokenNameCapturesTheNumericIndex) {
    // Mirrors Go's TestRegistry_PlaceholderRegex ACCESS_TOKEN case: matches
    // "<ACCESS-  token__123>" with capture group 1 == "123".
    auto p = Guard::build_placeholder_pattern("ACCESS_TOKEN");
    RE2 re(p.pattern);
    ASSERT_TRUE(re.ok()) << re.error();

    std::string number;
    ASSERT_TRUE(RE2::PartialMatch("before <ACCESS-  token__123> after", re, &number));
    EXPECT_EQ(number, "123");
}

TEST(GuardPlaceholderRegex, TokensAreRegexEscaped) {
    // A placeholder name containing a regex metacharacter must be matched
    // literally, not interpreted as a regex operator -- mirrors Go's use of
    // regexp.QuoteMeta per token (we use RE2::QuoteMeta).
    auto p = Guard::build_placeholder_pattern("A.B");
    RE2 re(p.pattern);
    ASSERT_TRUE(re.ok()) << re.error();

    EXPECT_TRUE(RE2::PartialMatch("<A.B_1>", re));
    EXPECT_FALSE(RE2::PartialMatch("<AxB_1>", re));  // '.' must NOT act as "any char"
}

TEST(GuardPlaceholderRegex, MaxLenIsPositiveAndSmall) {
    auto p = Guard::build_placeholder_pattern("EMAIL");
    EXPECT_GT(p.max_len, 0u);
    EXPECT_LT(p.max_len, 100u);
}

TEST(GuardPlaceholderRegex, PatternHasExactlyOneCaptureGroup) {
    auto p = Guard::build_placeholder_pattern("EMAIL");
    RE2 re(p.pattern);
    ASSERT_TRUE(re.ok()) << re.error();
    EXPECT_EQ(re.NumberOfCapturingGroups(), 1);
}

// ── regex_max_len: RE2 parse-tree length bound ───────────────────────────────

TEST(GuardRegexMaxLen, Literal) {
    EXPECT_EQ(Guard::regex_max_len("abc"), 3u);
}

TEST(GuardRegexMaxLen, UnicodeLiteralUsesByteLength) {
    // "ёж" is two 2-byte Cyrillic runes -> 4 bytes total.
    EXPECT_EQ(Guard::regex_max_len("ёж"), 4u);
}

TEST(GuardRegexMaxLen, BoundedRepeat) {
    EXPECT_EQ(Guard::regex_max_len("a{2,4}"), 4u);
}

TEST(GuardRegexMaxLen, BoundedRepeatWithTrailingLiteral) {
    EXPECT_EQ(Guard::regex_max_len("a{2,5}b"), 6u);
}

TEST(GuardRegexMaxLen, OptionalBoundedSubexpression) {
    EXPECT_EQ(Guard::regex_max_len("(ab)?"), 2u);
}

TEST(GuardRegexMaxLen, AlternationUsesLongestBranch) {
    EXPECT_EQ(Guard::regex_max_len("ab|cde"), 3u);
}

TEST(GuardRegexMaxLen, CharClassUsesMaximumRuneByteLength) {
    // 'A' is 1 byte, 'Я' (Cyrillic, U+042F) is 2 bytes -> the class bound is 2.
    EXPECT_EQ(Guard::regex_max_len("[AЯ]"), 2u);
}

TEST(GuardRegexMaxLen, CharClassWithMultibyteRunesUnderRepeat) {
    // 'а'/'б' (Cyrillic) are each 2 UTF-8 bytes; {2} makes the bound 4.
    EXPECT_EQ(Guard::regex_max_len("[аб]{2}"), 4u);
}

TEST(GuardRegexMaxLen, AnyCharUsesUtf8Max) {
    EXPECT_EQ(Guard::regex_max_len("."), 4u);
}

TEST(GuardRegexMaxLen, StarIsUnbounded) {
    EXPECT_EQ(Guard::regex_max_len("a*"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, PlusIsUnbounded) {
    EXPECT_EQ(Guard::regex_max_len("a+"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, OpenRepeatIsUnbounded) {
    EXPECT_EQ(Guard::regex_max_len("a{2,}"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, InvalidRegexpIsTreatedAsUnbounded) {
    // Go's public regexpMaxLen collapses "unparsable" into the same 0
    // sentinel it uses for "unbounded" (a signed int can't spare a second
    // sentinel); our unsigned SIZE_MAX return plays the same role here --
    // "cannot prove a bound" is reported the same way as "no bound exists".
    EXPECT_EQ(Guard::regex_max_len("["), SIZE_MAX);
}

TEST(GuardRegexMaxLen, ConcatOfMixedBoundedPieces) {
    EXPECT_EQ(Guard::regex_max_len("ab[AЯ]c{0,2}"), 2u + 2u + 2u);  // "ab" + class + "c{0,2}"
}

TEST(GuardRegexMaxLen, CaptureGroupBoundIsChildBound) {
    EXPECT_EQ(Guard::regex_max_len("(a{3})"), 3u);
}

// ── build_placeholder_pattern: max_len always matches regex_max_len ────────

TEST(GuardPlaceholderRegex, MaxLenMatchesRegexMaxLenOfBuiltPattern) {
    auto p = Guard::build_placeholder_pattern("DB_DSN");
    EXPECT_EQ(p.max_len, Guard::regex_max_len(p.pattern));
}
