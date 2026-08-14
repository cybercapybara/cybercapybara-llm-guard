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
 * regex_max_len is implemented as a hand-rolled recursive-descent parser
 * over a restricted regex subset (see the doc comment on
 * src/guard/PlaceholderRegex.hpp) rather than a walk of RE2's own parse
 * tree -- re2/regexp.h, RE2's internal parser header, is not installed by
 * the vcpkg re2 port. TestMaxRuneLenInClass_InvalidRuneFallsBackToUTFMax
 * from the Go suite is NOT ported for the same reason it never applied to
 * a from-scratch parser either: it exercises an internal helper with a
 * synthetic out-of-Unicode-range rune that can never arise from parsing a
 * real textual pattern.
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

// ── regex_max_len: bounded-subset regex length parser ───────────────────────

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

// ── parser robustness: bounded-subset recursive-descent parser ──────────────
// (regex_max_len no longer walks RE2's internal parse tree -- re2/regexp.h
// is not installed by the vcpkg re2 port -- it hand-parses a restricted
// RE2/Perl subset instead. These cover the parser's own edge cases: nested
// quantified groups, an escaped literal brace, and inputs it must refuse
// without ever crashing.)

TEST(GuardRegexMaxLen, NestedGroupWithQuantifierFollowedByLiteral) {
    // (ab){2,3} -> 3 * len("ab") = 6, plus trailing literal 'c' -> 7.
    EXPECT_EQ(Guard::regex_max_len("(ab){2,3}c"), 7u);
}

TEST(GuardRegexMaxLen, EscapedBraceIsALiteralNotAQuantifier) {
    // "a\{" is the two literal characters 'a' and '{' (RE2::QuoteMeta emits
    // exactly this for a literal '{' in a placeholder token) -- 2 bytes,
    // bounded, not confused for a malformed {m,n} quantifier attempt.
    EXPECT_EQ(Guard::regex_max_len("a\\{"), 2u);
}

TEST(GuardRegexMaxLen, UnclosedGroupIsUnboundedNotACrash) {
    EXPECT_EQ(Guard::regex_max_len("(ab"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, StrayClosingBraceIsUnboundedNotACrash) {
    EXPECT_EQ(Guard::regex_max_len("a}b"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, StrayClosingParenIsUnboundedNotACrash) {
    EXPECT_EQ(Guard::regex_max_len("a)b"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, UnclosedCharClassIsUnboundedNotACrash) {
    EXPECT_EQ(Guard::regex_max_len("[abc"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, TrailingBackslashIsUnboundedNotACrash) {
    EXPECT_EQ(Guard::regex_max_len("ab\\"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, EmptyPatternIsZero) {
    EXPECT_EQ(Guard::regex_max_len(""), 0u);
}

TEST(GuardRegexMaxLen, UnicodePropertyClassIsUnbounded) {
    // \p{...} is outside the supported subset (would need a full Unicode
    // property table to bound precisely) -- refused conservatively.
    EXPECT_EQ(Guard::regex_max_len("\\p{L}"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, LookaheadIsUnbounded) {
    // (?=...) is outside the supported subset -- refused conservatively.
    EXPECT_EQ(Guard::regex_max_len("(?=ab)"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, NonCapturingGroupWithFlags) {
    EXPECT_EQ(Guard::regex_max_len("(?i:ab)c"), 3u);
}

TEST(GuardRegexMaxLen, NamedCaptureGroup) {
    EXPECT_EQ(Guard::regex_max_len("(?P<x>ab)c"), 3u);
}

TEST(GuardRegexMaxLen, LazyQuantifierBoundIsSameAsGreedy) {
    EXPECT_EQ(Guard::regex_max_len("a{2,4}?"), 4u);
    EXPECT_EQ(Guard::regex_max_len("a*?"), SIZE_MAX);
}

// ── negated classes: complement spans (effectively) all of Unicode ─────────
// (Code review finding: a negated class or negated Perl escape must never
// be bounded by its LISTED members' width -- its complement is everything
// ELSE, up to kUtf8Max bytes, regardless of what's excluded.)

TEST(GuardRegexMaxLen, NegatedCharClassIsUtf8MaxRegardlessOfMembers) {
    EXPECT_EQ(Guard::regex_max_len("[^a]"), 4u);
    EXPECT_EQ(Guard::regex_max_len("[^0-9]"), 4u);
}

TEST(GuardRegexMaxLen, NegatedPerlClassesAreUtf8Max) {
    EXPECT_EQ(Guard::regex_max_len("\\D"), 4u);
    EXPECT_EQ(Guard::regex_max_len("\\S"), 4u);
    EXPECT_EQ(Guard::regex_max_len("\\W"), 4u);
}

TEST(GuardRegexMaxLen, NegatedPerlClassInsideBracketExpressionIsUtf8Max) {
    EXPECT_EQ(Guard::regex_max_len("[\\D]"), 4u);
}

TEST(GuardRegexMaxLen, PositivePerlClassesStayAsciiWidth) {
    // The non-negated counterparts really are a fixed ASCII-only set --
    // unaffected by the [^...]/\D\S\W fix above.
    EXPECT_EQ(Guard::regex_max_len("\\d"), 1u);
    EXPECT_EQ(Guard::regex_max_len("\\s"), 1u);
    EXPECT_EQ(Guard::regex_max_len("\\w"), 1u);
}

// ── hex/octal escapes: not decoded, refused rather than under-counted ──────

TEST(GuardRegexMaxLen, HexEscapeInsideClassIsUnbounded) {
    // Code review finding: [\xff] is code point 0xFF (2 UTF-8 bytes), but
    // the pre-fix parser fell through to treating 'x' as a literal ASCII
    // char and returned 1. Refused outright now instead of guessing.
    EXPECT_EQ(Guard::regex_max_len("[\\xff]"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, HexEscapeOutsideClassIsUnbounded) {
    EXPECT_EQ(Guard::regex_max_len("a\\xffb"), SIZE_MAX);
}

TEST(GuardRegexMaxLen, OctalEscapeIsUnbounded) {
    EXPECT_EQ(Guard::regex_max_len("\\052"), SIZE_MAX);
}

// ── recursion depth cap: refuse adversarial nesting, never crash ───────────

TEST(GuardRegexMaxLen, DeeplyNestedGroupsAreRefusedNotCrashed) {
    // parse_group recurses once per nested '('; an unbounded cap would let
    // an adversarial pattern exhaust the call stack. 5000 levels comfortably
    // exceeds BoundedLengthParser::kMaxGroupDepth (1000) -- must come back
    // as "unbounded", not crash the process.
    std::string pattern(5000, '(');
    pattern += "a";
    pattern.append(5000, ')');
    EXPECT_EQ(Guard::regex_max_len(pattern), SIZE_MAX);
}

// ── case-insensitive fold-orbit width: s/k widen under (?i) ────────────────
// (Code review finding: under (?i), ASCII 's'/'S' folds with U+017F LATIN
// SMALL LETTER LONG S [2 bytes] and 'k'/'K' folds with U+212A KELVIN SIGN
// [3 bytes] -- RE2 matches those wider runes too, so counting the literal
// ASCII byte under-estimates. Widened uniformly to 3 bytes, the wider of
// the two orbits, for both letters -- see the file-level "CORRECTNESS
// NOTES" on PlaceholderRegex.hpp for why a uniform, slightly loose bound
// beats tracking each letter's exact orbit width.)

TEST(GuardRegexMaxLen, CaseInsensitiveSAndKWidenToThreeBytes) {
    EXPECT_EQ(Guard::regex_max_len("(?i)s"), 3u);
    EXPECT_EQ(Guard::regex_max_len("(?i)S"), 3u);
    EXPECT_EQ(Guard::regex_max_len("(?i)k"), 3u);
    EXPECT_EQ(Guard::regex_max_len("(?i)K"), 3u);
}

TEST(GuardRegexMaxLen, CaseInsensitiveOtherLettersStayAsciiWidth) {
    // No known wide fold-orbit member for these -- (?i) doesn't widen them.
    EXPECT_EQ(Guard::regex_max_len("(?i)a"), 1u);
    EXPECT_EQ(Guard::regex_max_len("(?i)email"), 5u);
}

TEST(GuardRegexMaxLen, WithoutFoldFlagSAndKStayAsciiWidth) {
    EXPECT_EQ(Guard::regex_max_len("sk"), 2u);
}

TEST(GuardRegexMaxLen, InlineFoldFlagGroupWidensLettersInsideIt) {
    // "(?i:s)" -- the flag is scoped syntactically to "(?i:...)", but this
    // parser's fold_case_ is a sticky, never-cleared flag (see the
    // CORRECTNESS NOTES): once set it stays set, which only ever makes the
    // bound MORE conservative, never wrong.
    EXPECT_EQ(Guard::regex_max_len("(?i:s)"), 3u);
}

// ── build_placeholder_pattern: pinned exact max_len values ─────────────────
// Computed under the post-fix rules above; each is >= the true bound
// (deliberately, for "s"/"k" -- see PlaceholderRegex.hpp's CORRECTNESS
// NOTES) and > the pre-fix (buggy, under-estimating) value where the name
// contains an 's'/'S'/'k'/'K'.

TEST(GuardPlaceholderRegex, EmailMaxLenIsPinned) {
    // "EMAIL" has no s/k -> completely unaffected by the fold-orbit fix;
    // matches the value before that fix too.
    auto p = Guard::build_placeholder_pattern("EMAIL");
    EXPECT_EQ(p.max_len, 25u);
}

TEST(GuardPlaceholderRegex, DbDsnMaxLenIsPinned) {
    // "DSN" contains one 'S', widened +2 bytes (1 -> 3) over the pre-fix
    // value of 28.
    auto p = Guard::build_placeholder_pattern("DB_DSN");
    EXPECT_EQ(p.max_len, 30u);
}

TEST(GuardPlaceholderRegex, AccessTokenMaxLenIsPinned) {
    // "ACCESS" has two 'S's, "TOKEN" has one 'K': three letters widened +2
    // bytes each over the pre-fix value of 34 -> 40. This deliberately
    // exceeds the empirically measured true widest match (36 bytes) --
    // an intentional safety margin from using a uniform 3-byte width for
    // both the s (true widest 2) and k (true widest 3) orbits, not a bug.
    auto p = Guard::build_placeholder_pattern("ACCESS_TOKEN");
    EXPECT_EQ(p.max_len, 40u);
}

// ── build_placeholder_pattern: max_len always matches regex_max_len ────────
// Secondary consistency check alongside the pinned values above: max_len is
// defined as regex_max_len(pattern), so this can never legitimately fail --
// it exists to catch a future refactor that breaks that invariant.

TEST(GuardPlaceholderRegex, MaxLenMatchesRegexMaxLenOfBuiltPattern) {
    auto p = Guard::build_placeholder_pattern("DB_DSN");
    EXPECT_EQ(p.max_len, Guard::regex_max_len(p.pattern));
}
