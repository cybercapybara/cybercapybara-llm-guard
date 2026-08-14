/**
 * @file PlaceholderRegex.hpp
 * @brief Tolerant placeholder-recognition regex builder, plus a bounded-
 *        subset regex length parser that bounds the maximum byte length any
 *        given pattern can match.
 * @details Mirrors the Go reference's
 *          `pkg/guardrails/regex/registry/registry.go`
 *          (`buildDefaultPlaceholderRegexp`, `regexpMaxLen`):
 *            - `build_placeholder_pattern("EMAIL")` produces
 *              `(?i)<\s{0,3}EMAIL[\s_-]{0,3}([0-9]{1,9})\s{0,3}>` -- a
 *              tolerant recognizer for a masked placeholder like `<EMAIL_1>`
 *              that survives an LLM's paraphrasing: case drift, extra
 *              whitespace, `_`/`-` interchange (`< email - 12 >` still
 *              matches). Capture group 1 is always the placeholder's numeric
 *              index.
 *            - Multi-token names (e.g. "DB_DSN") split on `_`; the tokens
 *              are re-joined -- and separated from the trailing number -- by
 *              the same drift-tolerant `[\s_-]{0,3}` separator.
 *            - `regex_max_len` computes a saturating upper bound on the byte
 *              length of any string a pattern can match. `SIZE_MAX` means
 *              "unbounded" (Go's internal sentinel is `-1`; Go's *public*
 *              `regexpMaxLen` additionally collapses "unparsable" into the
 *              same `0` it uses for "unbounded" since a signed `int` return
 *              can't spare a second sentinel -- our unsigned `SIZE_MAX`
 *              doesn't have that problem, but we still treat "unparsable /
 *              outside the supported subset" as "can't prove a bound" and
 *              report SIZE_MAX for it, matching the spirit of the Go
 *              sentinel).
 *            - `build_placeholder_pattern` throws
 *              `RuleError{Code::UnboundedPlaceholder}` if the template ever
 *              produced an unbounded pattern. This is defensive: the fixed
 *              `\s{0,3}` / `[\s_-]{0,3}` / `[0-9]{1,9}` bounds baked into the
 *              template make an unbounded result unreachable for every
 *              shape this builder emits, but the check (and the RuleError
 *              code it uses) exists so a future change to the template that
 *              accidentally introduces `*`/`+` fails loudly at rule-compile
 *              time instead of silently shipping an unbounded SSE pending
 *              buffer.
 *
 *          IMPLEMENTATION NOTE -- why a hand-rolled parser instead of
 *          walking RE2's own parse tree: the natural port of the Go
 *          reference's `regexpMaxLen` (which walks `regexp/syntax`'s parsed
 *          tree) is to walk RE2's equivalent internal tree via
 *          `re2::Regexp::Parse` (declared in `re2/regexp.h`). That header is
 *          RE2's *internal* API and is not installed by the vcpkg `re2`
 *          port (confirmed by CI: `fatal error: re2/regexp.h: No such file
 *          or directory`), so it isn't available to link against here.
 *          `regex_max_len` instead hand-parses `pattern` itself with a small
 *          recursive-descent parser (`detail::BoundedLengthParser`) over a
 *          *restricted subset* of RE2/Perl regex syntax -- exactly the
 *          subset `build_placeholder_pattern` generates, plus the ad-hoc
 *          patterns this file's unit tests exercise. Go parity note: for
 *          every pattern in that subset, this parser computes the same
 *          answer `regexp/syntax`-based `regexpMaxLen` would (see the
 *          per-construct comments on `BoundedLengthParser`'s methods for the
 *          equivalence, e.g. "`{m,n}` == Go's `OpRepeat`"). Anything outside
 *          the subset (backreferences, lookaround, `\p{...}` Unicode
 *          property classes, malformed syntax such as an unclosed group or
 *          a stray brace) is refused conservatively -- SIZE_MAX
 *          ("unbounded"), never a crash and never an underestimate. The
 *          supported subset, precisely:
 *            - literal characters, including multibyte UTF-8 runes written
 *              directly in the pattern (byte length = the rune's UTF-8
 *              encoded length)
 *            - backslash escapes: `\d \s \w` (RE2's Perl classes are
 *              ASCII-only per RE2's own syntax docs, so 1 byte each); their
 *              negations `\D \S \W` match anything OUTSIDE that ASCII-only
 *              set, so `kUtf8Max` (4) instead; `\b \B \A \z \Z` (zero-width
 *              anchors); `\n \t \r \f \v \a` (1-byte control literals); and
 *              `\X` for any other character X (a literal escaped char, e.g.
 *              what `RE2::QuoteMeta` produces for `.` -> `\.`) -- EXCEPT
 *              `\xHH`/`\x{...}` hex and `\0`-`\7` octal escapes, which are
 *              NOT supported (refused; see the CORRECTNESS NOTES below)
 *            - character classes `[...]` -- bounded by the UTF-8 length of
 *              the widest member or range endpoint; a *negated* class
 *              `[^...]` is always `kUtf8Max` regardless of its members
 *              (see CORRECTNESS NOTES)
 *            - groups `(...)`, non-capturing `(?:...)`, named `(?P<n>...)`,
 *              and inline-flag forms `(?i)` / `(?i:...)` (flags themselves
 *              don't affect length; `\p{...}`/`\P{...}` and lookaround
 *              `(?=...)` `(?!...)` etc. are NOT supported -- refused)
 *            - alternation `|` (bound = the longest branch)
 *            - quantifiers `{m,n}` `{m}` (bound = n * operand, or m *
 *              operand), `?` (bound = operand's own bound -- 0 vs 1 copy),
 *              `*` `+` `{m,}` (SIZE_MAX unless the operand is zero-width,
 *              in which case repeating it any number of times still adds
 *              zero bytes); a trailing non-greedy `?` on any quantifier is
 *              consumed and ignored (greediness doesn't affect the bound)
 *            - anchors `^` `$` and `.` (any char, bounded by UTF-8 max)
 *
 *          Saturating arithmetic (`detail::sat_add`/`detail::sat_mul`) is
 *          used throughout so a pathological pattern (e.g. deeply nested
 *          large bounded repeats) can never silently overflow
 *          `std::size_t` into a small, *wrong* bound -- it clamps to
 *          `SIZE_MAX` ("unbounded") instead, which is always safe for a
 *          buffer-sizing bound even if it costs precision.
 *
 *          CORRECTNESS NOTES (closed after code review on this PR -- each
 *          one was a real under-estimate or crash path, the two classes of
 *          bug this function must never have):
 *            - Case-insensitive fold-orbit width: under `(?i)`, ASCII 's'/
 *              'S' Unicode-simple-case-folds with U+017F LATIN SMALL LETTER
 *              LONG S (2 bytes in UTF-8) and 'k'/'K' folds with U+212A
 *              KELVIN SIGN (3 bytes) -- RE2 matches those wider runes too,
 *              so counting the literal ASCII byte (1) under-estimates. While
 *              `(?i)`/`(?i:...)` is active, `s`/`S`/`k`/`K` literals count
 *              as 3 bytes (the wider of the two known orbits, used
 *              uniformly rather than tracking each letter's exact width
 *              separately). This deliberately exceeds the true bound for
 *              'S' (true widest is 2) and exceeds Go's own bound (the Go
 *              reference has this same defect, uncorrected) -- an
 *              intentional safety margin, since over-estimating a length
 *              bound is always safe and under-estimating never is. Other
 *              ASCII letters have no known wide fold-orbit member and are
 *              NOT widened by this rule (fold-tracking is scoped to
 *              wherever a `(?i)`/`(?i:...)` flag was seen; see
 *              `fold_case_`).
 *            - Negated classes: `[^...]`'s complement spans everything
 *              *outside* the listed members -- i.e. effectively all of
 *              Unicode -- so its bound is `kUtf8Max` regardless of what's
 *              listed, not the listed members' width. Likewise the negated
 *              Perl escapes `\D \S \W` (unlike their positive counterparts
 *              `\d \s \w`, which really are a fixed ASCII-only set) match
 *              "anything that isn't ASCII digit/space/word", which includes
 *              arbitrary wide Unicode runes.
 *            - Recursion depth: `parse_group` recurses through
 *              `parse_alternation`/`parse_concat`/`parse_atom` for every
 *              nested `(`; an adversarial input with tens of thousands of
 *              nested groups can exhaust the call stack. `parse_group`
 *              caps nesting at `kMaxGroupDepth` and refuses (SIZE_MAX)
 *              rather than recursing further.
 *            - `\xHH` hex and `\0`-`\7` octal escapes are not decoded (that
 *              would require converting the numeric value to a UTF-8 byte
 *              length correctly); refusing them beats silently under-
 *              counting (e.g. `[\xff]` is codepoint 0xFF, 2 UTF-8 bytes,
 *              not the 1 a naive "treat the char after `\` literally" rule
 *              would report).
 */

#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <re2/re2.h>

#include "guard/Errors.hpp"

namespace Guard {

struct PlaceholderPattern {
    std::string pattern;
    std::size_t max_len{0};
};

namespace detail {

constexpr std::size_t kUtf8Max = 4;  // utf8.UTFMax

// ---- saturating arithmetic over std::size_t ----------------------------
// Clamp to SIZE_MAX ("unbounded") instead of wrapping. Order matters in
// sat_mul: the zero check must come first so that "repeated zero times"
// (an unbounded per-occurrence length times a repeat count of 0) correctly
// collapses to a bounded 0, not SIZE_MAX.

inline std::size_t sat_add(std::size_t a, std::size_t b) {
    if (a > SIZE_MAX - b)
        return SIZE_MAX;
    return a + b;
}

inline std::size_t sat_mul(std::size_t a, std::size_t b) {
    if (a == 0 || b == 0)
        return 0;
    if (a > SIZE_MAX / b)
        return SIZE_MAX;
    return a * b;
}

// Internal control-flow signal only: thrown by BoundedLengthParser wherever
// it hits a construct outside the supported subset (see the file-level doc
// comment), or malformed syntax (unclosed group, stray brace, truncated
// escape...). Always caught inside regex_max_len -- never observable
// outside this file.
struct UnboundedSignal {};

// Recursive-descent parser over the restricted RE2/Perl regex subset
// documented in the file-level comment. Computes a saturating upper bound,
// in bytes, on the length of any string the pattern can match; throws
// UnboundedSignal for anything it can't bound (unbounded repetition,
// unsupported syntax, or malformed input) rather than guessing.
//
// Grammar (roughly, in the usual regex-engine shape):
//   pattern      := alternation                     -- must consume all input
//   alternation  := concat ('|' concat)*             -- bound = max of branches
//   concat       := piece*                           -- bound = sum of pieces
//   piece        := atom quantifier?
//   atom         := '(' group_body ')' | '[' class ']' | '\' escape
//                  | '^' | '$' | '.' | <literal rune>
//   quantifier   := '*' | '+' | '?' | '{' m (',' n?)? '}'    (each '?'-suffixable)
class BoundedLengthParser {
public:
    explicit BoundedLengthParser(const std::string& pattern) : s_(pattern), pos_(0) {}

    // Entry point. Throws UnboundedSignal if the pattern uses anything
    // outside the supported subset, is malformed, or is unbounded.
    std::size_t parse() {
        const std::size_t n = parse_alternation();
        if (pos_ != s_.size())
            throw UnboundedSignal{};  // trailing unconsumed input: e.g. a stray ')'
        return n;
    }

private:
    // Nesting cap for parse_group's recursion (parse_group ->
    // parse_alternation -> parse_concat -> parse_piece -> parse_atom ->
    // parse_group ...). Real patterns -- ours and anything a human would
    // author -- never come close; this exists purely to refuse an
    // adversarial input with tens of thousands of nested '(' before it
    // exhausts the call stack.
    static constexpr int kMaxGroupDepth = 1000;

    const std::string& s_;
    std::size_t pos_;
    int depth_ = 0;
    // Set once a `(?i)` or `(?i:...)` flag is seen and never cleared again
    // (see the file-level "CORRECTNESS NOTES" -- staying on is the safe
    // direction). Widens the s/k fold-orbit letters in consume_rune_len.
    bool fold_case_ = false;

    bool at_end() const { return pos_ >= s_.size(); }
    char peek() const { return at_end() ? '\0' : s_[pos_]; }

    // Consumes and returns the UTF-8 byte length of the rune starting at
    // pos_ (1-4 bytes), advancing past it. Used for un-escaped literal
    // characters, including multibyte ones written directly in the pattern.
    // Under an active case-insensitive flag, 's'/'S'/'k'/'K' are widened to
    // 3 bytes (their Unicode fold partners ſ/K -- see the file-level
    // "CORRECTNESS NOTES") instead of the raw 1-byte ASCII width.
    std::size_t consume_rune_len() {
        if (at_end())
            throw UnboundedSignal{};
        const auto c = static_cast<unsigned char>(s_[pos_]);
        std::size_t n = 1;
        if ((c & 0xE0) == 0xC0)
            n = 2;
        else if ((c & 0xF0) == 0xE0)
            n = 3;
        else if ((c & 0xF8) == 0xF0)
            n = 4;
        if (pos_ + n > s_.size())
            n = s_.size() - pos_;  // truncated multibyte sequence at end of string
        const bool wide_fold_letter = fold_case_ && n == 1 && (c == 's' || c == 'S' || c == 'k' || c == 'K');
        pos_ += n;
        return wide_fold_letter ? 3 : n;
    }

    // Go equivalent: OpAlternate -- bound is the longest branch, since
    // exactly one branch is taken.
    std::size_t parse_alternation() {
        std::size_t best = parse_concat();
        while (peek() == '|') {
            ++pos_;
            const std::size_t n = parse_concat();
            if (n > best)
                best = n;
        }
        return best;
    }

    // Go equivalent: OpConcat -- bound is the sum of every piece, since all
    // are present in the match.
    std::size_t parse_concat() {
        std::size_t total = 0;
        while (!at_end() && peek() != '|' && peek() != ')')
            total = sat_add(total, parse_piece());
        return total;
    }

    std::size_t parse_piece() { return parse_quantifier(parse_atom()); }

    // RE2/Perl non-greedy marker: a '?' immediately following a quantifier
    // (e.g. `a*?`) only changes greediness, not the bound -- consume and
    // ignore it if present.
    void skip_lazy_marker() {
        if (peek() == '?')
            ++pos_;
    }

    std::size_t parse_quantifier(std::size_t atom_len) {
        if (at_end())
            return atom_len;
        const char c = peek();

        // Go equivalent: OpStar / OpPlus -- unbounded unless the operand is
        // zero-width, in which case repeating it any number of times still
        // contributes zero bytes.
        if (c == '*' || c == '+') {
            ++pos_;
            skip_lazy_marker();
            return atom_len == 0 ? 0 : SIZE_MAX;
        }
        // Go equivalent: OpQuest -- 0 or 1 copies; the bound is just the
        // operand's own bound (which already covers the "0 copies" case).
        if (c == '?') {
            ++pos_;
            skip_lazy_marker();
            return atom_len;
        }
        if (c == '{')
            return parse_brace_quantifier(atom_len);
        return atom_len;
    }

    // Go equivalent: OpRepeat -- {m}: exactly m copies; {m,n}: bounded by n
    // copies; {m,}: unbounded unless the operand is zero-width. A '{' that
    // doesn't form a valid quantifier (no digits, no closing '}') is NOT a
    // quantifier at all; it's left unconsumed for the caller to reparse as
    // the start of the next atom, where an unescaped '{' is refused (see
    // parse_atom) -- outside the supported subset, so SIZE_MAX overall.
    std::size_t parse_brace_quantifier(std::size_t atom_len) {
        const std::size_t save = pos_;
        ++pos_;  // consume '{'
        std::string min_digits;
        while (!at_end() && std::isdigit(static_cast<unsigned char>(peek())))
            min_digits.push_back(s_[pos_++]);
        bool has_comma = false;
        if (peek() == ',') {
            has_comma = true;
            ++pos_;
        }
        std::string max_digits;
        while (!at_end() && std::isdigit(static_cast<unsigned char>(peek())))
            max_digits.push_back(s_[pos_++]);

        if (min_digits.empty() || peek() != '}') {
            pos_ = save;
            return atom_len;
        }
        ++pos_;  // consume '}'
        skip_lazy_marker();

        if (!has_comma)
            return sat_mul(parse_repeat_count(min_digits), atom_len);
        if (max_digits.empty())
            return atom_len == 0 ? 0 : SIZE_MAX;
        return sat_mul(parse_repeat_count(max_digits), atom_len);
    }

    // Repeat counts in any pattern this parser supports are small (RE2
    // itself caps them well below 2^31); a plain saturating decimal parse
    // is sufficient.
    static std::size_t parse_repeat_count(const std::string& digits) {
        std::size_t v = 0;
        for (char c : digits)
            v = sat_add(sat_mul(v, 10), static_cast<std::size_t>(c - '0'));
        return v;
    }

    std::size_t parse_atom() {
        if (at_end())
            throw UnboundedSignal{};
        const char c = peek();
        if (c == '(')
            return parse_group();
        if (c == '[')
            return parse_char_class();
        if (c == '\\')
            return parse_escape();
        // Go equivalent: OpBeginLine/OpEndLine (^/$) -- zero-width anchors.
        if (c == '^' || c == '$') {
            ++pos_;
            return 0;
        }
        // Go equivalent: OpAnyCharNotNL/OpAnyChar -- bounded by UTF-8 max
        // either way (see the file-level doc comment's note on RE2's '.').
        if (c == '.') {
            ++pos_;
            return kUtf8Max;
        }
        // Structurally out of place here (an atom can't start with these) --
        // most commonly a malformed quantifier's stray '{'/'}' left behind
        // by parse_brace_quantifier, or an unmatched ']'/'*'/'+'/'?'.
        if (c == '|' || c == ')' || c == '*' || c == '+' || c == '?' || c == '{' || c == '}' || c == ']')
            throw UnboundedSignal{};
        return consume_rune_len();  // plain literal character (possibly multibyte)
    }

    // RAII nesting guard for parse_group: increments on construction,
    // decrements on destruction, so every one of parse_group's several
    // return points (and the UnboundedSignal throw paths above them)
    // unwinds depth_ correctly.
    class DepthGuard {
    public:
        explicit DepthGuard(int& depth) : depth_(depth) { ++depth_; }
        ~DepthGuard() { --depth_; }
        DepthGuard(const DepthGuard&) = delete;
        DepthGuard& operator=(const DepthGuard&) = delete;

    private:
        int& depth_;
    };

    // Go equivalent: OpCapture (plain '(...)' and named '(?P<n>...)') or a
    // transparent pass-through for '(?:...)' / '(?i)' / '(?i:...)' (flags
    // don't change the bound; Go's syntax parser strips them before this
    // point ever matters). Lookaround and other '(?...)' forms outside the
    // supported subset are refused.
    std::size_t parse_group() {
        if (depth_ >= kMaxGroupDepth)
            throw UnboundedSignal{};  // adversarially deep nesting: refuse before the stack does
        DepthGuard guard(depth_);

        ++pos_;  // consume '('
        if (peek() != '?') {
            const std::size_t n = parse_alternation();
            expect(')');
            return n;
        }
        ++pos_;  // consume '?'
        if (peek() == ':') {
            ++pos_;
            const std::size_t n = parse_alternation();
            expect(')');
            return n;
        }
        if (peek() == 'P' && pos_ + 1 < s_.size() && s_[pos_ + 1] == '<') {
            pos_ += 2;  // "P<"
            while (!at_end() && peek() != '>')
                ++pos_;
            expect('>');
            const std::size_t n = parse_alternation();
            expect(')');
            return n;
        }
        // (?flags) or (?flags:...): consume the recognized flag letters
        // (i s m U, optionally separated by a single '-' for on/off
        // groups). Anything else here (lookahead '(?=' '(?!', lookbehind
        // '(?<=' '(?<!', etc.) falls through and is refused below. Seeing
        // 'i' anywhere in the flag list sets fold_case_ and never clears
        // it (see the file-level "CORRECTNESS NOTES" -- ignoring a `-i`
        // that's meant to turn folding back off just keeps the bound safe,
        // never wrong).
        bool saw_flag = false;
        while (!at_end() && (peek() == 'i' || peek() == 's' || peek() == 'm' || peek() == 'U' || peek() == '-')) {
            if (peek() == 'i')
                fold_case_ = true;
            ++pos_;
            saw_flag = true;
        }
        if (saw_flag && peek() == ')') {
            ++pos_;
            return 0;  // (?i) etc: zero-width flag setter, not a group
        }
        if (saw_flag && peek() == ':') {
            ++pos_;
            const std::size_t n = parse_alternation();
            expect(')');
            return n;
        }
        throw UnboundedSignal{};
    }

    void expect(char c) {
        if (peek() != c)
            throw UnboundedSignal{};
        ++pos_;
    }

    // Go equivalent: OpCharClass -- bound is the UTF-8 length of the widest
    // single member (a literal char, an escape like \s, or the high end of
    // an a-b range); a wider class only ever needs *more* bytes for its
    // widest member, never fewer for a narrower one, so tracking the max is
    // sufficient (mirrors Go's maxRuneLenInClass). A *negated* class
    // `[^...]` is the complement of its listed members -- effectively all
    // of Unicode minus a few code points -- so its bound is always
    // kUtf8Max, regardless of what's listed; the members still have to be
    // parsed (for correct cursor advancement and to catch malformed
    // syntax), just not used to compute the returned width.
    std::size_t parse_char_class() {
        ++pos_;  // consume '['
        bool negated = false;
        if (peek() == '^') {
            negated = true;
            ++pos_;
        }
        std::size_t widest = 0;
        bool any_member = false;
        while (true) {
            if (at_end())
                throw UnboundedSignal{};
            if (peek() == ']') {
                ++pos_;
                break;
            }
            any_member = true;
            std::size_t member_len = peek() == '\\' ? parse_escape() : consume_rune_len();
            // 'a-z' style range: only when '-' is not immediately followed
            // by ']' (which makes it a literal '-' instead).
            if (peek() == '-' && pos_ + 1 < s_.size() && s_[pos_ + 1] != ']') {
                ++pos_;  // consume '-'
                const std::size_t hi_len = peek() == '\\' ? parse_escape() : consume_rune_len();
                if (hi_len > member_len)
                    member_len = hi_len;
            }
            if (member_len > widest)
                widest = member_len;
        }
        if (!any_member)
            throw UnboundedSignal{};  // "[]" -- empty/malformed class
        return negated ? kUtf8Max : widest;
    }

    // A backslash escape: either one of the recognized Perl class/anchor
    // letters, or `\X` for a literal character X (what RE2::QuoteMeta
    // produces for an escaped metacharacter, e.g. '.' -> "\.").
    std::size_t parse_escape() {
        ++pos_;  // consume '\\'
        if (at_end())
            throw UnboundedSignal{};
        const char c = s_[pos_];
        switch (c) {
            case 'd':
            case 's':
            case 'w':
                // RE2's Perl classes \d \s \w are ASCII-only per RE2's
                // syntax documentation: 1 byte, always.
                ++pos_;
                return 1;
            case 'D':
            case 'S':
            case 'W':
                // Their negations match "anything that ISN'T" the
                // ASCII-only positive set -- i.e. any other Unicode rune,
                // up to kUtf8Max bytes. Conflating these with the positive
                // classes above (both returning 1) was the exact
                // under-estimate this case review caught.
                ++pos_;
                return kUtf8Max;
            case 'b':
            case 'B':
            case 'A':
            case 'z':
            case 'Z':
                ++pos_;
                return 0;  // word boundary / text anchors: zero-width
            case 'n':
            case 't':
            case 'r':
            case 'f':
            case 'v':
            case 'a':
                ++pos_;
                return 1;  // single-byte control-character literal
            case 'p':
            case 'P':
                // \p{...} / \P{...} Unicode property class: bounding this
                // precisely needs a full Unicode property table, which is
                // outside the supported subset -- refuse rather than guess.
                throw UnboundedSignal{};
            case 'x':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
                // \xHH / \x{...} hex escapes and \0-\7 octal escapes encode
                // a numeric code point that this parser does not decode
                // (that requires parsing the digits and converting the
                // resulting value to a UTF-8 byte length correctly) --
                // refuse rather than fall through to the default case
                // below, which would wrongly treat 'x'/the digit as a
                // literal ASCII char and under-count (e.g. `[\xff]` is
                // code point 0xFF, 2 UTF-8 bytes, not 1).
                throw UnboundedSignal{};
            default:
                return consume_rune_len();  // literal escaped char, e.g. "\."
        }
    }
};

// UTF-8 byte length of `pattern`'s match, or SIZE_MAX if unbounded / outside
// the supported subset / malformed. See BoundedLengthParser above.
inline std::size_t bounded_length(const std::string& pattern) {
    try {
        BoundedLengthParser parser(pattern);
        return parser.parse();
    } catch (const UnboundedSignal&) {
        return SIZE_MAX;
    }
}

// Splits `name` on runs of '_', discarding empty fields -- mirrors Go's
// `strings.FieldsFunc(placeholderType, func(r rune) bool { return r == '_' })`.
// If nothing survives the split (blank name, or a name made entirely of
// underscores), the whole original name is used as a single token, exactly
// as the Go reference falls back to `[]string{placeholderType}`.
inline std::vector<std::string> split_on_underscore(std::string_view name) {
    std::vector<std::string> tokens;
    std::string current;
    for (char c : name) {
        if (c == '_') {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty())
        tokens.push_back(current);
    if (tokens.empty())
        tokens.emplace_back(name);
    return tokens;
}

// Builds the pattern string for the given placeholder name per the template
// in the file-level doc comment. maxDrift/indexLen match the Go reference's
// unexported constants of the same name in buildDefaultPlaceholderRegexp.
inline std::string build_placeholder_pattern_string(std::string_view placeholder_name) {
    constexpr int kMaxDrift = 3;
    constexpr int kIndexLen = 9;

    const std::vector<std::string> tokens = split_on_underscore(placeholder_name);
    const std::string sep = "[\\s_-]{0," + std::to_string(kMaxDrift) + "}";

    std::string pattern = "(?i)<\\s{0," + std::to_string(kMaxDrift) + "}";
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        if (i > 0)
            pattern += sep;
        pattern += RE2::QuoteMeta(tokens[i]);
    }
    pattern += sep;
    pattern += "([0-9]{1," + std::to_string(kIndexLen) + "})\\s{0," + std::to_string(kMaxDrift) + "}>";
    return pattern;
}

}  // namespace detail

/**
 * @brief Upper bound, in bytes, on the length of any string `pattern` can
 *        match, computed by parsing `pattern` over a restricted
 *        RE2/Perl-syntax subset (see the file-level doc comment).
 * @return `SIZE_MAX` if `pattern` is unbounded (contains an unbounded
 *         repetition such as `*`/`+`/`{n,}`), uses syntax outside the
 *         supported subset, or is malformed -- in every case, a bound
 *         cannot be proven, so the safe answer is "unbounded".
 */
inline std::size_t regex_max_len(const std::string& pattern) {
    return detail::bounded_length(pattern);
}

/**
 * @brief Builds the tolerant placeholder-recognition pattern for a masking
 *        placeholder name (e.g. "EMAIL", "DB_DSN") together with its
 *        max byte length (see regex_max_len).
 * @details The pattern always has exactly one capture group (the
 *          placeholder's numeric index) and is case-insensitive
 *          (`(?i)`-prefixed) so `<EMAIL_1>`, `< email - 12 >`, `<EMAIL-1>`
 *          all match. See the file-level doc comment for the full template
 *          and the multi-token join rule.
 * @throws RuleError{Code::UnboundedPlaceholder} if the built pattern turns
 *         out to be unbounded (see regex_max_len) -- unreachable for the
 *         fixed-shape template this function emits, kept as a defensive
 *         assertion.
 * @note This function does NOT special-case a blank/whitespace-only
 *       `placeholder_name` -- it always builds a (permissive, but still
 *       bounded) pattern, even for `""`. The Go reference's blank-placeholder
 *       guard (`compilePlaceholderRegex`: `strings.TrimSpace(name) == ""`
 *       means "no recognizer at all" -- a nil regex, zero length, skipped
 *       entirely) lives one layer up, at the call site that decides whether
 *       a rule gets a placeholder recognizer in the first place. Callers
 *       (Registry::compile_rule in Task 1.5) must replicate that guard
 *       themselves before calling this function: skip calling it, rather
 *       than calling it and discarding the result, when
 *       `rule.masking.placeholder` is empty or all-whitespace.
 */
inline PlaceholderPattern build_placeholder_pattern(std::string_view placeholder_name) {
    std::string pattern = detail::build_placeholder_pattern_string(placeholder_name);
    const std::size_t max_len = regex_max_len(pattern);
    if (max_len == SIZE_MAX) {
        throw RuleError(RuleError::Code::UnboundedPlaceholder,
                        "placeholder regex for '" + std::string(placeholder_name) + "' is unbounded: " + pattern);
    }
    return PlaceholderPattern{std::move(pattern), max_len};
}

}  // namespace Guard
