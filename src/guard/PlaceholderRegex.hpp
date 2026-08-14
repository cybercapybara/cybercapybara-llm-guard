/**
 * @file PlaceholderRegex.hpp
 * @brief Tolerant placeholder-recognition regex builder, plus an RE2
 *        parse-tree walk that bounds the maximum byte length any given
 *        pattern can match.
 * @details Mirrors the Go reference's
 *          `pkg/guardrails/regex/registry/registry.go`
 *          (`buildDefaultPlaceholderRegexp`, `regexpMaxLen`) op-for-op:
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
 *            - `regex_max_len` walks the *compiled RE2 parse tree*
 *              (`re2::Regexp::Parse`, not the pattern string -- a textual
 *              scan can't see through case-insensitive expansion or nested
 *              groups the way the parser already has) to compute a
 *              saturating upper bound on the byte length of any string the
 *              pattern can match. `SIZE_MAX` means "unbounded" (Go's
 *              internal sentinel is `-1`; Go's *public* `regexpMaxLen`
 *              additionally collapses "unparsable" into the same `0` it
 *              uses for "unbounded" since a signed `int` return can't spare
 *              a second sentinel -- our unsigned `SIZE_MAX` doesn't have
 *              that problem, but we still treat "unparsable" as "can't
 *              prove a bound" and report SIZE_MAX for it, matching the
 *              spirit of the Go sentinel).
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
 *          Go `regexp/syntax` op -> RE2 `re2::Regexp` op mapping used by the
 *          parse-tree walk in `detail::regexp_op_max_len` (see that
 *          function's switch for the exact byte-length rule applied to each
 *          case):
 *
 *            Go syntax.Op                RE2 Regexp::op()
 *            --------------------------  ------------------------------------
 *            OpEmptyMatch                kRegexpEmptyMatch
 *            OpBeginLine / OpEndLine     kRegexpBeginLine / kRegexpEndLine
 *            OpBeginText / OpEndText     kRegexpBeginText / kRegexpEndText
 *            OpWordBoundary /            kRegexpWordBoundary /
 *              OpNoWordBoundary            kRegexpNoWordBoundary
 *            OpLiteral (1 rune)          kRegexpLiteral (`rune()`)
 *            OpLiteral (N runes)         kRegexpLiteralString
 *                                          (`runes()`/`nrunes()`) -- RE2
 *                                          splits what Go keeps as one op
 *                                          into two ops depending on rune
 *                                          count.
 *            OpCharClass                 kRegexpCharClass (`cc()`)
 *            OpAnyCharNotNL / OpAnyChar  kRegexpAnyChar -- RE2 has no
 *                                          "NotNL" variant at the tree
 *                                          level; without the DotNL flag the
 *                                          parser instead rewrites `.` into
 *                                          a CharClass excluding `\n`
 *                                          (`[0,\n) | (\n,0x10FFFF]`), which
 *                                          the CharClass case below already
 *                                          bounds to the same UTF-8 max (its
 *                                          upper range still reaches
 *                                          0x10FFFF).
 *            (none -- RE2-only)          kRegexpAnyByte (`\C`; matches
 *                                          exactly one byte)
 *            OpConcat                    kRegexpConcat (`sub()`/`nsub()`)
 *            OpAlternate                 kRegexpAlternate
 *            OpStar / OpPlus             kRegexpStar / kRegexpPlus
 *            OpQuest                     kRegexpQuest
 *            OpRepeat                    kRegexpRepeat (`min()`/`max()`)
 *            OpCapture                   kRegexpCapture (child `sub()[0]`)
 *            OpNoMatch                   kRegexpNoMatch (matches no string
 *                                          at all, so the bound is
 *                                          vacuously 0)
 *            (none -- RE2-only)          kRegexpHaveMatch (an RE2::Set-only
 *                                          internal marker `Regexp::Parse`
 *                                          never produces; treated as
 *                                          unbounded defensively, alongside
 *                                          any future op this switch doesn't
 *                                          yet know about)
 *
 *          Saturating arithmetic (`detail::sat_add`/`detail::sat_mul`) is
 *          used throughout so a pathological pattern (e.g. deeply nested
 *          large bounded repeats) can never silently overflow
 *          `std::size_t` into a small, *wrong* bound -- it clamps to
 *          `SIZE_MAX` ("unbounded") instead, which is always safe for a
 *          buffer-sizing bound even if it costs precision.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <re2/re2.h>
#include <re2/regexp.h>

#include "guard/Errors.hpp"

namespace Guard {

struct PlaceholderPattern {
    std::string pattern;
    std::size_t max_len{0};
};

namespace detail {

// ---- saturating arithmetic over std::size_t ----------------------------
// Clamp to SIZE_MAX ("unbounded") instead of wrapping. Order matters in
// sat_mul: the zero check must come first so that "repeated zero times"
// (an unbounded per-occurrence length times a Repeat max of 0) correctly
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

// UTF-8 byte length of a rune, mirroring Go's utf8.RuneLen. Returns 0 for a
// negative or out-of-Unicode-range value (Go returns -1; this is unsigned
// code so 0 -- never a valid RuneLen result for a real rune -- is the
// "invalid" sentinel instead), letting callers fall back to the worst case.
inline std::size_t rune_utf8_len(re2::Rune r) {
    if (r < 0 || r > 0x10FFFF)
        return 0;
    if (r <= 0x7F)
        return 1;
    if (r <= 0x7FF)
        return 2;
    if (r <= 0xFFFF)
        return 3;
    return 4;
}

constexpr std::size_t kUtf8Max = 4;  // utf8.UTFMax

inline std::size_t rune_utf8_len_or_max(re2::Rune r) {
    const std::size_t n = rune_utf8_len(r);
    return n == 0 ? kUtf8Max : n;
}

// Mirrors Go's maxRuneLenInClass: a character class's byte-length bound is
// the UTF-8 length of the single largest rune among its ranges (a wider
// class only ever needs *more* bytes for its largest member, never fewer
// for a smaller one, so scanning for the max hi is sufficient).
inline std::size_t max_rune_len_in_class(re2::CharClass* cc) {
    re2::Rune max_rune = 0;
    for (auto it = cc->begin(); it != cc->end(); ++it) {
        if (it->hi > max_rune)
            max_rune = it->hi;
    }
    return rune_utf8_len_or_max(max_rune);
}

// Recursively computes the maximum byte length any string matched by `re`
// (and everything under it) can have. SIZE_MAX means unbounded. See the
// file-level doc comment for the Go-op -> RE2-op mapping this switch
// implements. Patterns handled here (the placeholder template, and the
// small ad-hoc patterns regex_max_len is unit-tested against) are shallow,
// so plain recursion is used rather than re2::Regexp::Walker -- RE2's own
// recommendation to prefer Walker exists to protect against adversarial,
// deeply right-nested input like `x++++++++...`, which never arises here.
inline std::size_t regexp_op_max_len(re2::Regexp* re) {
    switch (re->op()) {
        case re2::kRegexpEmptyMatch:
        case re2::kRegexpBeginLine:
        case re2::kRegexpEndLine:
        case re2::kRegexpBeginText:
        case re2::kRegexpEndText:
        case re2::kRegexpWordBoundary:
        case re2::kRegexpNoWordBoundary:
        case re2::kRegexpNoMatch:
            return 0;

        case re2::kRegexpLiteral:
            return rune_utf8_len_or_max(re->rune());

        case re2::kRegexpLiteralString: {
            std::size_t total = 0;
            re2::Rune* runes = re->runes();
            for (int i = 0; i < re->nrunes(); ++i)
                total = sat_add(total, rune_utf8_len_or_max(runes[i]));
            return total;
        }

        case re2::kRegexpCharClass:
            return max_rune_len_in_class(re->cc());

        case re2::kRegexpAnyChar:
            return kUtf8Max;

        case re2::kRegexpAnyByte:
            return 1;

        case re2::kRegexpConcat: {
            std::size_t total = 0;
            re2::Regexp** subs = re->sub();
            for (int i = 0; i < re->nsub(); ++i)
                total = sat_add(total, regexp_op_max_len(subs[i]));
            return total;
        }

        case re2::kRegexpAlternate: {
            std::size_t longest = 0;
            re2::Regexp** subs = re->sub();
            for (int i = 0; i < re->nsub(); ++i) {
                const std::size_t n = regexp_op_max_len(subs[i]);
                if (n > longest)
                    longest = n;
            }
            return longest;
        }

        case re2::kRegexpStar:
        case re2::kRegexpPlus:
            return SIZE_MAX;

        case re2::kRegexpQuest:
            return re->nsub() > 0 ? regexp_op_max_len(re->sub()[0]) : 0;

        case re2::kRegexpRepeat: {
            if (re->max() < 0)
                return SIZE_MAX;
            const std::size_t child = re->nsub() > 0 ? regexp_op_max_len(re->sub()[0]) : 0;
            return sat_mul(static_cast<std::size_t>(re->max()), child);
        }

        case re2::kRegexpCapture:
            return re->nsub() > 0 ? regexp_op_max_len(re->sub()[0]) : 0;

        case re2::kRegexpHaveMatch:
        default:
            // Unrecognized or unhandled op: cannot prove a bound, so stay
            // safe rather than guess. kRegexpHaveMatch specifically is an
            // RE2::Set-only marker Regexp::Parse never produces.
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
 *        match -- computed by walking RE2's parsed representation of
 *        `pattern`, not the source text.
 * @return `SIZE_MAX` if `pattern` is unbounded (contains an unbounded
 *         repetition such as `*`/`+`/`{n,}`) or fails to parse at all (a
 *         bound cannot be proven either way, so the safe answer is
 *         "unbounded").
 */
inline std::size_t regex_max_len(const std::string& pattern) {
    re2::RegexpStatus status;
    re2::Regexp* parsed = re2::Regexp::Parse(pattern, re2::Regexp::LikePerl, &status);
    if (parsed == nullptr)
        return SIZE_MAX;
    const std::size_t result = detail::regexp_op_max_len(parsed);
    parsed->Decref();
    return result;
}

/**
 * @brief Builds the tolerant placeholder-recognition pattern for a masking
 *        placeholder name (e.g. "EMAIL", "DB_DSN") together with its
 *        RE2-parse-tree-derived max byte length.
 * @details The pattern always has exactly one capture group (the
 *          placeholder's numeric index) and is case-insensitive
 *          (`(?i)`-prefixed) so `<EMAIL_1>`, `< email - 12 >`, `<EMAIL-1>`
 *          all match. See the file-level doc comment for the full template
 *          and the multi-token join rule.
 * @throws RuleError{Code::UnboundedPlaceholder} if the built pattern turns
 *         out to be unbounded (see regex_max_len) -- unreachable for the
 *         fixed-shape template this function emits, kept as a defensive
 *         assertion.
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
