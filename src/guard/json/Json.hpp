/**
 * @file Json.hpp
 * @brief Byte-surgical JSON span scanner + splicer: the C++ equivalent of
 *        the `github.com/tidwall/gjson` (v1.19.0) / `github.com/tidwall/sjson`
 *        (v1.2.5) behavioral subset the Go reference (`_reference/
 *        guardrails-llm-filter`) actually uses at its `gjson.GetBytes` /
 *        `sjson.SetBytes` / `sjson.SetRawBytes` call sites (the
 *        `pkg/llmutils` subpackages' `extract.go` / `extract_response.go`
 *        files) plus `internal/sseproc/common/json.go`'s `MarshalNoEscape`
 *        and `demask_args.go`'s `DemaskJSONArguments`.
 * @details **Surgical byte-splicing, not parse/re-serialize** (spec §5):
 *          `find_value` returns a byte SPAN of a value inside the raw
 *          document instead of building a tree, and `splice`/`splice_all`
 *          patch replacement bytes directly into the original bytes. Every
 *          unmodeled field, key order, and number's exact literal form
 *          survives untouched outside the spliced span(s).
 *
 *          **Paths are pre-split, not dotted strings.** gjson/sjson address
 *          a value via a single dotted-and-escaped string
 *          (`"messages.0.content"`, with `\.` / `\\` escaping for keys that
 *          themselves contain a literal `.`). This port's `PathSeg` is a
 *          pre-split `vector<PathSeg>` instead — each segment is either an
 *          object key (already-decoded, arbitrary Unicode, no escaping
 *          rules to reverse-engineer) or an array index. This sidesteps
 *          gjson's dotted-path escaping grammar entirely: callers building
 *          a path (the Task 2.2-2.4 extractors) push segments directly, so
 *          there is no dotted-string round-trip and no escaping bugs to
 *          port.
 *
 *          **Duplicate keys: FIRST occurrence wins.** gjson is a byte
 *          scanner, not a map-builder: `Result.Get`/`parseObject` walk an
 *          object's keys left to right and return control to the caller the
 *          moment a matching key is found, never continuing the scan for a
 *          later duplicate. This is the OPPOSITE of `encoding/json`'s
 *          unmarshal-into-map behavior (later key wins, since each
 *          assignment overwrites the map slot) -- gjson's own docs/tests
 *          call this out as a deliberate divergence from stdlib. Since every
 *          `gjson.GetBytes`/`Result.Get` call in the Go reference's
 *          extractors is exactly this kind of scan, `find_value` below
 *          matches gjson: it returns as soon as it finds the first key
 *          equal to the requested segment, and never inspects a later
 *          duplicate in the same object.
 *
 *          **Invalid `\u` escape policy** (`decode_string`): mirrors Go's
 *          `encoding/json` string-unquoting (`decode.go`'s `unquote` +
 *          `unicode/utf16.DecodeRune`), read from the stdlib source rather
 *          than assumed. A `\uXXXX` that decodes to a UTF-16 surrogate half
 *          is resolved as a pair when immediately followed by a matching
 *          `\uXXXX` low/high surrogate (combined into one Unicode code
 *          point and encoded as one UTF-8 sequence); an UNPAIRED surrogate
 *          half (either kind) is replaced with U+FFFD (the standard
 *          replacement character) and only the 6 bytes of that ONE escape
 *          are consumed -- a dangling low surrogate right after it is then
 *          reprocessed independently on the next loop pass (itself becoming
 *          another U+FFFD if it, too, is unpaired). This is exactly Go's
 *          behavior: `unicode/utf16.DecodeRune` returns `unicode.
 *          ReplacementChar` for any non-surrogate-pair input, and `decode.go`
 *          only advances past the second `\u` escape when the combination
 *          actually succeeded.
 *
 *          **`encode_string` is `MarshalNoEscape` (`json.go`), not
 *          `json.Marshal`.** Go's default encoder rewrites `<`, `>`, `&`
 *          to their \u003c/\u003e/\u0026 escapes "for safety in HTML
 *          contexts";
 *          `MarshalNoEscape` calls `Encoder.SetEscapeHTML(false)` to turn
 *          that off, because rewriting a synthetic placeholder like
 *          `<EMAIL_1>` would stop a code-agent client from recognizing it.
 *          `encode_string` never escapes `<`, `>`, `&`, or `/` -- pinned by
 *          `GuardJson.EncodeStringDoesNotEscapeAngleBracketsOrAmpersand`.
 *          It DOES still escape U+2028/U+2029 (the line/paragraph
 *          separator code points): Go's
 *          `encoding/json/encode.go` escapes those two code points
 *          UNCONDITIONALLY, in a separate code path from the
 *          `escapeHTML`-gated `<`/`>`/`&`/backslash-tag table -- they are
 *          illegal raw line terminators inside a JavaScript string literal
 *          pre-ES2019, and `SetEscapeHTML(false)` does not touch that
 *          separate check. Matching it here means `encode_string` is a
 *          faithful `MarshalNoEscape` port, not just "don't escape HTML".
 *
 *          **Iterative, not recursive.** Every routine that walks into
 *          nested containers (`detail::skip_value`, `find_value`,
 *          `string_leaves`) uses an explicit `std::vector`-backed stack
 *          instead of native call recursion, so document nesting depth is
 *          bounded only by heap (tested to 1000 levels; no fixed limit
 *          below ~10k). `find_value`'s per-segment walk additionally never
 *          even needs a stack of its own: it loops over the caller-supplied
 *          `path` (bounded by the caller, not the document), using
 *          `detail::skip_value` as a black box to jump over sibling values
 *          it doesn't need to visit.
 *
 *          **Never throws on lookup.** `find_value`, `valid`, and
 *          `string_leaves` treat every malformed/truncated/type-mismatched
 *          input as "not found" (`std::nullopt` / empty vector), never an
 *          exception -- callers (the Task 2.2-2.4 extractors, whose
 *          "messages" format spec explicitly says "never errors") depend on
 *          this. `splice`/`splice_all` DO throw `std::runtime_error` for
 *          out-of-bounds or overlapping spans -- that is a programmer
 *          error (mismatched span/document pair, or two edits computed
 *          against the same document that collide), not a malformed-input
 *          case.
 *
 *          **`find_value_in`/`string_leaves_in` (added by Task 2.2) are
 *          scoped variants of `find_value`/`string_leaves`**: instead of
 *          walking from the document root, they resolve a path/walk a
 *          subtree relative to a caller-supplied `ValueSpan` container
 *          (itself previously returned by `find_value`/`find_value_in`
 *          against the SAME `doc`), then re-add `container.start` onto the
 *          result so it still lands in `doc`'s own byte offsets -- see
 *          either function's own doc comment for the full offset-readd
 *          contract. They exist so a caller walking many array/object
 *          siblings (e.g. a `messages`/`choices` array) can resolve each
 *          sibling's own fields in O(that sibling's size) rather than
 *          O(document size): looking up every field from the document root
 *          for every one of N siblings costs O(N * document size) overall,
 *          which is quadratic for a proxy request whose body size and
 *          message count both grow together -- confirmed as a real DoS
 *          regression (143ms @ 200 messages, 12.4s @ 2MB) against the first
 *          `find_value`-from-root-per-field extractor implementation
 *          (`Guard::Extract::ChatCompletions`, Task 2.2).
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Guard::Json {

/// Byte range `[start, end)` of one JSON value inside a raw document. For a
/// string value, the range INCLUDES the surrounding quotes (so `splice`ing
/// it out and back in never has to special-case re-adding them).
struct ValueSpan {
    std::size_t start;
    std::size_t end;
    bool is_string;
};

/// One segment of a path into a JSON document: either an object key
/// (`is_index == false`, `key` significant) or an array index
/// (`is_index == true`, `index` significant). See the file-level doc
/// comment for why this replaces gjson's dotted-and-escaped path strings.
struct PathSeg {
    std::string key;
    std::size_t index;
    bool is_index;
};

/// One STRING-valued leaf found by `string_leaves`, with the full path from
/// the document root (the `root` argument passed to `string_leaves`, plus
/// every key/index walked below it) and its span in the original document.
struct StringLeaf {
    std::vector<PathSeg> path;
    ValueSpan span;
};

namespace detail {

inline bool is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

inline std::size_t skip_ws(std::string_view doc, std::size_t pos) {
    while (pos < doc.size() && is_ws(doc[pos]))
        ++pos;
    return pos;
}

inline bool is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

// `lit` matched literally at `pos`, without ever forming an out-of-range
// std::string_view (unlike `doc.substr(pos, ...)`, which throws if
// `pos > doc.size()`); used for the `true`/`false`/`null` literals.
inline bool match_literal(std::string_view doc, std::size_t pos, std::string_view lit) {
    if (pos + lit.size() > doc.size())
        return false;
    return doc.compare(pos, lit.size(), lit) == 0;
}

// `pos` must index the opening quote. Returns the offset just past the
// closing quote, or nullopt for any malformed/truncated/invalid-escape
// string (including an unescaped control byte < 0x20, which RFC 8259
// requires to be escaped). Strict by design: both `valid()` and
// `find_value`'s lookup path share this scanner, so a document neither of
// them should accept never produces a bogus "found" span either.
inline std::optional<std::size_t> skip_string(std::string_view doc, std::size_t pos) {
    if (pos >= doc.size() || doc[pos] != '"')
        return std::nullopt;
    ++pos;
    while (true) {
        if (pos >= doc.size())
            return std::nullopt;
        const unsigned char c = static_cast<unsigned char>(doc[pos]);
        if (c == '"')
            return pos + 1;
        if (c == '\\') {
            ++pos;
            if (pos >= doc.size())
                return std::nullopt;
            switch (doc[pos]) {
                case '"':
                case '\\':
                case '/':
                case 'b':
                case 'f':
                case 'n':
                case 'r':
                case 't':
                    ++pos;
                    break;
                case 'u': {
                    ++pos;
                    if (pos + 4 > doc.size())
                        return std::nullopt;
                    for (std::size_t i = 0; i < 4; ++i) {
                        if (!is_hex_digit(doc[pos + i]))
                            return std::nullopt;
                    }
                    pos += 4;
                    break;
                }
                default:
                    return std::nullopt;
            }
            continue;
        }
        if (c < 0x20)
            return std::nullopt;
        ++pos;
    }
}

// Strict RFC 8259 number grammar: `-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?`.
// No leading zeros (other than a lone "0"), a digit required after '-',
// '.', and 'e'/'E'. Returns the offset just past the number, or nullopt.
inline std::optional<std::size_t> skip_number(std::string_view doc, std::size_t pos) {
    const std::size_t n = doc.size();
    const std::size_t start = pos;
    if (pos < n && doc[pos] == '-')
        ++pos;
    if (pos >= n || !is_digit(doc[pos]))
        return std::nullopt;
    if (doc[pos] == '0') {
        ++pos;
    } else {
        while (pos < n && is_digit(doc[pos]))
            ++pos;
    }
    if (pos < n && doc[pos] == '.') {
        ++pos;
        if (pos >= n || !is_digit(doc[pos]))
            return std::nullopt;
        while (pos < n && is_digit(doc[pos]))
            ++pos;
    }
    if (pos < n && (doc[pos] == 'e' || doc[pos] == 'E')) {
        ++pos;
        if (pos < n && (doc[pos] == '+' || doc[pos] == '-'))
            ++pos;
        if (pos >= n || !is_digit(doc[pos]))
            return std::nullopt;
        while (pos < n && is_digit(doc[pos]))
            ++pos;
    }
    if (pos == start)
        return std::nullopt;
    return pos;
}

// FSM states for `skip_value`'s explicit container stack. Named for "what
// this frame is waiting for next", mirroring a standard recursive-descent
// JSON grammar with the recursion flattened into a `std::vector<Frame>`.
enum class WalkState : std::uint8_t {
    ArrayStart,        // just saw '[': a value or ']' (empty array) is next
    ArrayAfterValue,   // just finished an element: ',' or ']' is next
    ArrayAfterComma,   // just saw ',': a value is next (no bare close)
    ObjectStart,       // just saw '{': a "key" or '}' (empty object) is next
    ObjectAfterKey,    // just finished a key string: ':' is next
    ObjectAfterColon,  // just saw ':': a value is next
    ObjectAfterValue,  // just finished a value: ',' or '}' is next
    ObjectAfterComma,  // just saw ',': a key string is next (no bare close)
};

struct WalkFrame {
    char kind;  // '{' or '['
    WalkState state;
};

#if defined(__GNUC__) || defined(__clang__)
#define GUARD_JSON_NOINLINE __attribute__((noinline))
#else
#define GUARD_JSON_NOINLINE
#endif

// Reads a scalar value or opens a container at `p`. A scalar returns its
// own end offset directly; an opener pushes a frame onto `frames`
// (invalidating any previously-held `WalkFrame&`/index taken before this
// call) and returns the offset just past the bracket.
//
// A separate, explicitly NOT-inlined function (not a lambda nested in
// `skip_value`, which is how this was first written) -- GCC 13 at -O3
// mis-inlines this function's two `push_back` call sites into `skip_value`
// at several of its own call sites simultaneously, and `noinline` avoids
// that. It is NOT, by itself, enough to silence the false positive below;
// see that comment for the rest of the story.
GUARD_JSON_NOINLINE inline std::optional<std::size_t> open_or_scalar(std::string_view doc,
                                                                     std::size_t p,
                                                                     std::vector<WalkFrame>& frames) {
    if (p >= doc.size())
        return std::nullopt;
    const char c = doc[p];
    if (c == '"')
        return skip_string(doc, p);
    if (c == '-' || is_digit(c))
        return skip_number(doc, p);
    if (c == 't')
        return match_literal(doc, p, "true") ? std::optional<std::size_t>(p + 4) : std::nullopt;
    if (c == 'f')
        return match_literal(doc, p, "false") ? std::optional<std::size_t>(p + 5) : std::nullopt;
    if (c == 'n')
        return match_literal(doc, p, "null") ? std::optional<std::size_t>(p + 4) : std::nullopt;

        // GCC 13 at -O3 has a confirmed false positive on these two
        // `push_back` calls: `-Werror=stringop-overflow` on
        // `vector<WalkFrame>::_M_realloc_insert`/`construct_at`'s inlined
        // placement-new, reported as "writing 1 byte into a region of size 0"
        // at a nonsensical NEGATIVE offset into an object GCC itself computed
        // as ~2^63 bytes -- internally self-contradictory, and independent of
        // both initial capacity (tried `frames.reserve(...)` first: no effect)
        // and caller-side inlining depth (tried extracting this whole function
        // with `noinline`, above: reduced the backtrace to a single inlining
        // chain but did not remove the warning). `WalkFrame` is a 2-byte
        // `{char; enum class : uint8_t;}` aggregate; this specific
        // size/layout combination through `vector::push_back` under `-O3`
        // matches publicly reported GCC 12/13 `-Wstringop-overflow`
        // false-positive reports (e.g. GCC PR 106252-class reallocation
        // mis-analysis) rather than anything this scanner does with the
        // vector -- `frames` is a plain local `std::vector`, standard
        // `push_back` on a POD, nothing more exotic. Suppressed at exactly
        // these two call sites (not project-wide, not for the warning class
        // in general -- `-Wstringop-overflow` stays fully enabled and gating
        // for every other line in this codebase) with a paired push/pop so
        // the scope is unambiguous. Not reachable on Clang, which has no
        // `-Wstringop-overflow` diagnostic to begin with.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
    if (c == '{') {
        frames.push_back(WalkFrame{'{', WalkState::ObjectStart});
        return p + 1;
    }
    if (c == '[') {
        frames.push_back(WalkFrame{'[', WalkState::ArrayStart});
        return p + 1;
    }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
    return std::nullopt;
}

#undef GUARD_JSON_NOINLINE

// Skips exactly one JSON value starting at (or after, via an internal
// skip_ws) `pos`, however deeply nested, and returns the offset just past
// it -- or nullopt for any malformed input. Nesting is walked with an
// explicit `frames` stack rather than native recursion (see the file-level
// doc comment), so this has no fixed depth limit below what the heap can
// hold. Never inspects anything beyond the single value it is asked to
// skip -- trailing-garbage detection is `valid()`'s job, not this
// function's.
inline std::optional<std::size_t> skip_value(std::string_view doc, std::size_t pos) {
    pos = skip_ws(doc, pos);
    if (pos >= doc.size())
        return std::nullopt;

    std::vector<WalkFrame> frames;

    // A container frame just closed (already popped): tell the newly-
    // exposed parent frame, if any, that one of ITS values just completed.
    auto complete_value_in_parent = [&]() {
        if (frames.empty())
            return;
        frames.back().state = (frames.back().kind == '[') ? WalkState::ArrayAfterValue : WalkState::ObjectAfterValue;
    };

    {
        const auto r = open_or_scalar(doc, pos, frames);
        if (!r)
            return std::nullopt;
        pos = *r;
        if (frames.empty())
            return pos;  // the whole value was a scalar
    }

    while (!frames.empty()) {
        const std::size_t idx = frames.size() - 1;
        const WalkState state = frames[idx].state;
        pos = skip_ws(doc, pos);
        if (pos >= doc.size())
            return std::nullopt;

        switch (state) {
            case WalkState::ArrayStart:
                if (doc[pos] == ']') {
                    frames.pop_back();
                    ++pos;
                    complete_value_in_parent();
                    if (frames.empty())
                        return pos;
                    break;
                }
                [[fallthrough]];
            case WalkState::ArrayAfterComma: {
                const auto r = open_or_scalar(doc, pos, frames);
                if (!r)
                    return std::nullopt;
                pos = *r;
                if (frames.size() == idx + 1)
                    frames[idx].state = WalkState::ArrayAfterValue;
                break;
            }
            case WalkState::ArrayAfterValue: {
                if (doc[pos] == ']') {
                    frames.pop_back();
                    ++pos;
                    complete_value_in_parent();
                    if (frames.empty())
                        return pos;
                } else if (doc[pos] == ',') {
                    ++pos;
                    frames[idx].state = WalkState::ArrayAfterComma;
                } else {
                    return std::nullopt;
                }
                break;
            }
            case WalkState::ObjectStart:
                if (doc[pos] == '}') {
                    frames.pop_back();
                    ++pos;
                    complete_value_in_parent();
                    if (frames.empty())
                        return pos;
                    break;
                }
                [[fallthrough]];
            case WalkState::ObjectAfterComma: {
                if (doc[pos] != '"')
                    return std::nullopt;
                const auto r = skip_string(doc, pos);
                if (!r)
                    return std::nullopt;
                pos = *r;
                frames[idx].state = WalkState::ObjectAfterKey;
                break;
            }
            case WalkState::ObjectAfterKey: {
                if (doc[pos] != ':')
                    return std::nullopt;
                ++pos;
                frames[idx].state = WalkState::ObjectAfterColon;
                break;
            }
            case WalkState::ObjectAfterColon: {
                const auto r = open_or_scalar(doc, pos, frames);
                if (!r)
                    return std::nullopt;
                pos = *r;
                if (frames.size() == idx + 1)
                    frames[idx].state = WalkState::ObjectAfterValue;
                break;
            }
            case WalkState::ObjectAfterValue: {
                if (doc[pos] == '}') {
                    frames.pop_back();
                    ++pos;
                    complete_value_in_parent();
                    if (frames.empty())
                        return pos;
                } else if (doc[pos] == ',') {
                    ++pos;
                    frames[idx].state = WalkState::ObjectAfterComma;
                } else {
                    return std::nullopt;
                }
                break;
            }
        }
    }
    return pos;  // unreachable: the loop above always returns once frames empties
}

inline void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// Parses exactly 4 hex digits at `p` (all within `body`), or nullopt if
// out of range or non-hex. Caller already knows a well-formed string
// (found via `skip_string`) has 4 valid hex digits after every `\u` it
// contains, so failure here only happens against a hand-built/adversarial
// span passed directly to `decode_string` -- handled by best-effort
// fallback in the caller, never an exception (see the file-level doc
// comment's "never throws on lookup", which `decode_string` also honors).
inline std::optional<std::uint16_t> read_hex4(std::string_view body, std::size_t p) {
    if (p + 4 > body.size())
        return std::nullopt;
    std::uint16_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        const char c = body[p + i];
        std::uint16_t d;
        if (c >= '0' && c <= '9')
            d = static_cast<std::uint16_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = static_cast<std::uint16_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            d = static_cast<std::uint16_t>(c - 'A' + 10);
        else
            return std::nullopt;
        v = static_cast<std::uint16_t>((v << 4) | d);
    }
    return v;
}

}  // namespace detail

/// Unescapes a JSON string literal SPAN (`quoted` includes the surrounding
/// quotes, matching `ValueSpan`'s convention for string values) into its
/// decoded UTF-8 content. See the file-level doc comment for the invalid-
/// `\u`-escape (unpaired surrogate) policy, mirrored from Go's
/// `encoding/json` decoder. `quoted` is assumed to already be a valid JSON
/// string literal (e.g. from a `find_value`/`string_leaves` span, or a
/// document that passed `valid()`) -- if it is not (missing quotes,
/// truncated escape), this degrades to a best-effort decode rather than
/// throwing, consistent with every other lookup in this file never
/// throwing on malformed input.
inline std::string decode_string(std::string_view quoted) {
    if (quoted.size() < 2 || quoted.front() != '"' || quoted.back() != '"')
        return std::string(quoted);  // not a well-formed span; best-effort passthrough

    const std::string_view body = quoted.substr(1, quoted.size() - 2);
    std::string out;
    out.reserve(body.size());

    std::size_t i = 0;
    while (i < body.size()) {
        const char c = body[i];
        if (c != '\\') {
            out.push_back(c);
            ++i;
            continue;
        }
        ++i;
        if (i >= body.size())
            break;  // truncated escape at the very end: stop (best-effort)
        const char e = body[i];
        switch (e) {
            case '"':
                out.push_back('"');
                ++i;
                break;
            case '\\':
                out.push_back('\\');
                ++i;
                break;
            case '/':
                out.push_back('/');
                ++i;
                break;
            case 'b':
                out.push_back('\b');
                ++i;
                break;
            case 'f':
                out.push_back('\f');
                ++i;
                break;
            case 'n':
                out.push_back('\n');
                ++i;
                break;
            case 'r':
                out.push_back('\r');
                ++i;
                break;
            case 't':
                out.push_back('\t');
                ++i;
                break;
            case 'u': {
                ++i;
                const auto h1 = detail::read_hex4(body, i);
                if (!h1) {
                    detail::append_utf8(out, 0xFFFD);
                    break;  // truncated/invalid \u at end of a malformed span
                }
                const std::uint16_t r = *h1;
                i += 4;
                if (r >= 0xD800 && r <= 0xDBFF) {
                    // High surrogate: a valid pair needs an immediately
                    // following "\uDCxx"-"\uDFxx".
                    bool paired = false;
                    if (i + 1 < body.size() && body[i] == '\\' && body[i + 1] == 'u') {
                        const auto h2 = detail::read_hex4(body, i + 2);
                        if (h2 && *h2 >= 0xDC00 && *h2 <= 0xDFFF) {
                            const std::uint32_t cp = 0x10000U + ((static_cast<std::uint32_t>(r) - 0xD800U) << 10) +
                                                     (static_cast<std::uint32_t>(*h2) - 0xDC00U);
                            detail::append_utf8(out, cp);
                            i += 6;  // consumed the second \uXXXX too
                            paired = true;
                        }
                    }
                    if (!paired)
                        detail::append_utf8(out, 0xFFFD);  // unpaired high surrogate
                } else if (r >= 0xDC00 && r <= 0xDFFF) {
                    detail::append_utf8(out, 0xFFFD);  // unpaired low surrogate
                } else {
                    detail::append_utf8(out, r);
                }
                break;
            }
            default:
                out.push_back(e);  // malformed escape char; best-effort passthrough
                ++i;
                break;
        }
    }
    return out;
}

/// Encodes `raw` (assumed valid UTF-8 -- this does not itself repair
/// invalid UTF-8, unlike Go's `encoding/json` which substitutes U+FFFD for
/// it) as a JSON string literal, optionally with the surrounding quotes.
/// This is `MarshalNoEscape`, not `json.Marshal`: see the file-level doc
/// comment for exactly which characters are/aren't escaped and why.
inline std::string encode_string(std::string_view raw, bool with_quotes) {
    std::string out;
    out.reserve(raw.size() + (with_quotes ? 2 : 0));
    if (with_quotes)
        out.push_back('"');

    std::size_t i = 0;
    while (i < raw.size()) {
        const unsigned char c = static_cast<unsigned char>(raw[i]);
        switch (c) {
            case '"':
                out += "\\\"";
                ++i;
                continue;
            case '\\':
                out += "\\\\";
                ++i;
                continue;
            case '\b':
                out += "\\b";
                ++i;
                continue;
            case '\f':
                out += "\\f";
                ++i;
                continue;
            case '\n':
                out += "\\n";
                ++i;
                continue;
            case '\r':
                out += "\\r";
                ++i;
                continue;
            case '\t':
                out += "\\t";
                ++i;
                continue;
            default:
                break;
        }
        if (c < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
            ++i;
            continue;
        }
        // U+2028/U+2029 (UTF-8 E2 80 A8 / E2 80 A9): escaped unconditionally,
        // independent of the HTML-escaping table -- see the file-level doc
        // comment.
        if (c == 0xE2 && i + 2 < raw.size() && static_cast<unsigned char>(raw[i + 1]) == 0x80 &&
            (static_cast<unsigned char>(raw[i + 2]) == 0xA8 || static_cast<unsigned char>(raw[i + 2]) == 0xA9)) {
            out += (static_cast<unsigned char>(raw[i + 2]) == 0xA8) ? "\\u2028" : "\\u2029";
            i += 3;
            continue;
        }
        // Deliberately NOT escaped: '<', '>', '&' (MarshalNoEscape parity)
        // and '/' (Go never escapes it by default either). Every other byte,
        // including UTF-8 continuation bytes, is copied through verbatim.
        out.push_back(static_cast<char>(c));
        ++i;
    }
    if (with_quotes)
        out.push_back('"');
    return out;
}

/// Strict RFC 8259 validity: exactly one JSON value, optionally surrounded
/// by whitespace, and nothing else. A lone scalar (`"42"`, `"true"`,
/// `"\"hi\""`) is valid per RFC 8259 §2 ("a JSON text is a serialized
/// value... valid JSON texts include a top-level number, string, or
/// boolean/null"); trailing bytes after the value (even just one stray
/// character) make the whole document invalid.
inline bool valid(std::string_view doc) {
    const std::size_t start = detail::skip_ws(doc, 0);
    if (start >= doc.size())
        return false;
    const auto end = detail::skip_value(doc, start);
    if (!end)
        return false;
    return detail::skip_ws(doc, *end) == doc.size();
}

/// Path-addressed span lookup over raw document bytes -- the C++ equivalent
/// of `gjson.GetBytes(body, path)`. `path` is empty ⇒ returns the whole
/// document's root value. Never throws; returns `nullopt` for a missing
/// key/out-of-range index, a type mismatch (e.g. an index segment against
/// an object), or any malformed JSON encountered along the way. See the
/// file-level doc comment for the duplicate-key (first wins) and
/// no-native-recursion design notes.
inline std::optional<ValueSpan> find_value(std::string_view doc, const std::vector<PathSeg>& path) {
    std::size_t pos = detail::skip_ws(doc, 0);
    if (pos >= doc.size())
        return std::nullopt;

    for (std::size_t si = 0; si < path.size(); ++si) {
        const PathSeg& seg = path[si];
        const bool is_last = (si + 1 == path.size());
        pos = detail::skip_ws(doc, pos);
        if (pos >= doc.size())
            return std::nullopt;

        if (seg.is_index) {
            if (doc[pos] != '[')
                return std::nullopt;
            ++pos;
            std::size_t idx = 0;
            while (true) {
                pos = detail::skip_ws(doc, pos);
                if (pos >= doc.size())
                    return std::nullopt;
                if (doc[pos] == ']')
                    return std::nullopt;  // empty array, or index out of range
                const auto ve = detail::skip_value(doc, pos);
                if (!ve)
                    return std::nullopt;
                if (idx == seg.index) {
                    if (is_last)
                        return ValueSpan{pos, *ve, doc[pos] == '"'};
                    break;  // `pos` already == this element's start; descend
                }
                pos = detail::skip_ws(doc, *ve);
                if (pos >= doc.size())
                    return std::nullopt;
                if (doc[pos] == ',') {
                    ++pos;
                    ++idx;
                    continue;
                }
                if (doc[pos] == ']')
                    return std::nullopt;
                return std::nullopt;
            }
        } else {
            if (doc[pos] != '{')
                return std::nullopt;
            ++pos;
            while (true) {
                pos = detail::skip_ws(doc, pos);
                if (pos >= doc.size())
                    return std::nullopt;
                if (doc[pos] == '}')
                    return std::nullopt;  // key not found
                if (doc[pos] != '"')
                    return std::nullopt;
                const auto ke = detail::skip_string(doc, pos);
                if (!ke)
                    return std::nullopt;
                const std::string key = decode_string(doc.substr(pos, *ke - pos));
                pos = detail::skip_ws(doc, *ke);
                if (pos >= doc.size() || doc[pos] != ':')
                    return std::nullopt;
                ++pos;
                pos = detail::skip_ws(doc, pos);
                if (pos >= doc.size())
                    return std::nullopt;
                const auto ve = detail::skip_value(doc, pos);
                if (!ve)
                    return std::nullopt;
                if (key == seg.key) {
                    if (is_last)
                        return ValueSpan{pos, *ve, doc[pos] == '"'};
                    break;  // `pos` already == this value's start; descend
                }
                pos = detail::skip_ws(doc, *ve);
                if (pos >= doc.size())
                    return std::nullopt;
                if (doc[pos] == ',') {
                    ++pos;
                    continue;
                }
                if (doc[pos] == '}')
                    return std::nullopt;
                return std::nullopt;
            }
        }
    }

    // path.empty(): the whole root value.
    const auto ve = detail::skip_value(doc, pos);
    if (!ve)
        return std::nullopt;
    return ValueSpan{pos, *ve, doc[pos] == '"'};
}

/// Scoped variant of `find_value`: resolves `relative_path` starting from
/// `container` (a `ValueSpan` previously returned by `find_value`/
/// `find_value_in` against this same `doc`) instead of the document root.
/// Implemented by delegating to `find_value` over
/// `doc.substr(container.start, container.end - container.start)` --
/// itself O(1), since `string_view::substr` only adjusts a pointer/length
/// pair, never copies -- and re-adding `container.start` onto BOTH fields
/// of whatever span that returns before handing it back, so the result
/// stays expressed in `doc`'s own (not the substring's) byte offsets,
/// exactly like every other `ValueSpan` this file produces. This is the
/// offset-readd contract every caller of this function relies on: a
/// `find_value_in` result is always directly comparable/splice-able
/// against the ORIGINAL `doc`, never against the intermediate substring.
///
/// Exists to keep a caller that walks an array/object of many siblings
/// (e.g. one `ContentField` per element of a `messages`/`choices` array)
/// OUT of `find_value`'s O(document size) per-lookup cost: resolve the
/// containing array/object's span ONCE via `find_value`, then resolve each
/// sibling and its nested fields via `find_value_in` scoped to that span
/// (or to a previously-`find_value_in`-resolved sibling's own span, for
/// fields nested more than one level below the container) -- each lookup
/// then costs O(that element's size), and the elements' sizes sum to at
/// most `doc`'s size, so a whole array walk is O(document size) instead of
/// O(element count * document size). `Guard::Extract::ChatCompletions`
/// (Task 2.2) is the first caller that needed this, after an unscoped,
/// find-value-from-root-per-field implementation measured quadratic on
/// large request bodies.
///
/// An out-of-bounds `container` (shouldn't happen for a span this file
/// itself produced, but checked anyway per this file's "never throws on
/// lookup" convention) yields `std::nullopt`, same as a missing key/index.
inline std::optional<ValueSpan> find_value_in(std::string_view doc,
                                              const ValueSpan& container,
                                              const std::vector<PathSeg>& relative_path) {
    if (container.start > container.end || container.end > doc.size())
        return std::nullopt;

    const std::string_view sub = doc.substr(container.start, container.end - container.start);
    const auto found = find_value(sub, relative_path);
    if (!found)
        return std::nullopt;
    return ValueSpan{found->start + container.start, found->end + container.start, found->is_string};
}

/// Replaces `[span.start, span.end)` in `doc` with `replacement` (already
/// JSON-encoded by the caller, e.g. via `encode_string`). Every byte
/// outside the span is copied through unchanged. Throws
/// `std::runtime_error` if `span` does not describe a valid range within
/// `doc` -- a programmer error (a span computed against a different
/// document, most likely), not a malformed-input case.
inline std::string splice(std::string_view doc, const ValueSpan& span, std::string_view replacement) {
    if (span.start > span.end || span.end > doc.size())
        throw std::runtime_error("Guard::Json::splice: span out of bounds for this document");

    std::string out;
    out.reserve(doc.size() - (span.end - span.start) + replacement.size());
    out.append(doc.substr(0, span.start));
    out.append(replacement);
    out.append(doc.substr(span.end));
    return out;
}

/// Applies multiple non-overlapping edits to `doc` in one pass. Edits are
/// sorted by `span.start`, checked for out-of-bounds/overlap (any two spans
/// with `start < ` the other's `end` throws `std::runtime_error` --
/// programmer error, since the extractors/demasker that build an edit list
/// are expected to compute disjoint spans), then applied via repeated
/// `splice()` calls in REVERSE-offset (highest `start` first) order so that
/// an edit already applied never shifts the byte offsets of a
/// not-yet-applied one earlier in the document.
inline std::string splice_all(std::string_view doc, const std::vector<std::pair<ValueSpan, std::string>>& edits) {
    if (edits.empty())
        return std::string(doc);

    std::vector<std::size_t> order(edits.size());
    for (std::size_t i = 0; i < order.size(); ++i)
        order[i] = i;
    std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
        return edits[a].first.start < edits[b].first.start;
    });

    for (std::size_t i = 0; i < order.size(); ++i) {
        const ValueSpan& s = edits[order[i]].first;
        if (s.start > s.end || s.end > doc.size())
            throw std::runtime_error("Guard::Json::splice_all: span out of bounds for this document");
        if (i > 0 && s.start < edits[order[i - 1]].first.end)
            throw std::runtime_error("Guard::Json::splice_all: overlapping edit spans");
    }

    std::string out(doc);
    for (auto it = order.rbegin(); it != order.rend(); ++it)
        out = splice(out, edits[*it].first, edits[*it].second);
    return out;
}

namespace detail {

// One pending node in `string_leaves`'s explicit walk stack: the value at
// `pos` (post-whitespace) is to be visited under `path`.
struct WalkTask {
    std::vector<PathSeg> path;
    std::size_t pos;
};

}  // namespace detail

/// Walks every STRING-valued leaf under the value found at `root`, in
/// document order (depth-first, left to right through both object keys and
/// array elements), skipping non-string leaves (numbers/booleans/null)
/// entirely. `root` not resolving to a value (missing/malformed) yields an
/// empty result, never a throw -- consistent with every other lookup in
/// this file. Iterative: the walk uses an explicit `std::vector`-backed
/// task stack (see the file-level doc comment), pushing each container's
/// immediate children in reverse so the leftmost pops -- and is therefore
/// visited -- first.
inline std::vector<StringLeaf> string_leaves(std::string_view doc, const std::vector<PathSeg>& root) {
    std::vector<StringLeaf> result;
    const auto root_span = find_value(doc, root);
    if (!root_span)
        return result;

    std::vector<detail::WalkTask> stack;
    stack.push_back(detail::WalkTask{root, root_span->start});

    while (!stack.empty()) {
        detail::WalkTask task = std::move(stack.back());
        stack.pop_back();

        std::size_t pos = detail::skip_ws(doc, task.pos);
        if (pos >= doc.size())
            continue;  // malformed subtree: contribute no leaves, don't throw

        if (doc[pos] == '"') {
            const auto e = detail::skip_string(doc, pos);
            if (e)
                result.push_back(StringLeaf{task.path, ValueSpan{pos, *e, true}});
            continue;
        }

        if (doc[pos] == '{') {
            std::vector<detail::WalkTask> children;
            std::size_t p = pos + 1;
            bool ok = true;
            while (true) {
                p = detail::skip_ws(doc, p);
                if (p >= doc.size()) {
                    ok = false;
                    break;
                }
                if (doc[p] == '}') {
                    ++p;
                    break;
                }
                if (doc[p] != '"') {
                    ok = false;
                    break;
                }
                const auto ke = detail::skip_string(doc, p);
                if (!ke) {
                    ok = false;
                    break;
                }
                const std::string key = decode_string(doc.substr(p, *ke - p));
                p = detail::skip_ws(doc, *ke);
                if (p >= doc.size() || doc[p] != ':') {
                    ok = false;
                    break;
                }
                ++p;
                p = detail::skip_ws(doc, p);
                if (p >= doc.size()) {
                    ok = false;
                    break;
                }
                const auto ve = detail::skip_value(doc, p);
                if (!ve) {
                    ok = false;
                    break;
                }
                std::vector<PathSeg> child_path = task.path;
                child_path.push_back(PathSeg{key, 0, false});
                children.push_back(detail::WalkTask{std::move(child_path), p});
                p = detail::skip_ws(doc, *ve);
                if (p >= doc.size()) {
                    ok = false;
                    break;
                }
                if (doc[p] == ',') {
                    ++p;
                    continue;
                }
                if (doc[p] == '}') {
                    ++p;
                    break;
                }
                ok = false;
                break;
            }
            if (!ok)
                continue;
            for (auto it = children.rbegin(); it != children.rend(); ++it)
                stack.push_back(std::move(*it));
            continue;
        }

        if (doc[pos] == '[') {
            std::vector<detail::WalkTask> children;
            std::size_t p = detail::skip_ws(doc, pos + 1);
            bool ok = true;
            if (p < doc.size() && doc[p] == ']') {
                // empty array: no children
            } else {
                std::size_t idx = 0;
                while (true) {
                    p = detail::skip_ws(doc, p);
                    if (p >= doc.size()) {
                        ok = false;
                        break;
                    }
                    const auto ve = detail::skip_value(doc, p);
                    if (!ve) {
                        ok = false;
                        break;
                    }
                    std::vector<PathSeg> child_path = task.path;
                    child_path.push_back(PathSeg{"", idx, true});
                    children.push_back(detail::WalkTask{std::move(child_path), p});
                    ++idx;
                    p = detail::skip_ws(doc, *ve);
                    if (p >= doc.size()) {
                        ok = false;
                        break;
                    }
                    if (doc[p] == ',') {
                        ++p;
                        continue;
                    }
                    if (doc[p] == ']')
                        break;
                    ok = false;
                    break;
                }
            }
            if (!ok)
                continue;
            for (auto it = children.rbegin(); it != children.rend(); ++it)
                stack.push_back(std::move(*it));
            continue;
        }

        // number / true / false / null / malformed scalar: not a string leaf.
    }

    return result;
}

/// Scoped variant of `string_leaves`: walks `relative_root` starting from
/// `container` (a `ValueSpan` previously returned by `find_value`/
/// `find_value_in` against this same `doc`) instead of the document root.
/// Same offset-readd contract as `find_value_in` (see its doc comment):
/// implemented by delegating to `string_leaves` over
/// `doc.substr(container.start, container.end - container.start)`, then
/// adding `container.start` onto every returned leaf's `span.start`/
/// `span.end` so each leaf's span is expressed in `doc`'s own byte offsets.
/// `relative_root` is walked relative to `container`, exactly as
/// `find_value_in`'s `relative_path` is -- an empty `relative_root` walks
/// every string leaf under `container` itself. Exists for the same reason
/// `find_value_in` does (see its doc comment): a caller that already holds
/// an element's span (e.g. one array element out of many) can walk its
/// string leaves in O(that element's size) instead of O(document size).
inline std::vector<StringLeaf> string_leaves_in(std::string_view doc,
                                                const ValueSpan& container,
                                                const std::vector<PathSeg>& relative_root) {
    if (container.start > container.end || container.end > doc.size())
        return {};

    const std::string_view sub = doc.substr(container.start, container.end - container.start);
    std::vector<StringLeaf> leaves = string_leaves(sub, relative_root);
    for (StringLeaf& leaf : leaves) {
        leaf.span.start += container.start;
        leaf.span.end += container.start;
    }
    return leaves;
}

}  // namespace Guard::Json
