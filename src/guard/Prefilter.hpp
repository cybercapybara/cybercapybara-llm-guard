/**
 * @file Prefilter.hpp
 * @brief Recall-preserving keyword-prefilter prover: proves whether every
 *        match of a regex is guaranteed to contain at least one of a set of
 *        keywords, so the scanner can skip a rule's (potentially expensive)
 *        regex entirely when none of its keywords appear in the text.
 * @details Ports `pkg/guardrails/regex/registry/registry.go`'s
 *          `regexGuaranteesKeyword` + `foldSafeForToLower`.
 *
 *          IMPLEMENTATION NOTE -- why a hand-rolled parser instead of walking
 *          RE2's own parse tree: the natural port of the Go reference (which
 *          walks `regexp/syntax`'s parsed tree via `syntax.Parse`) is to walk
 *          RE2's equivalent internal tree via `re2::Regexp::Parse`, declared
 *          in `re2/regexp.h`. That header is RE2's *internal* API and is not
 *          installed by the vcpkg `re2` port (the exact wall
 *          `PlaceholderRegex.hpp`'s `regex_max_len` hit first -- see that
 *          file's doc comment). This file follows the same sanctioned
 *          approach: a small recursive-descent parser
 *          (`detail::PrefilterParser`) over the *same* restricted RE2/Perl
 *          regex subset `PlaceholderRegex.hpp`'s `BoundedLengthParser`
 *          supports (this parser is modeled directly on that one's
 *          structure -- same grammar, same escape handling, same conservative
 *          refusals -- but instead of computing a byte-length bound, it
 *          builds a small AST (`detail::Node`) and walks it to decide keyword
 *          guarantee). ANY construct outside that subset, or any malformed
 *          input, is refused conservatively: the affected AST node becomes
 *          `Node::Kind::Unsupported`, which `guarantees_keyword` (below)
 *          always treats as "cannot prove" at that node -- never a crash,
 *          never an incorrect "true". A handful of constructs (an unclosed
 *          group, a stray `)`/`]`/quantifier-without-operand, trailing
 *          unconsumed input) can't even be structurally parsed; those throw
 *          `detail::PrefilterParseFailure`, caught once at the top of
 *          `regex_guarantees_keyword` and turned into an overall `false` --
 *          the same safe default as every other unprovable case.
 *
 *          GO-OP-TO-PARSER-NODE MAPPING (`regexGuaranteesKeyword`, read line
 *          by line against `Node::Kind` and `guarantees_keyword` below):
 *            - `syntax.OpLiteral`  -> `Node::Kind::Literal`: a maximal run of
 *              consecutive un-quantified literal characters (adjacent literal
 *              atoms are merged into one node exactly as Go's own parser
 *              merges consecutive `OpLiteral` runes -- see "LITERAL RUN
 *              MERGING" below). Guarantee: fold-safety check, then
 *              case-fold-insensitive-safe substring containment against each
 *              keyword.
 *            - `syntax.OpConcat`   -> `Node::Kind::Concat`: guarantee if ANY
 *              child guarantees (every child is present in the match, so one
 *              guaranteeing child suffices).
 *            - `syntax.OpAlternate` -> `Node::Kind::Alternate`: guarantee only
 *              if EVERY branch guarantees (the match takes exactly one
 *              branch, so nothing less than all of them suffices) and there
 *              is at least one branch.
 *            - `syntax.OpPlus`     -> `Node::Kind::Repeat` with `min == 1`:
 *              guarantee = recurse into the operand (at least one copy is
 *              always present).
 *            - `syntax.OpRepeat`   -> `Node::Kind::Repeat` with `min` taken
 *              from `{m}`/`{m,n}`/`{m,}`: guarantee = `min >= 1` and the
 *              operand guarantees (mirrors Go's `if re.Min == 0 { return
 *              false }`).
 *            - `syntax.OpCapture`  -> `Node::Kind::Capture`: guarantee =
 *              recurse into the single child (both plain `(...)` and named
 *              `(?P<name>...)` groups -- Go's parser produces `OpCapture` for
 *              both). A non-capturing group `(?:...)` and a `(?i:...)` /
 *              `(?flags:...)` group produce NO wrapping node at all in Go's
 *              parser (the inner expression appears directly in the parent);
 *              this parser mirrors that by returning the inner node
 *              unwrapped ("transparent" group -- see `parse_group`).
 *            - everything else (`OpStar`, `OpQuest`, `OpCharClass`,
 *              `OpAnyChar(NotNL)`, `OpBeginLine`/`OpEndLine`/`OpBeginText`/
 *              `OpEndText`/`OpWordBoundary`/`OpNoWordBoundary`,
 *              `OpEmptyMatch`, and Go's `default:` catch-all for anything
 *              else) -> `Node::Kind::Unsupported` (or, for `*`/`?`,
 *              `Node::Kind::Repeat` with `min == 0`, which `guarantees_keyword`
 *              treats identically to `Unsupported` -- `min == 0` always
 *              returns `false` without even looking at the operand): none of
 *              these can guarantee a keyword, but -- critically -- they are
 *              still ordinary nodes inside their parent `Concat`/`Alternate`,
 *              so a sibling later in the same concat (or the pattern) can
 *              still supply the guarantee. This is why `Unsupported` must be
 *              a *local*, not a global, failure: the "vendor context literal"
 *              test vector `(?i)[\w.-]{0,50}?(?:adobe)[\s'"]{0,3}(...)` proves
 *              a keyword ("adobe") despite starting with an unprovable
 *              `[\w.-]{0,50}?` charclass-repeat, because `OpConcat`'s "any
 *              child suffices" rule finds the guarantee in a later sibling.
 *
 *          LITERAL RUN MERGING: Go's parser (and `Simplify()`) coalesces
 *          consecutive literal runes with the same `FoldCase` flag into one
 *          `OpLiteral` node before `regexGuaranteesKeyword` ever runs, so
 *          e.g. `secret=` is a single 7-rune literal, not seven one-rune
 *          concat children -- which matters, because `strings.Contains` (and
 *          this port's substring check) needs the *whole* run in one string
 *          to find a multi-character keyword. `detail::PrefilterParser`
 *          reproduces this explicitly in `parse_concat`: a plain literal atom
 *          (no quantifier applied, same `fold_case_` value as the pending
 *          run) is appended to an in-progress `Node::Kind::Literal`'s
 *          `literal` string rather than becoming its own concat child; the
 *          run is flushed (pushed as a concat child) the moment a
 *          non-mergeable piece (anything quantified, or any non-Literal
 *          node) is encountered.
 *
 *          FOLD-SAFETY PORT (`foldSafeForToLower`): Go's version walks
 *          `unicode.SimpleFold`'s *general* per-rune fold-orbit table -- the
 *          full Unicode case-folding equivalence classes -- checking that
 *          every rune in a literal's fold orbit lowers (via
 *          `unicode.ToLower`) to the same value as the rune itself. C++ has
 *          no equivalent of that table available without pulling in a
 *          full ICU-class dependency (`utf8proc`, already a dependency via
 *          `Unicode.hpp`, exposes `tolower`/`toupper` per codepoint but not a
 *          "walk the fold orbit" enumerator). Rather than approximate that
 *          missing table with a partial one, this port uses a conservative,
 *          exactly-verified-safe substitute (`detail::literal_is_fold_safe`):
 *            - Not case-insensitive at all (`fold_case == false`): always
 *              safe -- the literal matches verbatim, and the pre-filter
 *              lowercases both sides, so they always agree (mirrors Go's
 *              `if !foldCase { return true }` short-circuit exactly).
 *            - An ASCII rune, case-insensitive: safe for every ASCII letter
 *              EXCEPT `s`/`S`, which is the one documented ASCII cross-fold
 *              that actually diverges under `strings.ToLower` -- ASCII `s`/
 *              `S` fold (under RE2/Go's default Unicode simple folding) with
 *              U+017F LATIN SMALL LETTER LONG S (`ſ`), whose own lowercase
 *              mapping is itself, not `s` -- traced by hand against
 *              `unicode.SimpleFold`'s documented orbit and confirmed against
 *              `TestCompileRule_PrefilterKeywords`'s "long-s cross-fold"
 *              vector. (ASCII `k`/`K` is NOT included here despite
 *              `PlaceholderRegex.hpp`'s doc comment grouping `s`/`k` together
 *              for its own, unrelated, purpose -- byte-*width* padding. Traced
 *              by hand: `k`/`K`'s fold orbit adds U+212A KELVIN SIGN, but
 *              KELVIN SIGN's own lowercase mapping IS `k`, so `k`/`K`'s orbit
 *              is fold-*safe* even though it is fold-*wide* -- two different
 *              properties this file and that one each care about one of.)
 *            - A non-ASCII rune, case-insensitive: conservatively UNSAFE,
 *              unconditionally. This is deliberately broader than Go's exact
 *              answer would be for every possible input (Go's algorithm would
 *              accept plenty of non-ASCII case-insensitive literals whose
 *              fold orbits happen to be internally consistent), but it is
 *              never *wrong* in the unsafe direction that matters: this
 *              function's only job is to gate whether a literal is safe to
 *              use for prefiltering, and marking something unsafe when it
 *              might actually be safe only costs a rule its prefilter
 *              eligibility (always-scanned, same as any other "can't prove"
 *              case) -- it can never cause a real match to be silently
 *              dropped, which is the one failure mode this whole feature must
 *              never have. Verified exactly against every fold-related vector
 *              in `TestCompileRule_PrefilterKeywords` (the ASCII `bearer` /
 *              non-ASCII `паспорт` cases stay eligible because neither uses
 *              `(?i)`; the Greek `(?i)ΣΤΑ` and ASCII `(?i)secret=...` cases
 *              go ineligible -- `ΣΤΑ` via the non-ASCII branch, `secret=...`
 *              via the ASCII `s` special case) and against
 *              `prefilter_unicode_test.go`'s corpus (every body in that test
 *              is scanned prefilter-on vs. prefilter-off for equivalence, not
 *              for a specific eligibility verdict -- this file's own
 *              `tests/unit/test_guard_prefilter.cpp` ports the same bodies
 *              against the real catalogs as its own equivalence check).
 *
 *          KNOWN CONSERVATIVE LIMITATION -- POSIX bracket expressions
 *          (`[[:alnum:]]` etc.): outside the supported subset, same as
 *          `PlaceholderRegex.hpp`'s parser (which doesn't special-case them
 *          either). `parse_char_class` treats the inner `]` of `[:alnum:]`
 *          as the char class's own closing `]` (it has no POSIX-class
 *          awareness), leaving a stray trailing `]` that `parse_atom`
 *          refuses -- `PrefilterParseFailure`, caught, `false` for the whole
 *          rule: safe, not a crash, just conservative. The one real instance
 *          in the shipped catalogs
 *          (`access_tokens.airtable-personnal-access-token.gl`, regex
 *          `\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b`) happens not to be an
 *          actual behavioral divergence from Go either way: its keyword
 *          ("airtable") never appears as a literal substring anywhere in the
 *          pattern, so `regexGuaranteesKeyword` would answer `false` for it
 *          too, just via the ordinary "keyword absent from every literal"
 *          path rather than a parse failure.
 *
 *          KNOWN CONSERVATIVE LIMITATION -- `\Q...\E` (Perl/PCRE literal-quote
 *          escape, NOT supported by RE2 or Go's `regexp/syntax` at all): an
 *          unrecognized alphanumeric escape like `\Q` or `\E` aborts the
 *          WHOLE parse (`PrefilterParseFailure`) rather than becoming a local
 *          `Unsupported` atom -- see `PrefilterParser::parse_escape`'s
 *          `default` case for why this needs to be a global abort, not a
 *          local one, unlike every other `Unsupported` construct in this
 *          file. Zero catalog instances (`\Q` never appears in either shipped
 *          catalog); a pattern using it isn't valid RE2 syntax anyway, so
 *          `Registry::compile_rule`'s own `RE2` construction would already
 *          reject it before `regex_guarantees_keyword` is ever called on it
 *          in every real caller -- this only matters for a direct call with
 *          deliberately invalid syntax (as this file's own unit tests do, to
 *          pin the conservative behavior).
 *
 *          `regex_guarantees_keyword` itself does the lowercasing of both the
 *          matched literal text and the incoming `keywords` (via
 *          `Guard::to_lower_utf8`) -- unlike Go's `regexGuaranteesKeyword`,
 *          which assumes its caller (`prefilterKeywords`) already lowered
 *          `loweredKeywords` before calling it. Lowercasing here too is a
 *          harmless no-op for the already-lowercased keywords
 *          `Registry::compile_rule` passes (`Rule::keywords` is lowercased at
 *          YAML-load time, see `RulesYaml.hpp`, for the common YAML-catalog
 *          path), and it keeps this function correct and self-contained for
 *          any other caller (including this file's own unit tests, several
 *          of which call it directly with mixed-case keywords per the task
 *          brief). This is a SEPARATE concern from `CompiledRule::
 *          prefilter_keywords` (`Registry.hpp`) -- the lowered copy the
 *          *scanner* matches against at request time, which
 *          `Registry::compile_rule` computes unconditionally from
 *          `r.keywords` regardless of how the rule was constructed (a rule
 *          built outside the YAML loader, e.g. by a future configuration
 *          API, is not guaranteed to arrive with already-lowered keywords).
 *          `regex_guarantees_keyword`'s own internal lowercasing only ever
 *          affects the eligibility *verdict* computed here at compile time;
 *          it does not, by itself, give the scanner anything lowercased to
 *          match against later.
 */

#pragma once

#include <cctype>
#include <cstddef>
#include <string>
#include <vector>

#include "guard/Unicode.hpp"

namespace Guard {

namespace detail {

// Internal control-flow signal only: thrown by PrefilterParser wherever the
// input can't even be structurally parsed within the supported subset (an
// unclosed group, a stray ')'/']'/quantifier-without-operand, a truncated
// escape, trailing unconsumed input...). Always caught inside
// regex_guarantees_keyword -- never observable outside this file. This is
// distinct from Node::Kind::Unsupported, which marks a single AST node as
// "can't prove a guarantee here" while parsing continues normally around it
// -- ParseFailure means parsing itself could not continue.
struct PrefilterParseFailure {};

// Small AST for the restricted RE2/Perl regex subset this parser supports --
// see the file-level doc comment's "GO-OP-TO-PARSER-NODE MAPPING" for the
// exact correspondence to Go's regexp/syntax ops.
struct Node {
    enum class Kind {
        Literal,      // maximal run of consecutive un-quantified literal chars
        Concat,       // ANY child guarantees -> whole node guarantees
        Alternate,    // ALL children (>=1) must guarantee
        Capture,      // recurse into the single child
        Repeat,       // recurse into child IFF min >= 1 (covers +, {m}, {m,n}, {m,})
        Unsupported,  // *, ?, char class, ., anchors, \d\s\w..., \p{...}, ... -- never guarantees
    };

    Kind kind{Kind::Unsupported};
    std::string literal;         // Kind::Literal: the raw (not-yet-lowered) UTF-8 bytes
    bool fold_case{false};       // Kind::Literal: was this run parsed inside an active (?i)?
    std::vector<Node> children;  // Kind::Concat / Kind::Alternate
    std::size_t min{0};          // Kind::Repeat
    std::vector<Node> child;     // Kind::Repeat / Kind::Capture: exactly one element
};

inline Node make_literal(std::string s, bool fold_case) {
    Node n;
    n.kind = Node::Kind::Literal;
    n.literal = std::move(s);
    n.fold_case = fold_case;
    return n;
}

inline Node make_unsupported() {
    Node n;
    n.kind = Node::Kind::Unsupported;
    return n;
}

// See the file-level doc comment's "FOLD-SAFETY PORT" section for the full
// rationale. `literal` is raw UTF-8 bytes (not yet lowered); iterates its
// codepoints via utf8proc so a multi-byte, non-ASCII rune is inspected as one
// unit rather than per-byte.
inline bool literal_is_fold_safe(const std::string& literal, bool fold_case) {
    if (!fold_case)
        return true;  // matches verbatim; both sides go through to_lower_utf8 -- always safe.

    std::size_t i = 0;
    while (i < literal.size()) {
        const auto c = static_cast<unsigned char>(literal[i]);
        if (c < 0x80) {
            // ASCII: every letter is fold-safe except 's'/'S' (cross-folds
            // with U+017F LATIN SMALL LETTER LONG S, whose own lowercase
            // mapping is itself, not 's' -- see the file-level doc comment).
            if (c == 's' || c == 'S')
                return false;
            ++i;
            continue;
        }
        // Non-ASCII rune under case-insensitivity: conservatively unsafe.
        // Always the safe direction (costs eligibility, never recall) -- see
        // the file-level doc comment.
        return false;
    }
    return true;
}

// Recursive-descent parser over the same restricted RE2/Perl regex subset as
// `PlaceholderRegex.hpp`'s `BoundedLengthParser` (modeled directly on that
// parser's structure and escape handling), but building a small AST
// (`Node`) instead of computing a length bound. See the file-level doc
// comment for the full construct-by-construct rationale.
//
// Grammar (identical shape to BoundedLengthParser's):
//   pattern      := alternation                     -- must consume all input
//   alternation  := concat ('|' concat)*             -- Node::Kind::Alternate (or bare concat if no '|')
//   concat       := piece*                           -- Node::Kind::Concat, with literal-run merging
//   piece        := atom quantifier?
//   atom         := '(' group_body ')' | '[' class ']' | '\' escape
//                  | '^' | '$' | '.' | <literal rune>
//   quantifier   := '*' | '+' | '?' | '{' m (',' n?)? '}'    (each '?'-suffixable)
class PrefilterParser {
public:
    explicit PrefilterParser(const std::string& pattern) : s_(pattern), pos_(0) {}

    // Entry point. Throws PrefilterParseFailure if the pattern can't be
    // structurally parsed within the supported subset (trailing unconsumed
    // input included -- e.g. a stray ')').
    Node parse() {
        Node n = parse_alternation();
        if (pos_ != s_.size())
            throw PrefilterParseFailure{};
        return n;
    }

private:
    // Nesting cap mirroring BoundedLengthParser's kMaxGroupDepth -- refuses
    // (via PrefilterParseFailure) an adversarial input with tens of
    // thousands of nested '(' before it exhausts the call stack.
    static constexpr int kMaxGroupDepth = 1000;

    const std::string& s_;
    std::size_t pos_;
    int depth_ = 0;
    // Set once a `(?i)`/`(?i:...)` flag is seen and never cleared (staying on
    // is the safe direction for the same reason BoundedLengthParser's
    // fold_case_ does the same -- an earlier `(?i)` that a later `(?-i)`
    // turns back off is rare, and treating fold-case as "sticky" only ever
    // makes a literal's fold-safety check stricter, never looser).
    bool fold_case_ = false;

    bool at_end() const { return pos_ >= s_.size(); }
    char peek() const { return at_end() ? '\0' : s_[pos_]; }

    // Consumes and returns the UTF-8 bytes of the rune starting at pos_ (1-4
    // bytes), advancing past it. Used for un-escaped literal characters,
    // including multibyte ones written directly in the pattern.
    std::string consume_rune() {
        if (at_end())
            throw PrefilterParseFailure{};
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
        std::string rune = s_.substr(pos_, n);
        pos_ += n;
        return rune;
    }

    // Go equivalent: OpAlternate -- guarantee iff every branch guarantees.
    // A single branch (no '|' seen) is NOT wrapped in an Alternate node,
    // mirroring Go's parser never producing OpAlternate for one branch.
    Node parse_alternation() {
        Node first = parse_concat();
        if (peek() != '|')
            return first;

        Node alt;
        alt.kind = Node::Kind::Alternate;
        alt.children.push_back(std::move(first));
        while (peek() == '|') {
            ++pos_;
            alt.children.push_back(parse_concat());
        }
        return alt;
    }

    // Go equivalent: OpConcat -- guarantee iff any child guarantees.
    // Reproduces Go's adjacent-literal-run merging (see the file-level doc
    // comment's "LITERAL RUN MERGING" section): a plain literal piece (no
    // quantifier applied) extends the pending literal run when its fold_case
    // matches; anything else flushes the run and becomes its own child.
    Node parse_concat() {
        Node concat;
        concat.kind = Node::Kind::Concat;
        bool have_pending_literal = false;
        Node pending_literal;

        auto flush_pending = [&]() {
            if (have_pending_literal) {
                concat.children.push_back(std::move(pending_literal));
                have_pending_literal = false;
            }
        };

        while (!at_end() && peek() != '|' && peek() != ')') {
            Node atom = parse_atom();
            const bool quantified = peek_is_quantifier_start();
            Node piece = quantified ? parse_quantifier(std::move(atom)) : std::move(atom);

            if (!quantified && piece.kind == Node::Kind::Literal) {
                if (have_pending_literal && pending_literal.fold_case == piece.fold_case) {
                    pending_literal.literal += piece.literal;
                } else {
                    flush_pending();
                    have_pending_literal = true;
                    pending_literal = std::move(piece);
                }
                continue;
            }
            flush_pending();
            concat.children.push_back(std::move(piece));
        }
        flush_pending();

        if (concat.children.empty())
            return make_literal("", false);  // empty concat: OpEmptyMatch -- vacuously never guarantees
        if (concat.children.size() == 1)
            return std::move(concat.children[0]);
        return concat;
    }

    bool peek_is_quantifier_start() const {
        const char c = peek();
        return c == '*' || c == '+' || c == '?' || c == '{';
    }

    // Go equivalent: OpPlus (min=1) / OpStar (min=0) / OpQuest (min=0) /
    // OpRepeat ({m}/{m,n}/{m,}, min=m). A malformed '{' (no digits, no
    // closing '}') is NOT a quantifier at all -- restores pos_ and returns
    // the atom unchanged, exactly like BoundedLengthParser (a raw '{' left
    // for the next parse_atom call is refused there -- see parse_atom).
    Node parse_quantifier(Node atom) {
        const char c = peek();
        if (c == '*') {
            ++pos_;
            skip_lazy_marker();
            return make_repeat(0, std::move(atom));
        }
        if (c == '+') {
            ++pos_;
            skip_lazy_marker();
            return make_repeat(1, std::move(atom));
        }
        if (c == '?') {
            ++pos_;
            skip_lazy_marker();
            return make_repeat(0, std::move(atom));
        }
        return parse_brace_quantifier(std::move(atom));
    }

    void skip_lazy_marker() {
        if (peek() == '?')
            ++pos_;
    }

    static Node make_repeat(std::size_t min, Node child) {
        Node n;
        n.kind = Node::Kind::Repeat;
        n.min = min;
        n.child.push_back(std::move(child));
        return n;
    }

    Node parse_brace_quantifier(Node atom) {
        const std::size_t save = pos_;
        ++pos_;  // consume '{'
        std::string min_digits;
        while (!at_end() && std::isdigit(static_cast<unsigned char>(peek())))
            min_digits.push_back(s_[pos_++]);
        if (peek() == ',') {
            ++pos_;
            while (!at_end() && std::isdigit(static_cast<unsigned char>(peek())))
                ++pos_;  // max digits, if any -- unused: only `min` matters for the guarantee.
        }

        if (min_digits.empty() || peek() != '}') {
            pos_ = save;
            return atom;  // not a quantifier after all -- caller reparses '{' as the next atom.
        }
        ++pos_;  // consume '}'
        skip_lazy_marker();

        std::size_t min = 0;
        for (char d : min_digits)
            min = min * 10 + static_cast<std::size_t>(d - '0');  // repeat counts are always small
        return make_repeat(min, std::move(atom));
    }

    Node parse_atom() {
        if (at_end())
            throw PrefilterParseFailure{};
        const char c = peek();
        if (c == '(')
            return parse_group();
        if (c == '[')
            return parse_char_class();
        if (c == '\\')
            return parse_escape();
        // Go equivalent: OpBeginLine/OpEndLine/OpBeginText/OpEndText --
        // zero-width anchors, never guarantee.
        if (c == '^' || c == '$') {
            ++pos_;
            return make_unsupported();
        }
        // Go equivalent: OpAnyCharNotNL/OpAnyChar -- never guarantees.
        if (c == '.') {
            ++pos_;
            return make_unsupported();
        }
        // Structurally out of place here -- most commonly a malformed
        // quantifier's stray '{'/'}' left behind, or an unmatched ']'/'*'/
        // '+'/'?'. Mirrors BoundedLengthParser's identical refusal list.
        if (c == '|' || c == ')' || c == '*' || c == '+' || c == '?' || c == '{' || c == '}' || c == ']')
            throw PrefilterParseFailure{};
        return make_literal(consume_rune(), fold_case_);  // plain literal character (possibly multibyte)
    }

    class DepthGuard {
    public:
        explicit DepthGuard(int& depth) : depth_(depth) { ++depth_; }
        ~DepthGuard() { --depth_; }
        DepthGuard(const DepthGuard&) = delete;
        DepthGuard& operator=(const DepthGuard&) = delete;

    private:
        int& depth_;
    };

    // Go equivalent: OpCapture for plain '(...)' and named '(?P<n>...)';
    // transparent (no wrapping node) for '(?:...)' / '(?i)' / '(?i:...)' --
    // Go's parser never produces OpCapture for those. Lookaround and other
    // '(?...)' forms outside the supported subset throw
    // PrefilterParseFailure (RE2 doesn't support them anyway; a pattern
    // reaching here already passed RE2 compilation upstream in every real
    // caller, so this path is only reachable from a direct unit-test call
    // with deliberately out-of-subset syntax).
    Node parse_group() {
        if (depth_ >= kMaxGroupDepth)
            throw PrefilterParseFailure{};
        DepthGuard guard(depth_);

        ++pos_;  // consume '('
        if (peek() != '?') {
            Node inner = parse_alternation();
            expect(')');
            Node cap;
            cap.kind = Node::Kind::Capture;
            cap.child.push_back(std::move(inner));
            return cap;
        }
        ++pos_;  // consume '?'
        if (peek() == ':') {
            ++pos_;
            Node inner = parse_alternation();
            expect(')');
            return inner;  // transparent: non-capturing group is not a node of its own.
        }
        if (peek() == 'P' && pos_ + 1 < s_.size() && s_[pos_ + 1] == '<') {
            pos_ += 2;  // "P<"
            while (!at_end() && peek() != '>')
                ++pos_;
            expect('>');
            Node inner = parse_alternation();
            expect(')');
            Node cap;
            cap.kind = Node::Kind::Capture;
            cap.child.push_back(std::move(inner));
            return cap;
        }
        // (?flags) or (?flags:...): consume recognized flag letters (i s m U,
        // optionally separated by a single '-'). Seeing 'i' sets fold_case_
        // and never clears it (see the class-level doc comment on
        // fold_case_).
        bool saw_flag = false;
        while (!at_end() && (peek() == 'i' || peek() == 's' || peek() == 'm' || peek() == 'U' || peek() == '-')) {
            if (peek() == 'i')
                fold_case_ = true;
            ++pos_;
            saw_flag = true;
        }
        if (saw_flag && peek() == ')') {
            ++pos_;
            return make_unsupported();  // (?i) etc: zero-width flag setter, not a group -- never guarantees.
        }
        if (saw_flag && peek() == ':') {
            ++pos_;
            Node inner = parse_alternation();
            expect(')');
            return inner;  // transparent, same as (?:...).
        }
        throw PrefilterParseFailure{};  // lookaround etc. -- outside the supported subset.
    }

    void expect(char c) {
        if (peek() != c)
            throw PrefilterParseFailure{};
        ++pos_;
    }

    // Go equivalent: OpCharClass -- never guarantees a keyword (the concrete
    // members aren't known to contain any fixed text), but the class must
    // still be fully, correctly consumed so parsing continues past it
    // correctly for later siblings (see the file-level doc comment's
    // "adobe" example, where a leading, unprovable char-class repeat must
    // not disturb finding the guarantee in a later sibling).
    Node parse_char_class() {
        ++pos_;  // consume '['
        if (peek() == '^')
            ++pos_;
        bool any_member = false;
        while (true) {
            if (at_end())
                throw PrefilterParseFailure{};
            if (peek() == ']') {
                ++pos_;
                break;
            }
            any_member = true;
            if (peek() == '\\')
                parse_escape();
            else
                consume_rune();
            if (peek() == '-' && pos_ + 1 < s_.size() && s_[pos_ + 1] != ']') {
                ++pos_;  // consume '-'
                if (peek() == '\\')
                    parse_escape();
                else
                    consume_rune();
            }
        }
        if (!any_member)
            throw PrefilterParseFailure{};  // "[]" -- empty/malformed class
        return make_unsupported();
    }

    // A backslash escape. `\d \s \w \D \S \W` (ASCII/negated Perl classes),
    // `\b \B \A \z \Z` (zero-width anchors), and `\p{...} \P{...}` (Unicode
    // property classes) never guarantee -- Unsupported. `\n \t \r \f \v \a`
    // are literal single control-character bytes -- Literal, so they
    // participate in run-merging like any other literal char. `\xHH` /
    // `\x{...}` hex escapes and `\0`-`\7` octal escapes are consumed
    // (correctly, so parsing continues past them) but their exact decoded
    // codepoint is not computed -- Unsupported, matching
    // `PlaceholderRegex.hpp`'s identical refusal for the same reason (see
    // that file's CORRECTNESS NOTES). `\X` for any other character X (e.g.
    // what `RE2::QuoteMeta` produces for '.' -> '\.') is a literal escaped
    // char.
    Node parse_escape() {
        ++pos_;  // consume '\\'
        if (at_end())
            throw PrefilterParseFailure{};
        const char c = s_[pos_];
        switch (c) {
            case 'd':
            case 's':
            case 'w':
            case 'D':
            case 'S':
            case 'W':
            case 'b':
            case 'B':
            case 'A':
            case 'z':
            case 'Z':
                ++pos_;
                return make_unsupported();
            case 'n':
                ++pos_;
                return make_literal("\n", fold_case_);
            case 't':
                ++pos_;
                return make_literal("\t", fold_case_);
            case 'r':
                ++pos_;
                return make_literal("\r", fold_case_);
            case 'f':
                ++pos_;
                return make_literal("\f", fold_case_);
            case 'v':
                ++pos_;
                return make_literal("\v", fold_case_);
            case 'a':
                ++pos_;
                return make_literal("\a", fold_case_);
            case 'p':
            case 'P': {
                ++pos_;
                if (peek() == '{') {
                    ++pos_;
                    while (!at_end() && peek() != '}')
                        ++pos_;
                    expect('}');
                } else if (!at_end()) {
                    ++pos_;  // single-letter shorthand class, e.g. \pL
                }
                return make_unsupported();
            }
            case 'x': {
                ++pos_;
                if (peek() == '{') {
                    ++pos_;
                    while (!at_end() && peek() != '}')
                        ++pos_;
                    expect('}');
                } else {
                    for (int i = 0; i < 2 && !at_end() && std::isxdigit(static_cast<unsigned char>(peek())); ++i)
                        ++pos_;
                }
                return make_unsupported();
            }
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7': {
                for (int i = 0; i < 3 && !at_end() && peek() >= '0' && peek() <= '7'; ++i)
                    ++pos_;
                return make_unsupported();
            }
            default:
                // RE2/Go-regexp-syntax only allows escaping PUNCTUATION as an
                // identity escape (`\.` for a literal '.', `\-` for a literal
                // '-', ...). Escaping an ASCII letter or digit that isn't one
                // of the specific escapes already handled above (`\Q`, `\Y`,
                // `\8`, ...) is not valid syntax at all -- Go's own
                // `regexp/syntax.Parse` rejects it outright ("invalid escape
                // sequence"), so a pattern containing one never reaches
                // `regexGuaranteesKeyword` in the Go reference either (every
                // real caller here already has `r.regex` proven RE2-parseable
                // by `Registry::compile_rule`'s earlier `RE2` construction).
                // Abort the WHOLE parse here (`PrefilterParseFailure` ->
                // `false` overall) rather than marking just this one atom
                // `Unsupported` and continuing -- unlike a char class or `.`
                // (valid, successfully-parsed RE2 constructs that simply
                // can't prove a literal, where continuing to parse siblings
                // is exactly right), an unrecognized alphanumeric escape means
                // the pattern itself is unparseable, so nothing else in it can
                // be trusted as a genuine literal either. This closes the one
                // constructible unsound "true": without this check,
                // `\Qsecret\E` parses as `Unsupported` + `Literal("secret")` +
                // `Unsupported`, and `Concat`'s "any child suffices" rule
                // would wrongly prove a `secret` (or `qsecret`) keyword
                // guarantee from a pattern that doesn't actually mean what it
                // looks like under real RE2/Go semantics.
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
                    throw PrefilterParseFailure{};
                return make_literal(consume_rune(), fold_case_);  // literal escaped punctuation, e.g. "\."
        }
    }
};

// Ports `regexGuaranteesKeyword`'s per-op switch. `lowered_keywords` are
// already lowercased. See the file-level doc comment's "GO-OP-TO-PARSER-NODE
// MAPPING" for the exact Go-op correspondence.
inline bool guarantees_keyword(const Node& n, const std::vector<std::string>& lowered_keywords) {
    switch (n.kind) {
        case Node::Kind::Literal: {
            if (!literal_is_fold_safe(n.literal, n.fold_case))
                return false;
            const std::string literal_lower = to_lower_utf8(n.literal);
            for (const auto& kw : lowered_keywords) {
                if (!kw.empty() && literal_lower.find(kw) != std::string::npos)
                    return true;
            }
            return false;
        }
        case Node::Kind::Concat: {
            for (const auto& child : n.children) {
                if (guarantees_keyword(child, lowered_keywords))
                    return true;
            }
            return false;
        }
        case Node::Kind::Alternate: {
            if (n.children.empty())
                return false;
            for (const auto& child : n.children) {
                if (!guarantees_keyword(child, lowered_keywords))
                    return false;
            }
            return true;
        }
        case Node::Kind::Capture:
            return !n.child.empty() && guarantees_keyword(n.child[0], lowered_keywords);
        case Node::Kind::Repeat:
            return n.min >= 1 && !n.child.empty() && guarantees_keyword(n.child[0], lowered_keywords);
        case Node::Kind::Unsupported:
            return false;
    }
    return false;
}

}  // namespace detail

/**
 * @brief True only if every string `pattern` can match is guaranteed to
 *        contain at least one of `keywords` (case-insensitively). Safe
 *        default: `false` -- any construct outside the supported regex
 *        subset (see the file-level doc comment), or any keyword-containment
 *        that can't be proven, means the rule using `pattern` must always be
 *        scanned rather than pre-filtered, so a false negative here only
 *        costs speed, never recall.
 * @param pattern The rule's regex SOURCE, without the `"(?m)"` prefix
 *        `Registry::compile_rule` adds before compiling it (the multiline
 *        flag doesn't affect literal matching, so it's irrelevant to this
 *        proof -- mirrors Go's `prefilterKeywords`, which parses `rl.Regex`
 *        directly, not `"(?m)" + rl.Regex`).
 * @param keywords Candidate keywords; need not be pre-lowercased (this
 *        function lowercases both the keywords and every literal it proves
 *        against via `Guard::to_lower_utf8`).
 */
inline bool regex_guarantees_keyword(const std::string& pattern, const std::vector<std::string>& keywords) {
    if (keywords.empty())
        return false;

    std::vector<std::string> lowered_keywords;
    lowered_keywords.reserve(keywords.size());
    for (const auto& kw : keywords)
        lowered_keywords.push_back(to_lower_utf8(kw));

    try {
        detail::PrefilterParser parser(pattern);
        const detail::Node tree = parser.parse();
        return detail::guarantees_keyword(tree, lowered_keywords);
    } catch (const detail::PrefilterParseFailure&) {
        return false;
    }
}

}  // namespace Guard
