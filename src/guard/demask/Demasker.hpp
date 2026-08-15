/**
 * @file Demasker.hpp
 * @brief The inverse of masking: restores the original sensitive values a
 *        request's masking phase replaced with synthetic `<TYPE_N>`
 *        placeholders, in a form safe to run over an SSE stream chunk by
 *        chunk.
 * @details Ports `internal/guardrails/demask/{provider,factory,demasker}.go`
 *          and `internal/sseproc/common/{demask_args,json}.go` (the shared
 *          `DemaskJSONArguments` / `MarshalNoEscape` pair), read directly
 *          rather than inferred:
 *
 *          **Config** (`DemaskConfig` + `Provider.NewFactory`) is built once
 *          per request from the `MaskingState` the masking phase produced,
 *          plus the SAME pinned `Registry` snapshot the masking phase used
 *          (`std::shared_ptr<const Registry>`, held by the Config so the
 *          `CompiledRule*`s it resolves stay alive even across a hot
 *          reload). It carries four tables built by `buildLookupIndex`:
 *          placeholder -> original (verbatim), placeholder -> original
 *          (JSON-escaped), and the exact-replacer form of each. Blank
 *          placeholders are skipped and the FIRST entry for a repeated
 *          placeholder wins, exactly as Go's `buildLookupIndex` does.
 *
 *          **max_pending** (the streaming hold-back bound), read from
 *          `newDemaskConfig` + `buildLookupIndex` + `Registry.
 *          GetMaxPlaceholderLenByRuleIDs`, is
 *              max( longest placeholder LITERAL among the replacements,
 *                   max placeholder_len over the TRIGGERED rules that the
 *                   pinned snapshot still resolves )
 *          -- i.e. `buildLookupIndex` seeds `maxPending` with the longest
 *          `len(rep.Placeholder)`, then `newDemaskConfig` raises it with
 *          `max(cfg.maxPending, reg.GetMaxPlaceholderLenByRuleIDs(sorted
 *          triggered ids))`, whose Go body maxes `PlaceholderLen` over the
 *          ids the registry knows and silently skips the ones it doesn't.
 *          Both halves matter: the literal bound covers the exact pass
 *          (`<EMAIL_1>` split across a chunk boundary), the rule bound
 *          covers the tolerant pass (`< email - 1 >`, which is LONGER than
 *          the literal it recognizes). UNDER-holding is a security bug -- a
 *          placeholder split across the boundary would be emitted verbatim
 *          and leak the mapping to the client -- while over-holding only
 *          costs stream latency, so every ambiguous case here resolves
 *          upward.
 *
 *          **Chunk pass order** (`DemaskChunk`): `text = pending + chunk`;
 *          `pending` is cleared FIRST (so it can never be emitted twice, on
 *          the error path included); then the exact replacer pass, then the
 *          tolerant placeholder-regex pass, then the hold-back.
 *
 *          **Exact pass** ports Go's `strings.Replacer` semantics precisely,
 *          which are neither leftmost-longest nor first-listed-only: at each
 *          byte position Go's `genericReplacer` finds EVERY registered
 *          pattern that matches there and takes the one with the highest
 *          priority, where priority is assigned by ARGUMENT ORDER (earlier
 *          pair wins), not by length; on a hit the cursor jumps past the
 *          matched pattern, so replacements never overlap and a replacement's
 *          own bytes are never re-scanned. `Demasker::apply_exact` reproduces
 *          that with a length-indexed probe (`Config::placeholder_lengths`,
 *          ascending) into `Config::index_by_placeholder`, keeping the lowest
 *          entry index among all lengths that hit. For the canonical
 *          `<TYPE_N>` shapes the masker mints, no two placeholders are ever
 *          prefixes of one another (the closing `>` disambiguates
 *          `<PLACEHOLDER_1>` from `<PLACEHOLDER_10>`), so the priority rule
 *          is unobservable in practice -- it is ported anyway because the
 *          replacement table is caller-supplied data, not a masker
 *          invariant.
 *
 *          **Tolerant pass** (`applyPlaceholderRegex` + the placeholder
 *          scanner it delegates to) re-recognizes placeholders the model
 *          paraphrased -- `< email - 12 >` for `<EMAIL_12>` -- via each
 *          triggered rule's `placeholder_re` (PlaceholderRegex.hpp), maps
 *          capture group 1 (the numeric index) back through
 *          `placeholderfmt.Format` to the canonical literal, and looks THAT
 *          up in the same tables. A number the mapping doesn't know
 *          (`<EMAIL_99>` when only `<EMAIL_1>` was minted) is left exactly
 *          as it appeared: Go's `originals[match.Placeholder]` misses and the
 *          match is dropped from the replacement list, never blanked and
 *          never guessed.
 *
 *          **Tolerant-pass overlap policy** -- TWO independent stages, both
 *          ported, because Go applies both and they are not the same rule:
 *            1. `placeholder.resolveConflicts` (scan.go:169-198), inside the
 *               scanner: sort by (start asc, MATCH LENGTH desc, rule id asc),
 *               then a greedy sweep dropping any match starting before the
 *               running `maxEnd`. So at equal start the LONGER match wins,
 *               ties broken by rule id for determinism, and a later
 *               overlapping match is dropped entirely (not truncated).
 *            2. `applyTextReplacements` (demasker.go:141-166), on whatever
 *               match list it is handed: sort by (start asc, END desc) and
 *               splice left to right, skipping any replacement whose `start`
 *               is before the write cursor `pos`. Adjacent matches
 *               (`a.end == b.start`) are BOTH kept.
 *          Stage 2 is redundant after stage 1 for scanner-produced matches,
 *          but is the only guard when a caller injects matches directly
 *          through `Config::scan` -- which is exactly what Go's own
 *          `TestDemasker_DemaskChunk_ScannerReplacementOrdering` does through
 *          its mocked scanner, and what this port's equivalent test does.
 *
 *          **Hold-back** (`DemaskChunk`'s tail + `utf8SafePrefixEnd`): unless
 *          `flush`, the last `max_pending` bytes are retained in `pending`
 *          for the next call, and the emit boundary is then TRIMMED BACK to a
 *          UTF-8 rune boundary so a multi-byte rune is never split across two
 *          emitted chunks (Go's `utf8SafePrefixEnd`: walk back to the nearest
 *          rune-start byte, decode it, and keep the boundary only if that
 *          whole rune fits before it). Trimming can only ever move the
 *          boundary EARLIER, so it can never shrink the hold-back below
 *          `max_pending`. If nothing is left to emit the whole buffer becomes
 *          `pending` and the call emits nothing.
 *
 *          **Error contract** (`DemaskChunk`'s `return text, err`): on an
 *          internal failure the demasker throws `DemaskError` carrying
 *          `unemitted` -- the buffer as of the exact pass, with any
 *          unresolved placeholders left intact -- and its `pending` is
 *          already empty. The caller MUST emit `unemitted`: that is the
 *          lossless fail-open Go's comment mandates ("hand back everything
 *          not yet emitted ... so the caller can emit it ... instead of
 *          dropping the stream tail"). Note what that means for content:
 *          the fallback may still contain placeholders, which is safe (a
 *          placeholder leaks nothing), whereas dropping the tail would
 *          silently truncate the model's answer. Go's own error inventory
 *          for this path is exactly one entry -- the scanner's error return,
 *          which in Go is only ever non-nil when a parallel scan worker
 *          panicked (`placeholder.scanParallel`'s `recover`) -- so this port
 *          mirrors the SHAPE rather than the enumeration: every exception
 *          escaping the tolerant pass (a throwing injected `Config::scan`, a
 *          `std::bad_alloc`, or the out-of-range-match guard below) is
 *          converted into one `DemaskError` with the correct un-emitted
 *          buffer. The exact pass is deliberately NOT inside that guard, for
 *          the same reason Go's isn't: `strings.Replacer.Replace` cannot
 *          fail, and if allocation there fails there is no buffer worth
 *          handing back that the caller doesn't already have.
 *
 *          **JSON-escaped variant** (`Factory.JSONDemasker`): the same passes
 *          with the JSON-escaped tables, for demasking a fragment that will
 *          land INSIDE a JSON string literal (Anthropic's
 *          `input_json_delta.partial_json`, tool-call argument deltas). An
 *          original containing `"` or `\` would otherwise corrupt the JSON
 *          the client accumulates. Escaping is `Guard::Json::encode_string
 *          (raw, false)` -- `MarshalNoEscape` parity, i.e. NO HTML escaping,
 *          so `<`, `>` and `&` survive byte-for-byte (Go's default
 *          `json.Marshal` would rewrite `<EMAIL_1>` into `<EMAIL_1>`
 *          and stop the client recognizing the placeholders this service
 *          emits).
 *
 *          **demask_json_arguments** (`common.DemaskJSONArguments`): a naive
 *          raw substitution over the whole arguments document first (fast
 *          path, byte-preserving); if that yields invalid JSON -- which
 *          happens exactly when a restored original contains a JSON
 *          metacharacter -- fall back to a STRUCTURAL demask. This port's
 *          structural pass deliberately DIVERGES from Go's implementation
 *          while preserving its contract: Go decodes into `map[string]any`,
 *          demasks each string leaf and re-marshals, which reorders object
 *          keys (Go marshals map keys sorted) and only preserves number
 *          literals thanks to `UseNumber`. This port instead walks the RAW
 *          bytes via `Guard::Json::string_leaves` and rebuilds with
 *          `Guard::Json::splice_all` BY SPAN, so key order, whitespace,
 *          duplicate keys and every number/boolean/null token are preserved
 *          byte-for-byte, and only the string leaves that actually changed
 *          are rewritten. Spans are the authoritative address: a leaf is
 *          never re-located by re-resolving its `path`, because a document
 *          with duplicate keys would resolve the path to the FIRST match and
 *          patch the wrong leaf. If the spliced result is still not valid
 *          JSON, the INPUT is returned unchanged -- keeping the masked
 *          placeholders is always preferable to emitting broken JSON (Go
 *          returns `("", false)` here and its callers keep the masked value;
 *          returning the input directly is the same outcome with one less
 *          way for a caller to get it wrong).
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <re2/re2.h>

#include "guard/MaskingState.hpp"
#include "guard/Registry.hpp"
#include "guard/Unicode.hpp"
#include "guard/json/Json.hpp"

namespace Guard::Demask {

/// One tolerant-pass hit: `[start, end)` are byte offsets into the text the
/// scan ran over, and `placeholder` is the CANONICAL `<TYPE_N>` literal the
/// hit maps back to (already rendered from the rule's placeholder type and
/// the match's captured index). Ports `placeholder.Match`.
struct PlaceholderMatch {
    std::string rule_id;
    std::size_t start{0};
    std::size_t end{0};
    std::string placeholder;
};

/**
 * @brief Thrown by `Demasker::demask_chunk` when the tolerant pass fails.
 * @details `unemitted` carries every byte the demasker has buffered but not
 *          yet emitted (the exact-demasked text, placeholders intact). The
 *          caller MUST write it to the stream: the demasker's own `pending`
 *          is already cleared, so nothing else holds those bytes and
 *          swallowing the exception silently truncates the response. See the
 *          file-level "Error contract" note.
 */
struct DemaskError : std::runtime_error {
    std::string unemitted;

    DemaskError(const std::string& msg, std::string unemitted_bytes)
        : std::runtime_error(msg), unemitted(std::move(unemitted_bytes)) {}
};

/// Bytes `demask_chunk` emits for one call (empty while the whole buffer is
/// still held back).
struct ChunkResult {
    std::string out;
};

/**
 * @brief Request-scoped, immutable-after-construction demasking tables,
 *        shared by every `Demasker` built from them (one per streamed
 *        field). Ports `DemaskConfig` + `Factory`: the per-stream mutable
 *        state (the pending buffer) lives in `Demasker`, never here, so one
 *        `Config` is safe to share across concurrently demasked fields.
 */
struct Config {
    /// One placeholder -> original mapping, in first-encounter order (which
    /// IS the exact replacer's priority order -- see the file-level note on
    /// `strings.Replacer` semantics).
    struct Entry {
        std::string placeholder;
        std::string original;       // verbatim
        std::string json_original;  // Json::encode_string(original, false)
    };

    std::vector<Entry> entries;
    /// placeholder -> index into `entries`. Heterogeneous-lookup hash so the
    /// exact pass probes with a `std::string_view` slice of the text without
    /// allocating a `std::string` per byte position.
    std::unordered_map<std::string, std::size_t, Guard::detail::TransparentStringHash, std::equal_to<>>
        index_by_placeholder;
    /// Distinct `entries[].placeholder.size()` values, ascending -- the only
    /// lengths the exact pass needs to probe at each position.
    std::vector<std::size_t> placeholder_lengths;
    /// `placeholder_first_byte[b]` is true iff some placeholder starts with
    /// byte `b`; lets the exact pass skip the map probes entirely for the
    /// overwhelming majority of bytes.
    std::array<bool, 256> placeholder_first_byte{};
    /// Streaming hold-back bound -- see the file-level "max_pending" note.
    std::size_t max_pending{0};
    /// The pinned registry snapshot the triggered rules were resolved from,
    /// held so the `CompiledRule*`s captured by `scan` outlive a hot reload.
    std::shared_ptr<const Registry> pinned;
    /**
     * @brief The tolerant pass. Empty (`Go: cfg.scan == nil`) when there are
     *        no triggered rules or no pinned snapshot -- the tolerant pass is
     *        then skipped entirely and only the exact pass runs.
     * @details Returns matches ALREADY conflict-resolved when built by
     *          `make_config`. Deliberately a `std::function` rather than a
     *          hard-wired member: it is the exact seam Go exposes through its
     *          `PlaceholderScanner` interface, which its own tests mock both
     *          to inject overlapping matches and to inject a failure. Any
     *          exception escaping it becomes a `DemaskError`.
     */
    std::function<std::vector<PlaceholderMatch>(std::string_view)> scan;

    /// The replacement text for a canonical placeholder literal, or nullptr
    /// if this request never minted it (Go: the `originals[...]` map miss
    /// that drops the match and leaves the text as-is).
    const std::string* lookup(std::string_view placeholder, bool json_escape) const {
        const auto it = index_by_placeholder.find(placeholder);
        if (it == index_by_placeholder.end())
            return nullptr;
        const Entry& e = entries[it->second];
        return json_escape ? &e.json_original : &e.original;
    }
};

namespace detail {

/// One resolved splice for `apply_text_replacements`. `original` points into
/// the owning `Config`, which outlives the call.
struct TextReplacement {
    std::size_t start;
    std::size_t end;
    const std::string* original;
};

/// Go's `utf8.RuneStart`: true for every byte that is NOT a UTF-8
/// continuation byte.
inline bool is_rune_start(unsigned char b) {
    return (b & 0xC0) != 0x80;
}

/// Byte length of the UTF-8 rune encoded at `s[i]`, mirroring Go's
/// `utf8.DecodeRuneInString` closely enough for the boundary decision: an
/// invalid lead byte, or a lead byte whose continuation bytes are missing or
/// malformed, decodes as RuneError with size 1 (exactly as Go does), so a
/// broken sequence can never claim to extend past the buffer.
inline std::size_t rune_len_at(std::string_view s, std::size_t i) {
    if (i >= s.size())
        return 1;
    const auto b = static_cast<unsigned char>(s[i]);
    std::size_t want = 0;
    if (b < 0x80)
        return 1;
    if ((b & 0xE0) == 0xC0)
        want = 2;
    else if ((b & 0xF0) == 0xE0)
        want = 3;
    else if ((b & 0xF8) == 0xF0)
        want = 4;
    else
        return 1;  // continuation byte or 0xF8..0xFF lead: RuneError, width 1
    if (i + want > s.size())
        return 1;
    for (std::size_t k = 1; k < want; ++k) {
        if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80)
            return 1;  // truncated/malformed sequence: RuneError, width 1
    }
    return want;
}

/**
 * @brief Largest offset <= `end` that does not split a UTF-8 rune. Ports
 *        `utf8SafePrefixEnd` (demasker.go:64-85) exactly, including its
 *        "walk back to a rune-start byte, decode there, keep `end` only if
 *        that whole rune fits" shape.
 * @return `end` itself when `end` already sits on a rune boundary; otherwise
 *         the start offset of the rune that straddles it (possibly 0, which
 *         the caller reads as "emit nothing this call").
 */
inline std::size_t utf8_safe_prefix_end(std::string_view s, std::size_t end) {
    if (end == 0)
        return 0;
    if (end >= s.size())
        return s.size();

    std::size_t i = end - 1;
    while (!is_rune_start(static_cast<unsigned char>(s[i]))) {
        if (i == 0)
            return 0;  // buffer opens mid-rune: Go's `if i < 0 { return 0 }`
        --i;
    }
    const std::size_t size = rune_len_at(s, i);
    if (i + size <= end)
        return end;
    return i;
}

/**
 * @brief Splices `replacements` into `text` left to right. Ports
 *        `applyTextReplacements` (demasker.go:141-166): sort by (start asc,
 *        end desc), then skip any replacement starting before the write
 *        cursor. Adjacent (`a.end == b.start`) replacements are both kept.
 * @note `std::stable_sort`, not `std::sort`: Go's `sort.Slice` is unstable
 *       too, but its comparator can only tie on an exact (start, end)
 *       duplicate -- of which the second is then dropped by the cursor check
 *       regardless -- so stability costs nothing and makes this port's output
 *       deterministic for a caller-injected match list as well.
 */
inline std::string apply_text_replacements(std::string_view text, std::vector<TextReplacement> replacements) {
    if (replacements.empty())
        return std::string(text);

    std::stable_sort(replacements.begin(), replacements.end(), [](const TextReplacement& a, const TextReplacement& b) {
        if (a.start != b.start)
            return a.start < b.start;
        return a.end > b.end;
    });

    std::string out;
    out.reserve(text.size());
    std::size_t pos = 0;
    for (const TextReplacement& rep : replacements) {
        if (rep.start < pos)
            continue;
        out.append(text.substr(pos, rep.start - pos));
        out.append(*rep.original);
        pos = rep.end;
    }
    out.append(text.substr(pos));
    return out;
}

/**
 * @brief Drops overlapping matches. Ports `placeholder.resolveConflicts`
 *        (scan.go:169-198): sort by (start asc, match length desc, rule id
 *        asc), then a greedy sweep keeping a match only when it starts at or
 *        after the running maximum end.
 * @note Go seeds `maxEnd` with -1 so the first match is always kept; 0 is
 *       equivalent here because a byte offset is never negative.
 */
inline std::vector<PlaceholderMatch> resolve_conflicts(std::vector<PlaceholderMatch> matches) {
    if (matches.size() <= 1)
        return matches;

    std::stable_sort(matches.begin(), matches.end(), [](const PlaceholderMatch& a, const PlaceholderMatch& b) {
        if (a.start != b.start)
            return a.start < b.start;
        const std::size_t left_len = a.end - a.start;
        const std::size_t right_len = b.end - b.start;
        if (left_len != right_len)
            return left_len > right_len;
        return a.rule_id < b.rule_id;
    });

    std::vector<PlaceholderMatch> resolved;
    resolved.reserve(matches.size());
    std::size_t max_end = 0;
    for (PlaceholderMatch& match : matches) {
        if (match.start < max_end)
            continue;
        if (match.end > max_end)
            max_end = match.end;
        resolved.push_back(std::move(match));
    }
    return resolved;
}

/// Parses the placeholder-index capture. Ports `strconv.Atoi` + Go's
/// `index <= 0` rejection; the capture is `[0-9]{1,9}` so the value always
/// fits an `int` and leading zeros are accepted (`001` -> 1), which is what
/// makes `< name-001 >` resolve to `<NAME_1>`.
inline bool parse_placeholder_index(std::string_view digits, int& out) {
    if (digits.empty() || digits.size() > 9)
        return false;
    int value = 0;
    for (char c : digits) {
        if (c < '0' || c > '9')
            return false;
        value = value * 10 + (c - '0');
    }
    if (value <= 0)
        return false;
    out = value;
    return true;
}

/**
 * @brief All tolerant-pass hits of one rule's placeholder recognizer, in
 *        left-to-right order. Ports `placeholder.scanRule` (scan.go:121-154):
 *        a rule with no recognizer (blank/whitespace-only
 *        `masking.placeholder`) contributes nothing, the numeric capture is
 *        group 1, and the canonical literal is rendered from the RAW
 *        (untrimmed) placeholder type -- `placeholderfmt.Format(cr.Masking.
 *        Placeholder, index)`, matching `Masker.hpp`'s `render_placeholder`.
 * @note The `RE2::Match` loop mirrors `Scanner.hpp`'s port of Go's
 *       `FindAllStringSubmatchIndex`, minus its empty-match bookkeeping: the
 *       placeholder template always requires at least `<` and `>`, so a
 *       zero-width match is unreachable. The `mend == mstart` branch is kept
 *       purely so a hand-built `CompiledRule` carrying some other pattern
 *       still terminates instead of spinning.
 */
inline void scan_rule(std::string_view text, const CompiledRule& cr, std::vector<PlaceholderMatch>& out) {
    if (!cr.placeholder_re || Guard::ascii_trim(cr.rule.masking.placeholder).empty())
        return;

    const RE2& re = *cr.placeholder_re;
    constexpr int kNumGroups = 2;  // [0] = whole match, [1] = the numeric index
    std::vector<std::string_view> groups(static_cast<std::size_t>(kNumGroups));

    const std::size_t end = text.size();
    std::size_t pos = 0;
    while (pos <= end) {
        if (!re.Match(text, pos, end, RE2::UNANCHORED, groups.data(), kNumGroups))
            break;

        const auto mstart = static_cast<std::size_t>(groups[0].data() - text.data());
        const std::size_t mend = mstart + groups[0].size();

        int index = 0;
        if (groups[1].data() != nullptr && parse_placeholder_index(groups[1], index)) {
            out.push_back(PlaceholderMatch{
                cr.rule.id, mstart, mend, "<" + cr.rule.masking.placeholder + "_" + std::to_string(index) + ">"});
        }

        pos = mend > mstart ? mend : mstart + 1;
    }
}

}  // namespace detail

/**
 * @brief Builds the request-scoped demasking tables. Ports `Provider.
 *        NewFactory` -> `newDemaskConfig` -> `buildLookupIndex`.
 * @param state the masking phase's own output -- its `replacements` supply
 *        the lookup tables, its `triggered_rule_ids` select the tolerant
 *        pass's recognizers.
 * @param pinned the SAME registry snapshot the masking phase used. A null
 *        snapshot disables the tolerant pass entirely (Go's `scanner == nil`
 *        branch) but leaves the exact pass fully functional.
 * @note Never throws for unknown/blank data: a triggered id the snapshot no
 *       longer knows is skipped (Go's `GetMaxPlaceholderLenByRuleIDs` and
 *       `GetCompiledRulesByRuleIDs` both skip silently), a blank-placeholder
 *       replacement is skipped, and a repeated placeholder keeps its first
 *       original.
 */
inline Config make_config(const Guard::MaskingState& state, const std::shared_ptr<const Registry>& pinned) {
    Config cfg;

    // ---- buildLookupIndex (factory.go:96-124) --------------------------
    cfg.entries.reserve(state.replacements.size());
    for (const Replacement& rep : state.replacements) {
        if (rep.placeholder.empty())
            continue;
        if (cfg.index_by_placeholder.find(rep.placeholder) != cfg.index_by_placeholder.end())
            continue;  // first entry for a placeholder wins

        const std::size_t idx = cfg.entries.size();
        cfg.entries.push_back(
            Config::Entry{rep.placeholder, rep.original, Guard::Json::encode_string(rep.original, false)});
        cfg.index_by_placeholder.emplace(rep.placeholder, idx);
        cfg.placeholder_first_byte[static_cast<unsigned char>(rep.placeholder.front())] = true;
        if (rep.placeholder.size() > cfg.max_pending)
            cfg.max_pending = rep.placeholder.size();
    }
    for (const Config::Entry& e : cfg.entries)
        cfg.placeholder_lengths.push_back(e.placeholder.size());
    std::sort(cfg.placeholder_lengths.begin(), cfg.placeholder_lengths.end());
    cfg.placeholder_lengths.erase(std::unique(cfg.placeholder_lengths.begin(), cfg.placeholder_lengths.end()),
                                  cfg.placeholder_lengths.end());

    // ---- newDemaskConfig (factory.go:64-92) ----------------------------
    // Sorted like Go's `sort.Strings(ruleIDs)`. The sort cannot change the
    // max below, but it does fix the order rules are resolved (and therefore
    // scanned) in, which keeps the pre-conflict-resolution match order
    // deterministic across calls.
    std::vector<std::string> rule_ids = state.triggered_rule_ids;
    std::sort(rule_ids.begin(), rule_ids.end());

    if (!pinned)
        return cfg;

    cfg.pinned = pinned;

    std::size_t max_placeholder_len = 0;
    std::vector<const CompiledRule*> rules;
    rules.reserve(rule_ids.size());
    for (const std::string& id : rule_ids) {
        const CompiledRule* cr = pinned->by_id(id);
        if (!cr)
            continue;  // dropped by a reload between masking and demasking
        if (cr->placeholder_len > max_placeholder_len)
            max_placeholder_len = cr->placeholder_len;
        rules.push_back(cr);
    }
    if (max_placeholder_len > cfg.max_pending)
        cfg.max_pending = max_placeholder_len;

    if (rule_ids.empty() || rules.empty())
        return cfg;  // Go: `len(ruleIDs) == 0` -> cfg.scan stays nil

    // Resolve-once fast path (Go's `ruleResolver`, factory.go:79-83): the
    // rule set is fixed for the stream's lifetime because its placeholders
    // were minted from this same snapshot, so the pointers are captured now
    // instead of re-resolved per chunk. `Config::pinned` (set above, and
    // copied/moved with the closure since both live in the same Config) is
    // what keeps the pointed-to `CompiledRule`s alive across a hot reload.
    cfg.scan = [rules = std::move(rules)](std::string_view text) {
        std::vector<PlaceholderMatch> matches;
        for (const CompiledRule* cr : rules)
            detail::scan_rule(text, *cr, matches);
        return detail::resolve_conflicts(std::move(matches));
    };

    return cfg;
}

/**
 * @brief One stream's demasker: a reference to the shared `Config` plus this
 *        stream's own pending buffer. Ports `Demasker` (demasker.go).
 * @note Holds the `Config` BY POINTER -- the caller must keep it alive for
 *       the demasker's lifetime (Go holds `*DemaskConfig` the same way). One
 *       `Config` backs many `Demasker`s; sharing a single `Demasker` across
 *       concurrent streams would interleave their pending buffers and is not
 *       supported, exactly as in Go.
 */
class Demasker {
public:
    /// @param json_escape_originals restore JSON-escaped originals, for text
    ///        that lands inside a JSON string literal (Go's
    ///        `Factory.JSONDemasker`).
    explicit Demasker(const Config& cfg, bool json_escape_originals = false)
        : cfg_(&cfg), json_ctx_(json_escape_originals) {}

    /**
     * @brief Demasks `pending + chunk` and emits the safe prefix.
     * @param flush emit everything, holding nothing back -- the last call of
     *        a stream, or a one-shot whole-text demask.
     * @return the emitted bytes; empty when the whole buffer is still held
     *         back (which is normal and not an error).
     * @throws DemaskError carrying every un-emitted byte, which the caller
     *         MUST emit -- see the file-level "Error contract" note.
     */
    ChunkResult demask_chunk(std::string_view chunk, bool flush) {
        std::string text;
        text.reserve(pending_.size() + chunk.size());
        text.append(pending_);
        text.append(chunk);
        // Cleared BEFORE any work, exactly as Go does: on the error path
        // below, `unemitted` is then the ONLY holder of these bytes, so a
        // caller that emits it can never emit them twice.
        pending_.clear();

        if (text.empty())
            return ChunkResult{};

        text = apply_exact(text);
        try {
            text = apply_placeholder_regex(text);
        } catch (const std::exception& e) {
            throw DemaskError(std::string("demask: placeholder pass failed: ") + e.what(), std::move(text));
        } catch (...) {
            throw DemaskError("demask: placeholder pass failed: unknown exception", std::move(text));
        }

        if (flush)
            return ChunkResult{std::move(text)};

        // Go: `safeEnd := len(text) - maxPending; if safeEnd <= 0 { ... }`.
        if (text.size() <= cfg_->max_pending) {
            pending_ = std::move(text);
            return ChunkResult{};
        }
        const std::size_t safe_end = detail::utf8_safe_prefix_end(text, text.size() - cfg_->max_pending);
        if (safe_end == 0) {
            pending_ = std::move(text);
            return ChunkResult{};
        }

        ChunkResult result{text.substr(0, safe_end)};
        pending_ = text.substr(safe_end);
        return result;
    }

    /// Bytes buffered but not yet emitted (introspection; the streaming
    /// contract is defined entirely by `demask_chunk`'s return value).
    std::string pending() const { return pending_; }

private:
    /// Go's `applyExact` -> `strings.Replacer.Replace`. See the file-level
    /// note for why priority is by entry order, not by match length.
    std::string apply_exact(std::string_view text) const {
        const Config& cfg = *cfg_;
        if (cfg.placeholder_lengths.empty())
            return std::string(text);

        std::string out;
        out.reserve(text.size());
        std::size_t i = 0;
        while (i < text.size()) {
            if (!cfg.placeholder_first_byte[static_cast<unsigned char>(text[i])]) {
                out.push_back(text[i]);
                ++i;
                continue;
            }

            std::size_t best = SIZE_MAX;  // index into cfg.entries; lower wins
            std::size_t best_len = 0;
            for (std::size_t len : cfg.placeholder_lengths) {
                if (i + len > text.size())
                    break;  // ascending: no longer length fits either
                const auto it = cfg.index_by_placeholder.find(text.substr(i, len));
                if (it != cfg.index_by_placeholder.end() && it->second < best) {
                    best = it->second;
                    best_len = len;
                }
            }
            if (best == SIZE_MAX) {
                out.push_back(text[i]);
                ++i;
                continue;
            }

            const Config::Entry& e = cfg.entries[best];
            out.append(json_ctx_ ? e.json_original : e.original);
            i += best_len;  // never re-scans the inserted original
        }
        return out;
    }

    /// Go's `applyPlaceholderRegex`. A match with a blank placeholder, or one
    /// whose canonical literal this request never minted, is dropped from the
    /// replacement list and therefore left in the text untouched.
    std::string apply_placeholder_regex(std::string_view text) const {
        const Config& cfg = *cfg_;
        if (!cfg.scan)
            return std::string(text);

        const std::vector<PlaceholderMatch> matches = cfg.scan(text);
        if (matches.empty())
            return std::string(text);

        std::vector<detail::TextReplacement> replacements;
        replacements.reserve(matches.size());
        for (const PlaceholderMatch& match : matches) {
            if (match.placeholder.empty())
                continue;
            // Go would panic on slicing `text` with an out-of-range match;
            // this port turns it into the same fail-open the scanner's own
            // error return gets (the caller emits `unemitted` verbatim).
            if (match.start > match.end || match.end > text.size())
                throw std::out_of_range("Guard::Demask: placeholder match is out of range for this text");
            const std::string* original = cfg.lookup(match.placeholder, json_ctx_);
            if (!original)
                continue;
            replacements.push_back(detail::TextReplacement{match.start, match.end, original});
        }

        return detail::apply_text_replacements(text, std::move(replacements));
    }

    const Config* cfg_;
    bool json_ctx_;
    std::string pending_;
};

/**
 * @brief One-shot whole-text demask -- a fresh `Demasker` flushed in a single
 *        call, so nothing is held back and no state survives the call.
 * @throws DemaskError (see `Demasker::demask_chunk`); its `unemitted` is the
 *         whole exact-demasked text.
 */
inline std::string demask_all(const Config& cfg, std::string_view text, bool json_escape = false) {
    Demasker demasker(cfg, json_escape);
    return demasker.demask_chunk(text, true).out;
}

/**
 * @brief Demasks a tool-call arguments JSON document, keeping the result
 *        valid JSON even when a restored original contains `"`, `\` or a
 *        control character. Ports `common.DemaskJSONArguments`.
 * @return the demasked document, or `raw_json` UNCHANGED when no safe
 *         rewrite exists -- keeping the placeholders is always preferable to
 *         emitting broken JSON. Never throws.
 * @details Naive raw substitution first (byte-preserving fast path); on
 *          invalid output, a structural pass that rewrites only the string
 *          leaves, addressed BY SPAN over the raw bytes so key order,
 *          duplicate keys, whitespace and every number literal survive
 *          byte-for-byte. See the file-level `demask_json_arguments` note for
 *          why this diverges from Go's parse-and-re-marshal implementation
 *          while preserving its contract.
 */
inline std::string demask_json_arguments(const Config& cfg, std::string_view raw_json) {
    if (raw_json.empty())
        return std::string(raw_json);

    try {
        std::string naive = demask_all(cfg, raw_json, false);
        if (Guard::Json::valid(naive))
            return naive;
    } catch (const DemaskError&) {
        // Go: `err == nil && json.Valid(...)` -- a failed naive pass simply
        // falls through to the structural one.
    }

    try {
        const std::vector<Guard::Json::StringLeaf> leaves = Guard::Json::string_leaves(raw_json, {});
        std::vector<std::pair<Guard::Json::ValueSpan, std::string>> edits;
        edits.reserve(leaves.size());
        for (const Guard::Json::StringLeaf& leaf : leaves) {
            // Spans, never `leaf.path`: re-resolving a path in a document
            // with duplicate keys would patch the FIRST match, not this leaf.
            const std::string_view quoted = raw_json.substr(leaf.span.start, leaf.span.end - leaf.span.start);
            const std::string decoded = Guard::Json::decode_string(quoted);
            const std::string demasked = demask_all(cfg, decoded, false);
            if (demasked == decoded)
                continue;
            edits.emplace_back(leaf.span, Guard::Json::encode_string(demasked, true));
        }
        if (edits.empty())
            return std::string(raw_json);

        std::string out = Guard::Json::splice_all(raw_json, edits);
        if (!Guard::Json::valid(out))
            return std::string(raw_json);
        return out;
    } catch (const std::exception&) {
        return std::string(raw_json);  // keep the masked value, never emit broken JSON
    }
}

}  // namespace Guard::Demask
