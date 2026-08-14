/**
 * @file Registry.hpp
 * @brief Compiled-rule registry: the single validation/compile path shared by
 *        startup file loading and (later) the configuration API, plus an
 *        atomically swappable snapshot for hot reload.
 * @details Ports `pkg/guardrails/regex/registry/{registry,reloadable}.go`:
 *            - `Registry::compile_rule` is `CompileRule` minus the
 *              registry-consulted duplicate-id check (the C++ signature
 *              takes only a `Rule`, not a `Registry&`, per
 *              phase1-interfaces.md) — duplicate detection instead happens
 *              in `Registry::build`, checked BEFORE calling `compile_rule`
 *              for each rule, matching Go's precedence exactly (`CompileRule`
 *              checks `reg.byID` first thing, ahead of even the empty-id
 *              check): a duplicate id is reported even when the second
 *              rule is also otherwise invalid, and no compile is wasted on
 *              a rule that can't be added regardless.
 *            - Both `RE2` constructions (the main regex and the placeholder
 *              recognizer) pass `RE2::Quiet` explicitly. The default
 *              `Options` log a parse error to stderr on construction; once
 *              a future configuration API reuses `compile_rule` for
 *              operator-supplied rules, the default would let a rejected
 *              custom regex write arbitrary operator text to the server's
 *              stderr on every request (log spam, and a log-injection
 *              vector) — Go's `regexp.Compile` has no such side channel at
 *              all. `RE2::error()` still carries the message back to the
 *              caller through `RuleError` either way.
 *            - `Registry::by_id_` uses a C++20 heterogeneous-lookup hash
 *              (`detail::TransparentStringHash`, paired with the already-
 *              transparent `std::equal_to<>`) so `by_id(std::string_view)` —
 *              a hot path once the demasker looks up rules per match — never
 *              allocates a temporary `std::string` just to probe the map.
 *            - Validation order mirrors `CompileRule` exactly, with one
 *              deliberate addition: the Go reference only checks
 *              `strings.TrimSpace(rl.ID) == ""`; this port additionally
 *              enforces the full `^[a-z0-9_.-]{1,128}$` shape mandated by
 *              `Rule::id`'s contract in Rule.hpp / phase1-interfaces.md,
 *              via `RuleError::Code::InvalidId` (a Go rule id was never
 *              validated this strictly — the C++ contract is stricter by
 *              design, not a divergence bug).
 *            - BLANK PLACEHOLDER GUARD — read directly from
 *              `compilePlaceholderRegex` (registry.go:394-398) rather than
 *              assumed: `placeholderType := strings.TrimSpace(rl.Masking.
 *              Placeholder); if placeholderType == "" { return nil, 0, nil }`.
 *              There is NO fallback anywhere in the Go reference that
 *              derives a placeholder name from the rule id when the
 *              placeholder is blank/whitespace-only — grepping the whole
 *              `regex/` tree for `Placeholder` turns up no such logic in
 *              `rule.go`, `registry.go`, or either scanner. A blank
 *              placeholder simply means "no recognizer at all": nil regex,
 *              zero length, no error. This mirrors `PlaceholderRegex.hpp`'s
 *              own doc comment, which already flags this exact guard as the
 *              caller's (this file's) responsibility.
 *            - `validateMaskingConfig` (capture group bounds) runs before
 *              `compilePlaceholderRegex` in Go; this port does too.
 *            - `prefilter_eligible` is set by `compile_rule` from
 *              `Prefilter.hpp`'s `regex_guarantees_keyword(r.regex,
 *              r.keywords)` (Go's `regexGuaranteesKeyword`, called through
 *              `prefilterKeywords`): `true` only when the rule declares at
 *              least one keyword AND the prover can show every match of
 *              `r.regex` is guaranteed to contain one of them. Deliberately
 *              parses `r.regex` itself, NOT `"(?m)" + r.regex` — mirrors
 *              Go's `prefilterKeywords(rl.Regex, rl.Keywords)`, which parses
 *              the un-prefixed source (the multiline flag doesn't affect
 *              literal matching, so it's irrelevant to the proof).
 *              `CompiledRule::prefilter_keywords` mirrors Go's
 *              `CompiledRule.PrefilterKeywords []string` directly: `r.
 *              keywords` lowercased via `Guard::to_lower_utf8`, computed
 *              unconditionally (not gated on `prefilter_eligible` — cheap,
 *              and it keeps the two independently correct rather than
 *              coupled). CANNOT be skipped in favor of reading `rule.
 *              keywords` straight off the (unlowered, in general)
 *              `Rule` — `RulesYaml.hpp` happens to lowercase keywords as a
 *              side effect of the YAML loader, but `compile_rule` is the
 *              single validation path for a rule built ANY way (a future
 *              configuration API's rules are not guaranteed pre-lowered);
 *              `regex_guarantees_keyword` itself lowercases keywords
 *              internally purely to decide the eligibility *verdict*, which
 *              does not, by itself, hand the scanner anything lowercased to
 *              match against later. Feeding the scanner raw, possibly
 *              mixed-case keywords against its always-lowercased scan text
 *              would silently zero out every hit for such a rule (caught by
 *              code review during Task 1.8 — see
 *              `GuardScanner.UppercaseKeywordNotPreLoweredStillHitsAfterPrefilterKeywordsFix`
 *              in `test_guard_scanner.cpp`). NOTE: `prefilter_keywords` is a
 *              `CompiledRule` field this port added beyond what
 *              `phase1-interfaces.md` documented as of Task 1.7.
 *            - DEVIATION FROM GO — no `spdlog` in the engine: Go's
 *              `Registry.PrefilterIneligibleRuleIDs()` exists purely so a
 *              caller can log, at startup, which keyword-bearing rules the
 *              prefilter had to skip (an operator-visibility aid, not a
 *              correctness requirement — every one of those rules is still
 *              always scanned, so recall is unaffected either way). This
 *              header-only `Guard::` engine (phase1-interfaces.md: "no
 *              Drogon/HTTP includes") has no logging dependency of its own
 *              -- `spdlog` isn't used anywhere under `src/guard/` -- so
 *              `Registry::prefilter_ineligible_rule_ids()` below is ported
 *              as a pure data accessor with the exact same contract and
 *              filter (`keywords` non-empty AND NOT `prefilter_eligible`,
 *              sorted) — callers in a later phase (the app-layer service
 *              startup path) are expected to log the returned list
 *              themselves.
 *            - `ReloadableRegistry` ports `Reloadable`: `std::atomic<std::
 *              shared_ptr<const Registry>>` gives the same lock-free-ish
 *              publish/read pair as Go's `atomic.Pointer[Registry]` — GCC 13
 *              (this repo's toolchain, see docker/Dockerfile) implements the
 *              C++20 `std::atomic<std::shared_ptr<T>>` partial
 *              specialization in libstdc++, so no mutex fallback is needed.
 *              A reader that captured an old snapshot via `get()` keeps it
 *              alive through ordinary `shared_ptr` refcounting even after a
 *              concurrent `swap()` publishes a new one.
 */

#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <re2/re2.h>

#include "guard/Errors.hpp"
#include "guard/PlaceholderRegex.hpp"
#include "guard/Prefilter.hpp"
#include "guard/Rule.hpp"
#include "guard/Unicode.hpp"
#include "guard/Validators.hpp"

namespace Guard {

struct CompiledRule {
    Rule rule;
    std::shared_ptr<const RE2> re;              // "(?m)" + rule.regex
    std::shared_ptr<const RE2> placeholder_re;  // tolerant recognizer, capture 1 = number; null if blank placeholder
    std::size_t placeholder_len{0};             // bound for SSE pending buffer; 0 if placeholder_re is null
    // True iff rule.keywords is non-empty AND regex_guarantees_keyword(rule.regex, rule.keywords)
    // (Prefilter.hpp) proved every match of the regex contains one of them.
    bool prefilter_eligible{false};
    // rule.keywords, lowercased via Guard::to_lower_utf8 -- computed unconditionally in compile_rule
    // (cheap; independent of prefilter_eligible) and consumed by the scanner's keyword-hit check when
    // prefilter_eligible is true. NOTE this is a field CompiledRule did not have in phase1-interfaces.md
    // as of Task 1.7 -- added here in Task 1.8. Cannot reuse rule.keywords directly for this: RulesYaml.hpp lowercases
    // keywords at YAML-load time, but Registry::compile_rule is also the single validation path for rules built any
    // other way (e.g. a future configuration API), which need not have pre-lowered keywords -- an
    // API-supplied rule with keywords={"Bearer"} must still substring-match against the scanner's
    // lowered text, exactly mirroring Go's CompiledRule.PrefilterKeywords []string.
    std::vector<std::string> prefilter_keywords;
};

namespace detail {

// Rule::id's documented shape (Rule.hpp, phase1-interfaces.md): lowercase
// ASCII letters, digits, '_', '.', '-'; 1-128 bytes. Stricter than the Go
// reference (which only rejects an empty/whitespace id) by design -- see
// the file-level doc comment.
inline bool is_valid_rule_id(std::string_view id) {
    if (id.empty() || id.size() > 128)
        return false;
    for (char c : id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

// C++20 heterogeneous-lookup hash so `Registry::by_id` (a hot path for the
// demasker) can look up a `std::string_view` directly against a `std::string`
// key without allocating a temporary `std::string` per call. Paired with
// `std::equal_to<>` (already transparent) on the map itself.
struct TransparentStringHash {
    using is_transparent = void;
    std::size_t operator()(std::string_view sv) const noexcept { return std::hash<std::string_view>{}(sv); }
};

}  // namespace detail

/**
 * @brief All compiled rules for one immutable snapshot, with O(1) lookup by
 *        rule id and by data type. Built once via `build()`; every accessor
 *        is read-only, so a `std::shared_ptr<const Registry>` snapshot is
 *        safe to share across threads without further locking.
 */
class Registry {
public:
    /**
     * @brief Compiles and indexes every rule in `rules`, in order.
     * @throws RuleError on the first invalid rule (see `compile_rule`), or
     *         `RuleError::Code::DuplicateId` if a rule id repeats within
     *         `rules` (mirrors `Add`'s registry-consulted duplicate check,
     *         performed here since `compile_rule` alone has no registry
     *         state to consult).
     */
    static std::shared_ptr<const Registry> build(const std::vector<Rule>& rules) {
        auto reg = std::make_shared<Registry>();
        for (const auto& r : rules) {
            // Duplicate id is checked BEFORE compiling -- mirrors Go's error
            // precedence (CompileRule checks reg.byID first thing, before
            // even the empty-id check): a duplicate is reported even when
            // the second rule is also otherwise invalid, and a doomed
            // compile is never wasted on a rule that can't be added anyway.
            if (reg->by_id_.find(r.id) != reg->by_id_.end()) {
                throw RuleError(RuleError::Code::DuplicateId,
                                "compile guardrails rule '" + r.id + "': duplicate rule_id");
            }
            CompiledRule cr = compile_rule(r);
            const std::size_t idx = reg->rules_.size();
            reg->by_id_.emplace(cr.rule.id, idx);
            reg->by_data_type_[cr.rule.data_type].push_back(idx);
            reg->rules_.push_back(std::move(cr));
        }
        return reg;
    }

    /**
     * @brief Validates and compiles a single rule. The single validation
     *        path shared by startup file loading and (later) the
     *        configuration API -- does NOT check for duplicate ids against
     *        any registry (that happens in `build`, the only place that
     *        holds cross-rule state).
     * @throws RuleError::Code::InvalidId       -- id fails ^[a-z0-9_.-]{1,128}$
     * @throws RuleError::Code::UnknownValidator -- a validators[] name Validators.hpp doesn't know
     * @throws RuleError::Code::BadRegex         -- "(?m)" + rule.regex fails to compile under RE2
     * @throws RuleError::Code::BadCaptureGroup  -- a masking.capture_groups index is <= 0 or exceeds
     *         the regex's capturing-group count
     * @throws RuleError::Code::UnboundedPlaceholder -- propagated from build_placeholder_pattern
     *         (see PlaceholderRegex.hpp); unreachable for the fixed-shape template it emits, kept
     *         as a defensive assertion
     */
    static CompiledRule compile_rule(const Rule& r) {
        if (!detail::is_valid_rule_id(r.id)) {
            throw RuleError(RuleError::Code::InvalidId,
                            "compile guardrails rule: invalid rule_id '" + r.id + "'; must match ^[a-z0-9_.-]{1,128}$");
        }
        for (const auto& validator : r.validators) {
            if (!is_known_validator(validator)) {
                throw RuleError(RuleError::Code::UnknownValidator,
                                "compile guardrails rule '" + r.id + "': unsupported validator '" + validator + "'");
            }
        }

        // RE2::Quiet: the default Options log a parse error to stderr on
        // construction. compile_rule is (from Task 1.5 on) the same path a
        // future configuration API reuses for operator-supplied rules, so a
        // rejected custom regex must not write arbitrary operator text to
        // the server's stderr (log spam / a log-injection vector) -- Go's
        // regexp.Compile has no such side channel at all. RE2::error()
        // still carries the same message back to the caller via RuleError.
        auto re = std::make_shared<RE2>("(?m)" + r.regex, RE2::Quiet);
        if (!re->ok()) {
            throw RuleError(RuleError::Code::BadRegex, "compile guardrails rule '" + r.id + "' regex: " + re->error());
        }

        const int num_groups = re->NumberOfCapturingGroups();
        for (int group : r.masking.capture_groups) {
            if (group <= 0) {
                throw RuleError(RuleError::Code::BadCaptureGroup,
                                "compile guardrails rule '" + r.id + "': capture_groups must contain positive indexes");
            }
            if (group > num_groups) {
                std::string msg = "compile guardrails rule '" + r.id + "': capture group " + std::to_string(group);
                msg += " exceeds regex capture groups " + std::to_string(num_groups);
                throw RuleError(RuleError::Code::BadCaptureGroup, msg);
            }
        }

        CompiledRule cr;
        cr.rule = r;
        cr.re = re;

        // BLANK PLACEHOLDER GUARD -- read from compilePlaceholderRegex
        // (registry.go:394-398), not guessed: TrimSpace(placeholder) == ""
        // means no recognizer at all, nil/null, zero length. No fallback to
        // an id-derived name exists anywhere in the Go reference (see the
        // file-level doc comment).
        const std::string placeholder = detail::ascii_trim(r.masking.placeholder);
        if (!placeholder.empty()) {
            PlaceholderPattern pp;
            try {
                pp = build_placeholder_pattern(placeholder);
            } catch (const RuleError& e) {
                // Re-thrown with the rule id attached: a 266-rule catalog
                // failure has to name which rule broke, not just report
                // "placeholder regex is unbounded" in the abstract.
                throw RuleError(e.code, "compile guardrails rule '" + r.id + "' placeholder: " + e.what());
            }
            // RE2::Quiet -- see the main-regex comment above; same rationale.
            auto placeholder_re = std::make_shared<RE2>("(?m)" + pp.pattern, RE2::Quiet);
            if (!placeholder_re->ok()) {
                throw RuleError(RuleError::Code::BadRegex,
                                "compile guardrails rule '" + r.id + "' placeholder regex: " + placeholder_re->error());
            }
            // registry.go:406-408 parity: the placeholder recognizer must
            // expose capture group #1 for the placeholder's numeric index --
            // the demasker depends on it. Unreachable for the fixed-shape
            // template build_placeholder_pattern emits today (it always
            // produces exactly one group), kept as a defensive assertion
            // against a future template change.
            if (placeholder_re->NumberOfCapturingGroups() < 1) {
                throw RuleError(RuleError::Code::BadRegex,
                                "compile guardrails rule '" + r.id +
                                    "' placeholder regex must have capture group #1 "
                                    "for the placeholder index");
            }
            cr.placeholder_re = placeholder_re;
            cr.placeholder_len = pp.max_len;
        }

        // Keyword pre-filter eligibility (Task 1.8): parses r.regex itself
        // (not "(?m)" + r.regex -- see the CompiledRule::prefilter_eligible
        // and file-level doc comments). A rule with no keywords is never
        // eligible -- regex_guarantees_keyword already returns false for an
        // empty keyword list, but the explicit check here documents the
        // short-circuit rather than relying on that implicitly.
        cr.prefilter_eligible = !r.keywords.empty() && regex_guarantees_keyword(r.regex, r.keywords);

        // cr.prefilter_keywords: r.keywords lowercased via to_lower_utf8, computed
        // unconditionally (cheap, and simpler than gating it on prefilter_eligible).
        // Do NOT reuse r.keywords directly here: RulesYaml.hpp lowercases at YAML-load
        // time, but compile_rule is the single validation path for rules from ANY
        // source, including a future configuration API whose keywords are not
        // guaranteed pre-lowered -- see CompiledRule::prefilter_keywords's doc comment.
        cr.prefilter_keywords.reserve(r.keywords.size());
        for (const auto& kw : r.keywords)
            cr.prefilter_keywords.push_back(to_lower_utf8(kw));

        return cr;
    }

    /// nullptr if `id` is absent from this snapshot.
    const CompiledRule* by_id(std::string_view id) const {
        const auto it = by_id_.find(id);
        return it == by_id_.end() ? nullptr : &rules_[it->second];
    }

    /// Rules for the given data types, in data-type-then-registration order.
    /// Pointers point into this Registry's own storage -- stable for the
    /// Registry's lifetime, since `rules_` never mutates after `build()`.
    std::vector<const CompiledRule*> for_data_types(const std::vector<DataType>& data_types) const {
        std::vector<const CompiledRule*> out;
        for (DataType dt : data_types) {
            const auto it = by_data_type_.find(dt);
            if (it == by_data_type_.end())
                continue;
            for (std::size_t idx : it->second)
                out.push_back(&rules_[idx]);
        }
        return out;
    }

    std::size_t size() const { return rules_.size(); }

    const std::vector<CompiledRule>& all() const { return rules_; }

    /**
     * @brief Sorted ids of rules that declare keywords but are NOT eligible
     *        for the keyword pre-filter (their regex doesn't guarantee a
     *        keyword in every match). Such rules are always scanned; this
     *        list exists purely for operator visibility. Ports Go's
     *        `Registry.PrefilterIneligibleRuleIDs()` as a pure data
     *        accessor -- see the file-level doc comment's "DEVIATION FROM
     *        GO" note: this header-only engine has no logging dependency,
     *        so (unlike Go, which only ever calls this to log at startup)
     *        it's the caller's job to do something with the returned list.
     */
    std::vector<std::string> prefilter_ineligible_rule_ids() const {
        std::vector<std::string> out;
        for (const auto& cr : rules_) {
            if (!cr.rule.keywords.empty() && !cr.prefilter_eligible)
                out.push_back(cr.rule.id);
        }
        std::sort(out.begin(), out.end());
        return out;
    }

private:
    std::vector<CompiledRule> rules_;
    std::unordered_map<std::string, std::size_t, detail::TransparentStringHash, std::equal_to<>> by_id_;
    std::unordered_map<DataType, std::vector<std::size_t>> by_data_type_;
};

/**
 * @brief Swappable `Registry` snapshot with lock-free-ish reads. Ports
 *        `Reloadable` (reloadable.go): readers always see a complete,
 *        immutable `Registry`; a writer builds a fresh one (`Registry::
 *        build`) and publishes it via `swap`. An old snapshot returned by an
 *        earlier `get()` stays valid and usable after a concurrent `swap`
 *        publishes a new one -- ordinary `shared_ptr` refcounting keeps it
 *        alive for as long as any caller holds it.
 */
class ReloadableRegistry {
public:
    explicit ReloadableRegistry(std::shared_ptr<const Registry> initial) : current_(std::move(initial)) {}

    /// Never null after construction (the constructor requires a non-null
    /// initial snapshot; `swap` is the only other writer and takes whatever
    /// the caller passes -- passing null there is a caller error, exactly
    /// as it would be in Go's `Store(nil)`).
    std::shared_ptr<const Registry> get() const { return current_.load(); }

    /// Atomically publishes `next` as the current snapshot.
    void swap(std::shared_ptr<const Registry> next) { current_.store(std::move(next)); }

private:
    std::atomic<std::shared_ptr<const Registry>> current_;
};

}  // namespace Guard
