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
 *              in `Registry::build` as it inserts each successfully
 *              compiled rule, which is functionally identical to Go's
 *              `Add` (`CompileRule` then insert) called in a loop by
 *              `Build`.
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
 *            - `prefilter_eligible` stays `false` on every `CompiledRule`
 *              here — Task 1.8 wires in the keyword-prefilter prover
 *              (`Prefilter.hpp` / Go's `regexGuaranteesKeyword`).
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

#include <atomic>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <re2/re2.h>

#include "guard/Errors.hpp"
#include "guard/PlaceholderRegex.hpp"
#include "guard/Rule.hpp"
#include "guard/Unicode.hpp"
#include "guard/Validators.hpp"

namespace Guard {

struct CompiledRule {
    Rule rule;
    std::shared_ptr<const RE2> re;              // "(?m)" + rule.regex
    std::shared_ptr<const RE2> placeholder_re;  // tolerant recognizer, capture 1 = number; null if blank placeholder
    std::size_t placeholder_len{0};             // bound for SSE pending buffer; 0 if placeholder_re is null
    bool prefilter_eligible{false};             // always false until Task 1.8 wires the prover
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
            CompiledRule cr = compile_rule(r);
            if (reg->by_id_.find(cr.rule.id) != reg->by_id_.end()) {
                throw RuleError(RuleError::Code::DuplicateId,
                                "compile guardrails rule '" + cr.rule.id + "': duplicate rule_id");
            }
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

        auto re = std::make_shared<RE2>("(?m)" + r.regex);
        if (!re->ok()) {
            throw RuleError(RuleError::Code::BadRegex,
                            "compile guardrails rule '" + r.id + "' regex: " + re->error());
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
            PlaceholderPattern pp = build_placeholder_pattern(placeholder);  // may throw UnboundedPlaceholder
            auto placeholder_re = std::make_shared<RE2>("(?m)" + pp.pattern);
            if (!placeholder_re->ok()) {
                throw RuleError(RuleError::Code::BadRegex,
                                "compile guardrails rule '" + r.id + "' placeholder regex: " + placeholder_re->error());
            }
            cr.placeholder_re = placeholder_re;
            cr.placeholder_len = pp.max_len;
        }

        return cr;
    }

    /// nullptr if `id` is absent from this snapshot.
    const CompiledRule* by_id(std::string_view id) const {
        const auto it = by_id_.find(std::string(id));
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

private:
    std::vector<CompiledRule> rules_;
    std::unordered_map<std::string, std::size_t> by_id_;
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
