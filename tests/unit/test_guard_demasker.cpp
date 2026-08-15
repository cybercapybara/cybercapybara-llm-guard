/**
 * @file test_guard_demasker.cpp
 * @brief Unit tests for Guard::Demask -- the streaming-safe inverse of
 *        masking (src/guard/demask/Demasker.hpp).
 *
 * Ports every behavioral case from the Go reference's
 * `internal/guardrails/demask/{demasker_test.go,factory_test.go}`:
 * `TestBuildLookupIndex`, `TestBuildLookupIndexJSONEscaped`,
 * `TestDemasker_DemaskChunk_Flush` (all 3 subtests),
 * `TestDemasker_DemaskChunk_ScannerReplacementOrdering` (all 3 subtests),
 * `TestDemasker_DemaskChunk_ScannerError`,
 * `TestDemasker_DemaskChunk_StreamingPending`,
 * `TestDemasker_DemaskChunk_KeepsExactPlaceholderTailWhenMaxPendingEqualsPlaceholderLen`
 * and `TestDemasker_DemaskChunk_DoesNotSplitUTF8Rune`.
 *
 * Go's tests drive the demasker through a gomock `PlaceholderScanner` and a
 * gomock `Registry`; this port drives it through `Config::scan` and
 * `Config::max_pending` directly (see `mock_config` below), which is the same
 * seam -- `Config::scan` exists precisely because Go exposes the scanner as an
 * injectable interface, both to feed in overlapping matches the real scanner's
 * conflict resolution would never emit and to force the error path.
 *
 * On top of the ported cases, this file adds the chunk-boundary TORTURE
 * MATRIX the Go suite has no equivalent of, because under-holding at a chunk
 * boundary is a SECURITY bug (a placeholder split across two chunks would be
 * emitted verbatim, leaking the mapping) rather than a cosmetic one:
 *   - every chunk size 1..64 over a masked text with three placeholders, one
 *     of them ending at the very last byte;
 *   - every single split point (flush at every position);
 *   - multi-byte UTF-8 (2/3/4-byte runes) straddling the hold boundary;
 *   - a real round trip through `Guard::mask_texts` with a real `Registry`,
 *     asserting byte-identical recovery of an input that itself contains a
 *     placeholder-lookalike the masker had to reserve around.
 */

#include <cstddef>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "guard/Masker.hpp"
#include "guard/MaskingState.hpp"
#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/demask/Demasker.hpp"
#include "guard/json/Json.hpp"

namespace {

using Guard::CompiledRule;
using Guard::DataType;
using Guard::MaskingState;
using Guard::Registry;
using Guard::Replacement;
using Guard::Rule;
using Guard::Demask::ChunkResult;
using Guard::Demask::Config;
using Guard::Demask::Demasker;
using Guard::Demask::DemaskError;
using Guard::Demask::PlaceholderMatch;

Replacement replacement(std::string rule_id, std::string original, std::string placeholder) {
    Replacement rep;
    rep.rule_id = std::move(rule_id);
    rep.data_type = DataType::Custom;
    rep.original = std::move(original);
    rep.placeholder = std::move(placeholder);
    return rep;
}

/// Go's `maskingState()` helper (demasker_test.go:268-279).
MaskingState masking_state() {
    MaskingState state;
    state.triggered_rule_ids = {"pii.name"};
    state.replacements = {replacement("pii.name", "Alice", "<NAME_1>")};
    return state;
}

/// The C++ analogue of Go's `NewProvider(mockRegistry, mockScanner)`: a
/// Config whose lookup tables come from real masking state, but whose
/// `max_pending` rule contribution and tolerant pass are injected, exactly as
/// the gomock Registry/PlaceholderScanner pair does in the Go suite.
/// `registry_max_placeholder_len` is combined with the literal bound the same
/// way `newDemaskConfig` combines them (`max(cfg.maxPending, ...)`).
Config mock_config(const MaskingState& state,
                   std::size_t registry_max_placeholder_len,
                   std::function<std::vector<PlaceholderMatch>(std::string_view)> scan = {}) {
    Config cfg = Guard::Demask::make_config(state, nullptr);
    if (registry_max_placeholder_len > cfg.max_pending)
        cfg.max_pending = registry_max_placeholder_len;
    cfg.scan = std::move(scan);
    return cfg;
}

/// A tolerant pass that records the text it was handed (so the pass ORDER --
/// exact first, tolerant second -- is observable) and returns a fixed match
/// list.
std::function<std::vector<PlaceholderMatch>(std::string_view)> recording_scan(std::vector<std::string>& seen,
                                                                              std::vector<PlaceholderMatch> matches) {
    return [&seen, matches = std::move(matches)](std::string_view text) {
        seen.emplace_back(text);
        return matches;
    };
}

Rule make_rule(std::string id, std::string regex, std::string placeholder, DataType data_type = DataType::Custom) {
    Rule r;
    r.id = std::move(id);
    r.name = r.id;
    r.data_type = data_type;
    r.regex = std::move(regex);
    r.masking.placeholder = std::move(placeholder);
    return r;
}

struct RegistryFixture {
    std::shared_ptr<const Registry> registry;
    std::vector<const CompiledRule*> rules;
};

RegistryFixture build_registry(const std::vector<Rule>& defs) {
    RegistryFixture fx;
    fx.registry = Registry::build(defs);
    for (const auto& cr : fx.registry->all())
        fx.rules.push_back(&cr);
    return fx;
}

Rule email_rule() {
    return make_rule("pii.email", R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", "EMAIL");
}

/// Feeds `text` through a fresh Demasker in fixed-size chunks and returns the
/// concatenation of everything emitted, including the final flush.
std::string demask_in_chunks(const Config& cfg, std::string_view text, std::size_t chunk_size, bool json_escape) {
    Demasker demasker(cfg, json_escape);
    std::string out;
    for (std::size_t i = 0; i < text.size(); i += chunk_size)
        out += demasker.demask_chunk(text.substr(i, chunk_size), false).out;
    out += demasker.demask_chunk("", true).out;
    return out;
}

// ---------------------------------------------------------------------------
// Config construction -- ports factory_test.go
// ---------------------------------------------------------------------------

TEST(GuardDemaskConfig, BuildLookupIndexSkipsBlankAndDuplicatePlaceholders) {
    MaskingState state;
    state.replacements = {
        replacement("", "ignored", ""),
        replacement("", "short", "<PLACEHOLDER_1>"),
        replacement("", "long", "<PLACEHOLDER_10>"),
        replacement("", "duplicate ignored", "<PLACEHOLDER_1>"),
    };

    const Config cfg = Guard::Demask::make_config(state, nullptr);

    ASSERT_EQ(cfg.entries.size(), 2U);
    ASSERT_NE(cfg.lookup("<PLACEHOLDER_1>", false), nullptr);
    ASSERT_NE(cfg.lookup("<PLACEHOLDER_10>", false), nullptr);
    EXPECT_EQ(*cfg.lookup("<PLACEHOLDER_1>", false), "short");
    EXPECT_EQ(*cfg.lookup("<PLACEHOLDER_10>", false), "long");
    EXPECT_EQ(cfg.lookup("", false), nullptr);
    // The exact replacer, exercised through the demasker it belongs to.
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "<PLACEHOLDER_1> <PLACEHOLDER_10>", false), "short long");
    EXPECT_EQ(cfg.max_pending, std::string("<PLACEHOLDER_10>").size());
}

TEST(GuardDemaskConfig, BuildLookupIndexJsonEscapedOriginalsSkipHtmlEscaping) {
    MaskingState state;
    state.replacements = {
        replacement("", R"(say "hi")", "<SECRET_1>"),
        replacement("", R"(C:\tmp\key)", "<SECRET_2>"),
        replacement("", "plain <tag> & more", "<SECRET_3>"),
    };

    const Config cfg = Guard::Demask::make_config(state, nullptr);

    EXPECT_EQ(*cfg.lookup("<SECRET_1>", true), R"(say \"hi\")");
    EXPECT_EQ(*cfg.lookup("<SECRET_2>", true), R"(C:\\tmp\\key)");
    // MarshalNoEscape parity: '<', '>' and '&' survive byte-for-byte.
    EXPECT_EQ(*cfg.lookup("<SECRET_3>", true), "plain <tag> & more");
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "<SECRET_1>", true), R"(say \"hi\")");
    // The verbatim table is unaffected by the escaping.
    EXPECT_EQ(*cfg.lookup("<SECRET_1>", false), R"(say "hi")");
}

TEST(GuardDemaskConfig, MaxPendingTakesTriggeredRulePlaceholderLenWhenLongerThanLiteral) {
    auto fx = build_registry({email_rule()});
    MaskingState state;
    state.triggered_rule_ids = {"pii.email"};
    state.replacements = {replacement("pii.email", "alice@example.com", "<EMAIL_1>")};

    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    const std::size_t rule_len = fx.registry->by_id("pii.email")->placeholder_len;
    // The tolerant recognizer (`< email - 123456789 >`) is far longer than the
    // canonical literal it recognizes -- the bound must follow the longer one.
    EXPECT_GT(rule_len, std::string("<EMAIL_1>").size());
    EXPECT_EQ(cfg.max_pending, rule_len);
    EXPECT_TRUE(static_cast<bool>(cfg.scan));
}

TEST(GuardDemaskConfig, MaxPendingTakesPlaceholderLiteralWhenLongerThanRuleBound) {
    auto fx = build_registry({make_rule("t.short", "zzz", "X")});
    MaskingState state;
    state.triggered_rule_ids = {"t.short"};
    // A literal far longer than any `<X_N>` the recognizer can match.
    const std::string long_placeholder = "<X_" + std::string(200, '9') + ">";
    state.replacements = {replacement("t.short", "secret", long_placeholder)};

    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    EXPECT_EQ(cfg.max_pending, long_placeholder.size());
    EXPECT_GT(cfg.max_pending, fx.registry->by_id("t.short")->placeholder_len);
}

TEST(GuardDemaskConfig, UnknownTriggeredRuleIdIsSkippedNotAnError) {
    auto fx = build_registry({email_rule()});
    MaskingState state;
    state.triggered_rule_ids = {"pii.email", "gone.after.reload"};
    state.replacements = {replacement("pii.email", "alice@example.com", "<EMAIL_1>")};

    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    EXPECT_EQ(cfg.max_pending, fx.registry->by_id("pii.email")->placeholder_len);
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "to <EMAIL_1>", false), "to alice@example.com");
}

TEST(GuardDemaskConfig, NullPinnedSnapshotDisablesTolerantPassButKeepsExactPass) {
    MaskingState state = masking_state();

    const Config cfg = Guard::Demask::make_config(state, nullptr);

    EXPECT_FALSE(static_cast<bool>(cfg.scan));
    EXPECT_EQ(cfg.max_pending, std::string("<NAME_1>").size());
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "hi <NAME_1>", false), "hi Alice");
    // No recognizer -> the tolerant form is left exactly as it arrived.
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "hi < name - 1 >", false), "hi < name - 1 >");
}

TEST(GuardDemaskConfig, NoTriggeredRulesDisablesTolerantPass) {
    auto fx = build_registry({email_rule()});
    MaskingState state;
    state.replacements = {replacement("pii.email", "alice@example.com", "<EMAIL_1>")};

    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    EXPECT_FALSE(static_cast<bool>(cfg.scan));
    EXPECT_EQ(cfg.max_pending, std::string("<EMAIL_1>").size());
}

TEST(GuardDemaskConfig, BlankPlaceholderRuleContributesNoRecognizerAndZeroBound) {
    // Registry::compile_rule's blank-placeholder guard: no recognizer at all,
    // placeholder_len 0 -- so the rule adds nothing to max_pending and its
    // (nonexistent) pattern is skipped by the tolerant pass.
    auto fx = build_registry({make_rule("t.blank", "zzz", "   ")});
    ASSERT_EQ(fx.registry->by_id("t.blank")->placeholder_re, nullptr);
    ASSERT_EQ(fx.registry->by_id("t.blank")->placeholder_len, 0U);

    MaskingState state;
    state.triggered_rule_ids = {"t.blank"};
    state.replacements = {replacement("t.blank", "secret", "<B_1>")};

    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    EXPECT_EQ(cfg.max_pending, std::string("<B_1>").size());
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "a <B_1> b", false), "a secret b");
    // The rule resolves, so a scan closure exists, but it can never match.
    ASSERT_TRUE(static_cast<bool>(cfg.scan));
    EXPECT_TRUE(cfg.scan("a < b - 1 > c").empty());
}

// ---------------------------------------------------------------------------
// DemaskChunk(flush=true) -- ports TestDemasker_DemaskChunk_Flush
// ---------------------------------------------------------------------------

TEST(GuardDemasker, FlushReplacesExactPlaceholdersAndLeavesUnknownOnesIntact) {
    std::vector<std::string> seen;
    const Config cfg = mock_config(masking_state(), 16, recording_scan(seen, {}));

    Demasker demasker(cfg);
    const ChunkResult got = demasker.demask_chunk("hello <NAME_1>, keep <UNKNOWN_1>", true);

    EXPECT_EQ(got.out, "hello Alice, keep <UNKNOWN_1>");
    // Pass order: the tolerant pass sees the ALREADY exact-demasked text.
    ASSERT_EQ(seen.size(), 1U);
    EXPECT_EQ(seen[0], "hello Alice, keep <UNKNOWN_1>");
}

TEST(GuardDemasker, FlushDemasksNonCanonicalPlaceholderFormViaTolerantPass) {
    const std::string text = "hello < name-001 >";
    const std::vector<PlaceholderMatch> matches = {
        PlaceholderMatch{"pii.name", std::string("hello ").size(), text.size(), "<NAME_1>"},
    };
    std::vector<std::string> seen;
    const Config cfg = mock_config(masking_state(), 16, recording_scan(seen, matches));

    Demasker demasker(cfg);
    const ChunkResult got = demasker.demask_chunk(text, true);

    EXPECT_EQ(got.out, "hello Alice");
    ASSERT_EQ(seen.size(), 1U);
    EXPECT_EQ(seen[0], "hello < name-001 >");
}

TEST(GuardDemasker, FlushSkipsUnknownAndEmptyPlaceholderMatches) {
    const std::string scanned = "hello Alice <EMAIL_1>";
    const std::vector<PlaceholderMatch> matches = {
        // An unknown placeholder (never minted) and a blank one: both dropped.
        PlaceholderMatch{"pii.email", std::string("hello Alice ").size(), scanned.size(), "<EMAIL_1>"},
        PlaceholderMatch{"empty.placeholder", 0, std::string("hello").size(), ""},
    };
    std::vector<std::string> seen;
    const Config cfg = mock_config(masking_state(), 16, recording_scan(seen, matches));

    Demasker demasker(cfg);
    const ChunkResult got = demasker.demask_chunk("hello <NAME_1> <EMAIL_1>", true);

    EXPECT_EQ(got.out, "hello Alice <EMAIL_1>");
}

// ---------------------------------------------------------------------------
// Overlap policy -- ports TestDemasker_DemaskChunk_ScannerReplacementOrdering
// (matches injected raw, bypassing the scanner's own conflict resolution)
// ---------------------------------------------------------------------------

MaskingState ordering_state() {
    MaskingState state;
    state.triggered_rule_ids = {"left", "long", "right", "short"};
    state.replacements = {
        replacement("short", "short", "<SHORT_1>"),
        replacement("long", "long", "<LONG_1>"),
        replacement("left", "left", "<LEFT_1>"),
        replacement("right", "right", "<RIGHT_1>"),
    };
    return state;
}

/// Runs `text` through a demasker whose tolerant pass returns `matches` raw
/// (no conflict resolution), so `apply_text_replacements`' own overlap guard
/// is what's under test -- Go's mocked-scanner setup exactly.
std::string demask_with_raw_matches(std::string_view text, std::vector<PlaceholderMatch> matches) {
    const Config cfg =
        mock_config(ordering_state(), 32, [matches = std::move(matches)](std::string_view) { return matches; });
    Demasker demasker(cfg);
    return demasker.demask_chunk(text, true).out;
}

TEST(GuardDemaskerOverlap, SameStartKeepsLongestMatch) {
    EXPECT_EQ(demask_with_raw_matches("token",
                                      {
                                          PlaceholderMatch{"short", 0, 3, "<SHORT_1>"},
                                          PlaceholderMatch{"long", 0, 5, "<LONG_1>"},
                                      }),
              "long");
}

TEST(GuardDemaskerOverlap, LaterOverlappingMatchIsSkippedEntirely) {
    EXPECT_EQ(demask_with_raw_matches("abcdef",
                                      {
                                          PlaceholderMatch{"left", 0, 4, "<LEFT_1>"},
                                          PlaceholderMatch{"right", 2, 6, "<RIGHT_1>"},
                                      }),
              "leftef");
}

TEST(GuardDemaskerOverlap, AdjacentMatchesAreBothKept) {
    EXPECT_EQ(demask_with_raw_matches("abcdef",
                                      {
                                          PlaceholderMatch{"right", 3, 6, "<RIGHT_1>"},
                                          PlaceholderMatch{"left", 0, 3, "<LEFT_1>"},
                                      }),
              "leftright");
}

TEST(GuardDemaskerOverlap, RealScannerResolvesConflictsByLongestThenRuleId) {
    // Two rules whose recognizers both match `<X_1>`-ish text at the same
    // offset: resolve_conflicts keeps the longer, ties broken by rule id.
    auto fx = build_registry({make_rule("b.rule", "zzz", "AB"), make_rule("a.rule", "zzz", "AB")});
    MaskingState state;
    state.triggered_rule_ids = {"a.rule", "b.rule"};
    state.replacements = {replacement("a.rule", "RESOLVED", "<AB_7>")};

    const Config cfg = Guard::Demask::make_config(state, fx.registry);
    const std::vector<PlaceholderMatch> matches = cfg.scan("x < ab - 7 > y");

    ASSERT_EQ(matches.size(), 1U);
    EXPECT_EQ(matches[0].rule_id, "a.rule");  // identical spans -> lowest rule id wins
    EXPECT_EQ(matches[0].placeholder, "<AB_7>");
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "x < ab - 7 > y", false), "x RESOLVED y");
}

// ---------------------------------------------------------------------------
// Error contract -- ports TestDemasker_DemaskChunk_ScannerError
// ---------------------------------------------------------------------------

TEST(GuardDemaskerError, ScanFailureThrowsDemaskErrorCarryingTheUnemittedBuffer) {
    const Config cfg = mock_config(masking_state(), 16, [](std::string_view) -> std::vector<PlaceholderMatch> {
        throw std::runtime_error("scan failed");
    });

    Demasker demasker(cfg);
    try {
        demasker.demask_chunk("hello < name-001 >", true);
        FAIL() << "expected DemaskError";
    } catch (const DemaskError& e) {
        // The un-emitted buffer is handed back placeholders-intact so the
        // caller can emit it as a lossless, fail-open fallback.
        EXPECT_EQ(e.unemitted, "hello < name-001 >");
        EXPECT_NE(std::string(e.what()).find("scan failed"), std::string::npos);
    }
    // pending was cleared BEFORE the failure: `unemitted` is the only holder
    // of those bytes, so emitting it cannot double-emit.
    EXPECT_EQ(demasker.pending(), "");
}

TEST(GuardDemaskerError, UnemittedBufferIsExactDemaskedAndIncludesTheHeldPending) {
    // Succeeds once, then fails -- so the failure lands on a call whose buffer
    // already carries a pending tail from the previous chunk.
    int calls = 0;
    const Config cfg = mock_config(masking_state(), 8, [&calls](std::string_view) {
        if (++calls > 1)
            throw std::runtime_error("boom");
        return std::vector<PlaceholderMatch>{};
    });

    Demasker demasker(cfg);
    EXPECT_EQ(demasker.demask_chunk("prefix <NAME", false).out, "pref");
    EXPECT_EQ(demasker.pending(), "ix <NAME");

    try {
        demasker.demask_chunk("_1> tail", true);
        FAIL() << "expected DemaskError";
    } catch (const DemaskError& e) {
        // pending + chunk, with the exact pass already applied and only the
        // tolerant pass failed -- the emitted "pref" is NOT repeated.
        EXPECT_EQ(e.unemitted, "ix Alice tail");
    }
    EXPECT_EQ(demasker.pending(), "");
}

TEST(GuardDemaskerError, OutOfRangeInjectedMatchFailsOpenWithTheWholeBuffer) {
    const Config cfg = mock_config(masking_state(), 16, [](std::string_view text) {
        return std::vector<PlaceholderMatch>{PlaceholderMatch{"pii.name", 0, text.size() + 5, "<NAME_1>"}};
    });

    Demasker demasker(cfg);
    try {
        demasker.demask_chunk("hello world", true);
        FAIL() << "expected DemaskError";
    } catch (const DemaskError& e) {
        EXPECT_EQ(e.unemitted, "hello world");
    }
}

// ---------------------------------------------------------------------------
// Streaming pending buffer -- ports TestDemasker_DemaskChunk_StreamingPending
// and ..._KeepsExactPlaceholderTailWhenMaxPendingEqualsPlaceholderLen
// ---------------------------------------------------------------------------

TEST(GuardDemaskerStreaming, PendingSuffixIsHeldBackUntilFlush) {
    std::vector<std::string> seen;
    const Config cfg = mock_config(masking_state(), 64, recording_scan(seen, {}));

    Demasker demasker(cfg);
    EXPECT_EQ(demasker.demask_chunk("hello <NA", false).out, "");
    EXPECT_EQ(demasker.demask_chunk("ME_1>!", true).out, "hello Alice!");
    ASSERT_EQ(seen.size(), 2U);
    EXPECT_EQ(seen[0], "hello <NA");
    EXPECT_EQ(seen[1], "hello Alice!");
}

TEST(GuardDemaskerStreaming, PendingBuffersAreIndependentPerDemasker) {
    std::vector<std::string> seen;
    const Config cfg = mock_config(masking_state(), 64, recording_scan(seen, {}));

    Demasker first(cfg);
    Demasker second(cfg);

    EXPECT_EQ(first.demask_chunk("first <NA", false).out, "");
    EXPECT_EQ(second.demask_chunk("second <NAME_1>", true).out, "second Alice");
    EXPECT_EQ(first.demask_chunk("ME_1>", true).out, "first Alice");
}

TEST(GuardDemaskerStreaming, KeepsExactPlaceholderTailWhenMaxPendingEqualsPlaceholderLen) {
    std::vector<std::string> seen;
    const Config cfg = mock_config(masking_state(), std::string("<NAME_1>").size(), recording_scan(seen, {}));

    Demasker demasker(cfg);
    EXPECT_EQ(demasker.demask_chunk("before <NA", false).out, "be");
    EXPECT_EQ(demasker.pending(), "fore <NA");
    EXPECT_EQ(demasker.demask_chunk("ME_1> after", true).out, "fore Alice after");
}

TEST(GuardDemaskerStreaming, EmptyChunkWithoutFlushEmitsNothingAndKeepsPending) {
    std::vector<std::string> seen;
    const Config cfg = mock_config(masking_state(), 64, recording_scan(seen, {}));

    Demasker demasker(cfg);
    EXPECT_EQ(demasker.demask_chunk("", false).out, "");
    EXPECT_EQ(demasker.pending(), "");
    EXPECT_EQ(demasker.demask_chunk("hi", false).out, "");
    EXPECT_EQ(demasker.pending(), "hi");
    // An empty chunk must not disturb an already-held pending buffer.
    EXPECT_EQ(demasker.demask_chunk("", false).out, "");
    EXPECT_EQ(demasker.pending(), "hi");
    EXPECT_EQ(demasker.demask_chunk("", true).out, "hi");
    EXPECT_EQ(demasker.pending(), "");
}

TEST(GuardDemaskerStreaming, DoesNotSplitUtf8Rune) {
    MaskingState state;
    state.replacements = {replacement("", "x", "x")};
    const Config cfg = mock_config(state, 1);

    Demasker demasker(cfg);
    EXPECT_EQ(demasker.demask_chunk("\xD0\xB6\x61", false).out, "\xD0\xB6");  // "жa" -> emits "ж"
    EXPECT_EQ(demasker.demask_chunk("", true).out, "a");
}

TEST(GuardDemaskerStreaming, HoldBoundaryIsTrimmedBackAcrossEveryRuneWidth) {
    // For each rune width, the hold boundary is forced to land INSIDE the
    // rune (max_pending is chosen so len(text) - max_pending splits it) and
    // must be trimmed back, never split.
    const std::vector<std::string> runes = {
        "\xC3\xA9",          // U+00E9 e-acute, 2 bytes
        "\xE2\x82\xAC",      // U+20AC euro sign, 3 bytes
        "\xF0\x9F\x98\x80",  // U+1F600 grinning face, 4 bytes
    };
    for (const std::string& rune : runes) {
        for (std::size_t offset = 1; offset < rune.size(); ++offset) {
            const std::string text = "ab" + rune + "cd";
            MaskingState state;
            state.replacements = {replacement("", "zzz", "<Z_1>")};
            Config cfg = Guard::Demask::make_config(state, nullptr);
            // Boundary at 2 + offset, i.e. `offset` bytes into the rune.
            cfg.max_pending = text.size() - (2 + offset);

            Demasker demasker(cfg);
            const std::string emitted = demasker.demask_chunk(text, false).out;
            EXPECT_EQ(emitted, "ab") << "rune width " << rune.size() << " offset " << offset;
            EXPECT_EQ(demasker.pending(), rune + "cd");
            EXPECT_EQ(emitted + demasker.demask_chunk("", true).out, text);
        }
    }
}

TEST(GuardDemaskerStreaming, BufferOpeningMidRuneEmitsNothingRatherThanSplitting) {
    MaskingState state;
    state.replacements = {replacement("", "zzz", "<Z_1>")};
    Config cfg = Guard::Demask::make_config(state, nullptr);
    cfg.max_pending = 1;

    Demasker demasker(cfg);
    // A lone continuation byte followed by another: no rune start exists
    // before the boundary, so nothing may be emitted.
    EXPECT_EQ(demasker.demask_chunk("\xB6\xB6", false).out, "");
    EXPECT_EQ(demasker.pending(), "\xB6\xB6");
    EXPECT_EQ(demasker.demask_chunk("", true).out, "\xB6\xB6");
}

// ---------------------------------------------------------------------------
// Torture matrix: chunk boundaries must never leak a split placeholder
// ---------------------------------------------------------------------------

struct TortureFixture {
    RegistryFixture registry;
    Config cfg;
    std::string original;
    std::string masked;
};

/// A masked text with three placeholders, the last one ending at the very
/// last byte -- the position where an off-by-one in the hold-back would leak.
TortureFixture make_torture_fixture() {
    TortureFixture fx;
    fx.registry = build_registry({email_rule()});
    fx.original = "mail alice@example.com then bob@example.com; finally carol@example.com";

    Guard::MaskResult masked = Guard::mask_texts({fx.original}, fx.registry.rules);
    fx.masked = masked.masked_texts[0];
    fx.cfg = Guard::Demask::make_config(masked.state, fx.registry.registry);
    return fx;
}

TEST(GuardDemaskerTorture, EveryChunkSizeFrom1To64MatchesTheOneShotDemask) {
    const TortureFixture fx = make_torture_fixture();
    ASSERT_NE(fx.masked, fx.original);
    ASSERT_EQ(fx.masked.back(), '>') << "the last placeholder must end at the very last byte";

    const std::string want = Guard::Demask::demask_all(fx.cfg, fx.masked, false);
    ASSERT_EQ(want, fx.original);

    for (std::size_t chunk_size = 1; chunk_size <= 64; ++chunk_size) {
        EXPECT_EQ(demask_in_chunks(fx.cfg, fx.masked, chunk_size, false), want) << "chunk size " << chunk_size;
    }
}

TEST(GuardDemaskerTorture, FlushAtEverySplitPositionMatchesTheOneShotDemask) {
    const TortureFixture fx = make_torture_fixture();
    const std::string want = Guard::Demask::demask_all(fx.cfg, fx.masked, false);

    for (std::size_t split = 0; split <= fx.masked.size(); ++split) {
        Demasker demasker(fx.cfg);
        std::string got = demasker.demask_chunk(std::string_view(fx.masked).substr(0, split), false).out;
        got += demasker.demask_chunk(std::string_view(fx.masked).substr(split), true).out;
        EXPECT_EQ(got, want) << "split at " << split;
    }
}

TEST(GuardDemaskerTorture, NoIntermediateEmissionEverContainsAPlaceholderFragment) {
    const TortureFixture fx = make_torture_fixture();

    for (std::size_t chunk_size = 1; chunk_size <= 16; ++chunk_size) {
        Demasker demasker(fx.cfg);
        std::string emitted;
        for (std::size_t i = 0; i < fx.masked.size(); i += chunk_size)
            emitted += demasker.demask_chunk(std::string_view(fx.masked).substr(i, chunk_size), false).out;
        // Before the flush, nothing emitted so far may contain any part of a
        // placeholder -- '<' would be the first byte of one.
        EXPECT_EQ(emitted.find('<'), std::string::npos) << "chunk size " << chunk_size << " emitted: " << emitted;
        emitted += demasker.demask_chunk("", true).out;
        EXPECT_EQ(emitted, fx.original);
    }
}

TEST(GuardDemaskerTorture, MultiByteUtf8StraddlingTheHoldBoundaryRoundTrips) {
    auto fx = build_registry({email_rule()});
    // Cyrillic + CJK + emoji around and between the placeholders, so the hold
    // boundary lands inside a multi-byte rune for many chunk sizes.
    const std::string original = "привет alice@example.com 世界 bob@example.com 😀 конец";
    Guard::MaskResult masked = Guard::mask_texts({original}, fx.rules);
    const Config cfg = Guard::Demask::make_config(masked.state, fx.registry);
    const std::string masked_text = masked.masked_texts[0];

    ASSERT_EQ(Guard::Demask::demask_all(cfg, masked_text, false), original);
    for (std::size_t chunk_size = 1; chunk_size <= 64; ++chunk_size) {
        EXPECT_EQ(demask_in_chunks(cfg, masked_text, chunk_size, false), original) << "chunk size " << chunk_size;
    }
}

TEST(GuardDemaskerTorture, RealMaskThenDemaskRoundTripsByteIdenticallyWithAReservedLookalike) {
    auto fx = build_registry({email_rule()});
    // `<EMAIL_1>` is already present in the plaintext, so the masker reserves
    // it and mints `<EMAIL_2>` for the real address. Demasking must restore
    // the address and leave the lookalike byte-identical.
    const std::string original = "see <EMAIL_1> above; write to alice@example.com now";

    Guard::MaskResult masked = Guard::mask_texts({original}, fx.rules);
    ASSERT_EQ(masked.state.replacements.size(), 1U);
    EXPECT_EQ(masked.state.replacements[0].placeholder, "<EMAIL_2>");
    EXPECT_NE(masked.masked_texts[0].find("<EMAIL_1>"), std::string::npos);

    const Config cfg = Guard::Demask::make_config(masked.state, fx.registry);
    EXPECT_EQ(Guard::Demask::demask_all(cfg, masked.masked_texts[0], false), original);
    for (std::size_t chunk_size = 1; chunk_size <= 32; ++chunk_size)
        EXPECT_EQ(demask_in_chunks(cfg, masked.masked_texts[0], chunk_size, false), original)
            << "chunk size " << chunk_size;
}

TEST(GuardDemaskerTorture, TolerantFormsMapToTheRightOriginal) {
    auto fx = build_registry({email_rule()});
    MaskingState state;
    state.triggered_rule_ids = {"pii.email"};
    state.replacements = {
        replacement("pii.email", "one@example.com", "<EMAIL_1>"),
        replacement("pii.email", "twelve@example.com", "<EMAIL_12>"),
    };
    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    EXPECT_EQ(Guard::Demask::demask_all(cfg, "a < email - 12 > b", false), "a twelve@example.com b");
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "a <email_12> b", false), "a twelve@example.com b");
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "a < EMAIL-1 > b", false), "a one@example.com b");
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "a <Email 1> b", false), "a one@example.com b");
    // Leading zeros parse to the same index (Go's strconv.Atoi).
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "a < email-001 > b", false), "a one@example.com b");
}

TEST(GuardDemaskerTorture, UnknownPlaceholderNumberIsLeftExactlyAsItArrived) {
    auto fx = build_registry({email_rule()});
    MaskingState state;
    state.triggered_rule_ids = {"pii.email"};
    state.replacements = {replacement("pii.email", "one@example.com", "<EMAIL_1>")};
    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    // The recognizer matches, the lookup misses -> dropped from the
    // replacement list, so the text is untouched (never blanked, never
    // guessed at a neighbouring index).
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "keep <EMAIL_99> please", false), "keep <EMAIL_99> please");
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "keep < email - 99 > please", false), "keep < email - 99 > please");
    // Index 0 is rejected outright by the scanner (Go's `index <= 0`).
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "keep <EMAIL_0> please", false), "keep <EMAIL_0> please");
    for (std::size_t chunk_size = 1; chunk_size <= 24; ++chunk_size) {
        EXPECT_EQ(demask_in_chunks(cfg, "keep <EMAIL_99> please", chunk_size, false), "keep <EMAIL_99> please")
            << "chunk size " << chunk_size;
    }
}

TEST(GuardDemaskerTorture, ExactPassPriorityFollowsEntryOrderNotMatchLength) {
    // Go's strings.Replacer picks the EARLIEST-registered pattern that
    // matches at a position, not the longest -- observable only with a
    // caller-supplied table where one placeholder prefixes another.
    MaskingState state;
    state.replacements = {
        replacement("", "SHORT", "<P_1"),
        replacement("", "LONG", "<P_1>"),
    };
    const Config cfg = Guard::Demask::make_config(state, nullptr);

    EXPECT_EQ(Guard::Demask::demask_all(cfg, "x<P_1>y", false), "xSHORT>y");
}

TEST(GuardDemaskerTorture, ExactPassNeverRescansAnInsertedOriginal) {
    // An original that itself looks like another placeholder must NOT be
    // re-demasked -- Go's replacer advances past the inserted bytes.
    MaskingState state;
    state.replacements = {
        replacement("", "<Q_1>", "<P_1>"),
        replacement("", "BOOM", "<Q_1>"),
    };
    const Config cfg = Guard::Demask::make_config(state, nullptr);

    EXPECT_EQ(Guard::Demask::demask_all(cfg, "<P_1>", false), "<Q_1>");
}

// ---------------------------------------------------------------------------
// JSON-escaped variant -- Factory.JSONDemasker
// ---------------------------------------------------------------------------

TEST(GuardDemaskerJsonContext, RestoredOriginalsAreEscapedForAJsonStringContext) {
    MaskingState state;
    state.replacements = {replacement("", "say \"hi\"\nbye\\now", "<SECRET_1>")};
    const Config cfg = Guard::Demask::make_config(state, nullptr);

    EXPECT_EQ(Guard::Demask::demask_all(cfg, "<SECRET_1>", true), R"(say \"hi\"\nbye\\now)");
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "<SECRET_1>", false), "say \"hi\"\nbye\\now");

    // The accumulated fragment stays a valid JSON string body.
    const std::string fragment = R"({"m":")" + Guard::Demask::demask_all(cfg, "<SECRET_1>", true) + R"("})";
    EXPECT_TRUE(Guard::Json::valid(fragment));
}

TEST(GuardDemaskerJsonContext, TolerantPassAlsoUsesTheEscapedTable) {
    auto fx = build_registry({make_rule("t.secret", "zzz", "SECRET")});
    MaskingState state;
    state.triggered_rule_ids = {"t.secret"};
    state.replacements = {replacement("t.secret", R"(a"b)", "<SECRET_1>")};
    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    EXPECT_EQ(Guard::Demask::demask_all(cfg, "< secret - 1 >", true), R"(a\"b)");
    EXPECT_EQ(Guard::Demask::demask_all(cfg, "< secret - 1 >", false), R"(a"b)");
}

TEST(GuardDemaskerJsonContext, ChunkedJsonEscapedOutputMatchesTheOneShot) {
    auto fx = build_registry({make_rule("t.secret", "zzz", "SECRET")});
    MaskingState state;
    state.triggered_rule_ids = {"t.secret"};
    state.replacements = {replacement("t.secret", R"(a"b\c)", "<SECRET_1>")};
    const Config cfg = Guard::Demask::make_config(state, fx.registry);

    const std::string masked = R"({"k":"<SECRET_1>"})";
    const std::string want = Guard::Demask::demask_all(cfg, masked, true);
    for (std::size_t chunk_size = 1; chunk_size <= 24; ++chunk_size)
        EXPECT_EQ(demask_in_chunks(cfg, masked, chunk_size, true), want) << "chunk size " << chunk_size;
}

// ---------------------------------------------------------------------------
// demask_json_arguments -- common.DemaskJSONArguments
// ---------------------------------------------------------------------------

Config args_config(std::vector<Replacement> replacements) {
    MaskingState state;
    state.replacements = std::move(replacements);
    return Guard::Demask::make_config(state, nullptr);
}

TEST(GuardDemaskJsonArguments, NaiveSubstitutionWinsWhenItStaysValidJson) {
    const Config cfg = args_config({replacement("", "alice@example.com", "<EMAIL_1>")});

    EXPECT_EQ(Guard::Demask::demask_json_arguments(cfg, R"({"to":"<EMAIL_1>","cc":null})"),
              R"({"to":"alice@example.com","cc":null})");
}

TEST(GuardDemaskJsonArguments, EmptyInputIsReturnedUnchanged) {
    const Config cfg = args_config({replacement("", "x", "<E_1>")});
    EXPECT_EQ(Guard::Demask::demask_json_arguments(cfg, ""), "");
}

TEST(GuardDemaskJsonArguments, StructuralFallbackReEscapesAQuotedOriginal) {
    const Config cfg = args_config({replacement("", R"(say "hi")", "<MSG_1>")});

    // The naive pass would produce `{"m":"say "hi""}` -- invalid JSON.
    const std::string got = Guard::Demask::demask_json_arguments(cfg, R"({"m":"<MSG_1>"})");

    EXPECT_EQ(got, R"({"m":"say \"hi\""})");
    ASSERT_TRUE(Guard::Json::valid(got));
}

TEST(GuardDemaskJsonArguments, StructuralFallbackPreservesNumberFormattingByteForByte) {
    const Config cfg = args_config({replacement("", R"(q"uote)", "<Q_1>")});

    // Trailing zeros, an explicit exponent sign and a negative zero all
    // survive: non-string tokens are spliced AROUND, never re-serialized.
    const std::string masked = R"({"a":1.20000,"b":1e+3,"c":-0.0,"e":"<Q_1>"})";
    const std::string want = R"({"a":1.20000,"b":1e+3,"c":-0.0,"e":"q\"uote"})";

    const std::string got = Guard::Demask::demask_json_arguments(cfg, masked);

    ASSERT_TRUE(Guard::Json::valid(got));
    EXPECT_EQ(got, want);
}

TEST(GuardDemaskJsonArguments, StructuralFallbackPreservesIntegersBeyondDoublePrecision) {
    const Config cfg = args_config({replacement("", R"(q"uote)", "<Q_1>")});

    const std::string masked = R"({"n":123456789012345678901234567890,"e":"<Q_1>"})";
    const std::string want = R"({"n":123456789012345678901234567890,"e":"q\"uote"})";

    EXPECT_EQ(Guard::Demask::demask_json_arguments(cfg, masked), want);
}

TEST(GuardDemaskJsonArguments, StructuralFallbackPreservesKeyOrderAndWhitespace) {
    const Config cfg = args_config({replacement("", R"(v")", "<V_1>")});

    const std::string masked = "{ \"z\": \"<V_1>\", \"a\": 1 }";
    const std::string got = Guard::Demask::demask_json_arguments(cfg, masked);

    EXPECT_EQ(got, "{ \"z\": \"v\\\"\", \"a\": 1 }");
}

TEST(GuardDemaskJsonArguments, StructuralFallbackPatchesDuplicateKeysBySpanNotByPath) {
    // Path re-resolution would resolve BOTH leaves to the first "a" and
    // mis-patch; spans address each leaf uniquely.
    const Config cfg = args_config({
        replacement("", R"(first")", "<D_1>"),
        replacement("", R"(second")", "<D_2>"),
    });

    const std::string got = Guard::Demask::demask_json_arguments(cfg, R"({"a":"<D_1>","a":"<D_2>"})");

    EXPECT_EQ(got, R"({"a":"first\"","a":"second\""})");
}

TEST(GuardDemaskJsonArguments, StructuralFallbackWalksNestedObjectsAndArrays) {
    const Config cfg = args_config({
        replacement("", R"(deep")", "<N_1>"),
        replacement("", "plain", "<N_2>"),
    });

    const std::string got = Guard::Demask::demask_json_arguments(cfg, R"({"o":{"p":["<N_1>","<N_2>"]},"q":"<N_2>"})");

    EXPECT_EQ(got, R"({"o":{"p":["deep\"","plain"]},"q":"plain"})");
}

TEST(GuardDemaskJsonArguments, ObjectKeysAreNeverRewritten) {
    const Config cfg = args_config({replacement("", R"(k")", "<K_1>")});

    // The key is not a string LEAF; only values are demasked -- rewriting a
    // key could collide with another key or change the argument's shape.
    const std::string got = Guard::Demask::demask_json_arguments(cfg, R"({"<K_1>":"<K_1>"})");

    EXPECT_EQ(got, R"({"<K_1>":"k\""})");
}

TEST(GuardDemaskJsonArguments, InvalidInputJsonIsReturnedUnchangedRatherThanHalfPatched) {
    const Config cfg = args_config({replacement("", R"(q")", "<Q_1>")});

    const std::string masked = R"({"a":"<Q_1>")";  // truncated: no closing brace
    EXPECT_EQ(Guard::Demask::demask_json_arguments(cfg, masked), masked);
}

TEST(GuardDemaskJsonArguments, NonJsonInputWithNoPlaceholdersIsReturnedUnchanged) {
    const Config cfg = args_config({replacement("", "x", "<E_1>")});
    EXPECT_EQ(Guard::Demask::demask_json_arguments(cfg, "not json at all"), "not json at all");
}

TEST(GuardDemaskJsonArguments, BareStringDocumentIsDemaskedStructurally) {
    const Config cfg = args_config({replacement("", R"(bare")", "<B_1>")});

    const std::string got = Guard::Demask::demask_json_arguments(cfg, R"("<B_1>")");

    EXPECT_EQ(got, R"("bare\"")");
    EXPECT_TRUE(Guard::Json::valid(got));
}

TEST(GuardDemaskJsonArguments, PlaceholderSurroundedByJsonEscapesIsDemaskedAndTheEscapesSurvive) {
    // The naive pass handles this one: the placeholder is JSON-safe, so it
    // appears verbatim in the raw bytes and the `\n`/`\t` escapes around it
    // are copied through untouched.
    const Config cfg = args_config({replacement("", "alice@example.com", "<EMAIL_1>")});

    const std::string got = Guard::Demask::demask_json_arguments(cfg, R"({"m":"line\n<EMAIL_1>\ttab"})");

    EXPECT_EQ(got, R"({"m":"line\nalice@example.com\ttab"})");
}

TEST(GuardDemaskJsonArguments, NoPlaceholdersLeavesTheDocumentByteIdentical) {
    const Config cfg = args_config({replacement("", R"(q")", "<Q_1>")});

    const std::string masked = R"({ "a" : [ 1.0 , "text" ] })";
    EXPECT_EQ(Guard::Demask::demask_json_arguments(cfg, masked), masked);
}

}  // namespace
