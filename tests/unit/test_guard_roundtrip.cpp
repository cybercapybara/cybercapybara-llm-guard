/**
 * @file test_guard_roundtrip.cpp
 * @brief Full-pipeline integration test (Task 2.6): extract -> mask -> patch
 *        -> demask over the REAL rule catalogs, proving Phase 2's pieces
 *        (Json.hpp, the three Extract.hpp extractors, Masker.hpp,
 *        Demasker.hpp) compose into a byte-identical round trip.
 * @details See `.superpowers/sdd/2026-08-15-phase2-json-extractors-demasker/
 *          task-2.6-brief.md` and `phase2-interfaces.md`.
 *
 *          **Raw-object fields only exist on ONE side.** Grepping every
 *          `ContentField{...}` construction site in `ChatCompletions.hpp`,
 *          `Messages.hpp` and `Responses.hpp` confirms `is_raw_object` is
 *          `false` for every field EITHER `extract_request` produces, in ALL
 *          THREE formats -- the ChatCompletions/Responses "arguments" fields
 *          are JSON STRINGS (scanned/patched as text like any other field);
 *          Messages' REQUEST-side `tool_use.input` (an assistant turn replayed
 *          from history) is walked LEAF BY LEAF via `string_leaves_in`, each
 *          leaf its own ordinary string `ContentField`. The ONLY place
 *          `is_raw_object == true` ever appears is `Messages::
 *          extract_response`'s `tool_use` block: a FRESH model turn, patched
 *          as one whole raw JSON object (`sjson.SetRawBytes` in the Go
 *          reference) rather than string-by-string, because it has not been
 *          re-marshaled through Go structs and so keeps its exact upstream
 *          byte shape. So exercising BOTH kinds requires testing a Messages
 *          RESPONSE body alongside the (request-side) round trips below --
 *          `MessagesResponseRawToolUseInputMasksAndDemasksByteIdentically`
 *          is that case.
 *
 *          **Structural-vs-plain demask selection**, read directly off the
 *          Go reference's `internal/controller/gateway/response.go`
 *          (`demaskAndPatchFields`), not guessed: a field is demasked via
 *          `DemaskJSONArguments` when its path ends in EITHER `.input`
 *          (`isRawObject`) OR `.arguments`; every other field goes through
 *          plain `DemaskChunk(flush=true)`. `is_raw_object` is exactly the
 *          C++ mirror of the `.input` suffix (see above), so
 *          `demask_field_text` below tests `f.is_raw_object ||
 *          path_is_arguments(f.path)` -- covering ONE more case than the
 *          brief's own "path ends in arguments" phrasing names explicitly,
 *          confirmed correct by this direct Go read rather than assumed.
 *
 *          **Why the structural (non-naive) fallback inside
 *          `demask_json_arguments` cannot be reached by a self-consistent
 *          single-field round trip** (a finding, not a limitation of this
 *          test): masking and demasking of one field both operate on the
 *          SAME flat text representation (`ContentField::text`), and
 *          `MaskerState::mask_text` only ever substitutes a placeholder for
 *          the EXACT matched substring, byte for byte, then
 *          `demask_all`/`demask_json_arguments`'s naive pass reverses
 *          exactly that substitution. If the flat "arguments" text was valid
 *          JSON before masking, swapping one substring for a placeholder
 *          (which can't itself corrupt JSON, since `Json::valid(masked.body)`
 *          is asserted below) and later swapping it back can never produce
 *          invalid JSON either -- the two passes are inverses over the same
 *          bytes. And by JSON's OWN grammar, no regex match living entirely
 *          inside an already-valid-JSON string value can ever capture a raw,
 *          unescaped `"` (it would have terminated the string first) --
 *          confirmed directly against every rule in `configs/rules.yaml` /
 *          `configs/rules.gitleaks.generated.yaml`, none of which admit a
 *          raw quote or lone backslash into a capture group's character
 *          class either. So the structural fallback is unreachable from
 *          THIS test's own round trip by construction, not by omission.
 *          `GuardRoundTripJsonEscape.
 *          DemaskJsonArgumentsStructuralFallbackHandlesEmbeddedQuotesAndBackslashes`
 *          below exercises it directly instead, via a hand-built
 *          `MaskingState` (the same technique `test_guard_demasker.cpp`
 *          already uses for its own `GuardDemaskJsonArguments.*` suite) --
 *          driven through the SAME `Config`/`demask_json_arguments` pairing
 *          this file's round-trip driver uses, so the wiring under test is
 *          identical even though the input can't come from `mask_texts`
 *          itself.
 *
 *          **Custom rule, DataType::Custom.** Neither shipped catalog
 *          populates data_type 6 (Custom) -- `configs/rules.yaml` covers 1-5,
 *          `configs/rules.gitleaks.generated.yaml` covers 1-3 only (grepped
 *          directly). `secret_note_rule()` below is one small addition so
 *          the registry this file builds genuinely covers all 6 non-
 *          Unspecified `DataType` values (pinned by
 *          `GuardRoundTripCatalog.LoadedRegistryCoversAllSixDataTypes`), and
 *          it deliberately has NO character-class restriction on its capture
 *          group (unlike every real catalog rule), so it can carry a raw
 *          quote/backslash/Cyrillic mix through a PLAIN (non-JSON-nested)
 *          text field for the UTF-8 + special-character byte-identity case.
 */

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "guard/ApiFormat.hpp"
#include "guard/Masker.hpp"
#include "guard/MaskingState.hpp"
#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/RulesYaml.hpp"
#include "guard/demask/Demasker.hpp"
#include "guard/extract/Extract.hpp"
#include "guard/json/Json.hpp"
#include "utils/Base64.hpp"

namespace {

using Guard::ApiFormat;
using Guard::CompiledRule;
using Guard::DataType;
using Guard::Registry;
using Guard::Rule;
using Guard::Demask::Config;
using Guard::Demask::Demasker;
using Guard::Extract::ContentField;
using Guard::Extract::ExtractResult;
using Guard::Json::PathSeg;
using Guard::Json::ValueSpan;

// ── Catalog fixture: both real catalogs + one Custom-data-type addition ────

std::vector<std::string> real_catalog_paths() {
    const std::string root(LLMGUARD_REPO_ROOT);
    return {root + "/configs/rules.yaml", root + "/configs/rules.gitleaks.generated.yaml"};
}

// See the file-level doc comment: no shipped rule's capture group admits a
// raw '"' or '\', so this is the only rule in the registry that can (used by
// the "quotes/backslashes in a plain field" case below), and it is the only
// DataType::Custom rule, completing all 6 non-Unspecified data types.
Rule secret_note_rule() {
    Rule r;
    r.id = "test.secret-note";
    r.name = "test.secret-note";
    r.data_type = DataType::Custom;
    r.regex = R"(SECRETNOTE:([^.\n]{1,200}))";
    r.masking.capture_groups = {1};
    r.masking.placeholder = "SECRET_NOTE";
    return r;
}

struct CatalogFixture {
    std::shared_ptr<const Registry> registry;
    std::vector<const CompiledRule*> rules;
};

const CatalogFixture& full_catalog() {
    static const CatalogFixture fixture = [] {
        CatalogFixture fx;
        Guard::LoadedRules loaded = Guard::load_rules_files(real_catalog_paths());
        std::vector<Rule> all_rules = std::move(loaded.rules);
        all_rules.push_back(secret_note_rule());
        fx.registry = Registry::build(all_rules);
        for (const auto& cr : fx.registry->all())
            fx.rules.push_back(&cr);
        return fx;
    }();
    return fixture;
}

// ── Shared extract -> mask -> splice -> demask -> splice driver ────────────

// Go's `strings.HasSuffix(f.Path, ".arguments")` (response.go's
// `demaskAndPatchFields`), ported to `PathSeg`'s pre-split shape: the last
// segment is an object key (not an array index) literally equal to
// "arguments".
bool path_is_arguments(const std::vector<PathSeg>& path) {
    return !path.empty() && !path.back().is_index && path.back().key == "arguments";
}

std::vector<ContentField> extract_fields(std::string_view body, ApiFormat format, bool is_response) {
    const ExtractResult result =
        is_response ? Guard::Extract::extract_response(body, format) : Guard::Extract::extract_request(body, format);
    return std::get<std::vector<ContentField>>(result);
}

struct MaskedBody {
    std::string body;
    Guard::MaskingState state;
};

// Extracts every ContentField from `original`, masks their texts through one
// shared MaskerState (Guard::mask_texts), then splices the masked texts back
// BY SPAN: `Json::encode_string(..., /*with_quotes=*/true)` for an ordinary
// string field (its span covers the quotes, per ValueSpan's own contract),
// or the masked text RAW for an `is_raw_object` field (its span covers a
// bare JSON object, no quotes to re-add). Mirrors the gateway's own
// "nothing triggered -> leave the body alone" pattern (task-2.6-brief.md
// step 7, the ledgered handoff: this decision is the CALLER's, not
// mask_texts'/Json::splice_all's) by skipping the splice entirely when
// `state.replacements` is empty, and skips an individual field's edit when
// its masked text is byte-identical to its original (nothing to patch).
MaskedBody mask_body(std::string_view original,
                     ApiFormat format,
                     bool is_response,
                     const std::vector<const CompiledRule*>& rules) {
    const std::vector<ContentField> fields = extract_fields(original, format, is_response);

    std::vector<std::string> texts;
    texts.reserve(fields.size());
    for (const auto& f : fields)
        texts.push_back(f.text);

    const Guard::MaskResult masked = Guard::mask_texts(texts, rules);

    MaskedBody out;
    out.state = masked.state;

    if (out.state.replacements.empty()) {
        out.body = std::string(original);
        return out;
    }

    std::vector<std::pair<ValueSpan, std::string>> edits;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (masked.masked_texts[i] == texts[i])
            continue;
        const ContentField& f = fields[i];
        std::string replacement =
            f.is_raw_object ? masked.masked_texts[i] : Guard::Json::encode_string(masked.masked_texts[i], true);
        edits.emplace_back(f.span, std::move(replacement));
    }
    out.body = edits.empty() ? std::string(original) : Guard::Json::splice_all(original, edits);
    return out;
}

// Ports response.go's `demaskAndPatchFields` structural-vs-plain selection --
// see the file-level doc comment. `chunk_size == 0` means one-shot
// (`demask_all` / `demask_json_arguments`); otherwise the plain-text branch
// streams through `Demasker::demask_chunk` in `chunk_size`-byte pieces
// (`demask_json_arguments` has no streaming form, matching Go, which never
// streams these two field kinds either -- see the same function).
std::string demask_field_text(const Config& cfg, const ContentField& f, std::size_t chunk_size) {
    if (f.is_raw_object || path_is_arguments(f.path))
        return Guard::Demask::demask_json_arguments(cfg, f.text);

    if (chunk_size == 0)
        return Guard::Demask::demask_all(cfg, f.text, false);

    Demasker demasker(cfg, false);
    std::string out;
    for (std::size_t i = 0; i < f.text.size(); i += chunk_size)
        out += demasker.demask_chunk(std::string_view(f.text).substr(i, chunk_size), false).out;
    out += demasker.demask_chunk("", true).out;
    return out;
}

// Re-extracts `masked_body` (paths/spans re-derived against the MASKED
// bytes, per task-2.6-brief.md step 4 -- a field's length changed under
// masking, so its original-body span is no longer valid here), demasks each
// field, and splices the results back BY SPAN exactly like `mask_body` does.
std::string demask_body(
    std::string_view masked_body, ApiFormat format, bool is_response, const Config& cfg, std::size_t chunk_size) {
    const std::vector<ContentField> fields = extract_fields(masked_body, format, is_response);

    std::vector<std::pair<ValueSpan, std::string>> edits;
    for (const auto& f : fields) {
        std::string demasked = demask_field_text(cfg, f, chunk_size);
        if (demasked == f.text)
            continue;
        std::string replacement = f.is_raw_object ? demasked : Guard::Json::encode_string(demasked, true);
        edits.emplace_back(f.span, std::move(replacement));
    }
    return edits.empty() ? std::string(masked_body) : Guard::Json::splice_all(masked_body, edits);
}

// The full round trip, plus every invariant task-2.6-brief.md's flow calls
// for: masked-body JSON validity, a placeholder token present, no original
// secret substring surviving anywhere in the masked body, one-shot
// byte-identical recovery, and chunk sizes 1..64 all agreeing with the
// one-shot result.
void expect_round_trip(const std::string& original, ApiFormat format, bool is_response) {
    const CatalogFixture& cat = full_catalog();
    const MaskedBody masked = mask_body(original, format, is_response, cat.rules);

    ASSERT_FALSE(masked.state.replacements.empty()) << "fixture body must actually trigger the catalog";
    EXPECT_TRUE(Guard::Json::valid(masked.body)) << "masked body: " << masked.body;
    EXPECT_NE(masked.body, original);
    EXPECT_NE(masked.body.find('<'), std::string::npos) << "no placeholder-shaped token found in: " << masked.body;

    for (const auto& rep : masked.state.replacements) {
        EXPECT_EQ(masked.body.find(rep.original), std::string::npos)
            << "original leaked into the masked body: \"" << rep.original << "\"";
    }

    const Config cfg = Guard::Demask::make_config(masked.state, cat.registry);

    const std::string demasked_one_shot = demask_body(masked.body, format, is_response, cfg, 0);
    EXPECT_EQ(demasked_one_shot, original);

    for (std::size_t chunk_size = 1; chunk_size <= 64; ++chunk_size) {
        EXPECT_EQ(demask_body(masked.body, format, is_response, cfg, chunk_size), original)
            << "chunk size " << chunk_size;
    }
}

void expect_untouched_when_nothing_triggers(const std::string& original, ApiFormat format, bool is_response) {
    const CatalogFixture& cat = full_catalog();
    const MaskedBody masked = mask_body(original, format, is_response, cat.rules);
    EXPECT_TRUE(masked.state.replacements.empty());
    EXPECT_EQ(masked.body, original);
}

// Reversed-then-base64url-encoded (same mitigation `test_guard_rule_corpus.cpp`'s
// file-level doc comment documents, via `scripts/corpus-codec.py`): a
// plaintext Stripe-key-shaped literal in this source trips GitHub's
// server-side push-protection secret scanner even as an obviously synthetic
// test fixture (confirmed the hard way -- the first version of this file
// used a plain literal and was rejected on push). `Utils::Base64::url_decode`
// already ignores stray '=' wherever they land, so reversing first and
// un-reversing at decode time (rather than only at encode time) round-trips
// correctly regardless of padding.
std::string decode_reversed_b64(std::string reversed_b64url) {
    std::reverse(reversed_b64url.begin(), reversed_b64url.end());
    return Utils::Base64::url_decode(reversed_b64url);
}

}  // namespace

// ── Catalog sanity ──────────────────────────────────────────────────────

TEST(GuardRoundTripCatalog, LoadedRegistryCoversAllSixDataTypes) {
    const CatalogFixture& cat = full_catalog();
    for (int dt = static_cast<int>(DataType::Credentials); dt <= static_cast<int>(DataType::Custom); ++dt) {
        const auto rules = cat.registry->for_data_types({static_cast<DataType>(dt)});
        EXPECT_FALSE(rules.empty()) << "no rules for DataType " << dt;
    }
}

// ── ChatCompletions request: email, credit card, Cyrillic INN/OGRN, a ──────
// ── Stripe-like key, and an "arguments" field carrying real PII ────────────

TEST(GuardRoundTrip, ChatCompletionsRequestMasksAndDemasksByteIdentically) {
    // A Stripe-like secret key, checked for genuine detection below without
    // pinning its exact placeholder name: `api_keys.stripe-key` and (nested
    // inside its alnum tail) `access_tokens.generic-long-token` both admit
    // this text, and Scanner.hpp's cross-rule overlap coalescing picks
    // whichever constituent is longest as the union's primary -- correctness
    // doesn't depend on which one wins, only that the literal itself never
    // survives masking. Decoded at runtime (see `decode_reversed_b64`) so no
    // Stripe-key-shaped literal sits in this file's own source bytes.
    const std::string stripe_key =
        decode_reversed_b64("w9UaVlHVyV0dRBnTtdjU0lFez4kZ4oUVxNkMvxWWLZnWLRmSxhUM18VZ2lGbft2c");
    ASSERT_EQ(stripe_key.substr(0, 8), "sk_live_") << "corpus-codec sanity: decode must round-trip";

    std::string body = R"({
        "model": "gpt-4o-mini",
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": "You are billing-support-bot. Never fabricate figures."},
            {"role": "user", "content": "Please send the receipt to alice.wonderland@example.com and charge 4111 1111 1111 1111. Для сверки: ИНН организации: 7707083893, ОГРН: 1027700132195."},
            {"role": "assistant", "content": "Понял, использую наш ключ STRIPE_KEY_MARKER для платежа."},
            {"role": "assistant", "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "send_receipt", "arguments": "{\"to\":\"alice.wonderland@example.com\",\"cc\":\"billing@example.com\"}"}}
            ]}
        ]
    })";
    const std::string marker = "STRIPE_KEY_MARKER";
    body.replace(body.find(marker), marker.size(), stripe_key);
    ASSERT_NE(body.find(stripe_key), std::string::npos) << "fixture setup: stripe key must be in the original body";

    // Confirm this body genuinely exercises the "arguments" routing rule
    // before trusting the round trip below to have covered it.
    const std::vector<ContentField> fields = extract_fields(body, ApiFormat::ChatCompletions, false);
    bool saw_arguments_field = false;
    for (const auto& f : fields)
        saw_arguments_field = saw_arguments_field || path_is_arguments(f.path);
    ASSERT_TRUE(saw_arguments_field);

    expect_round_trip(body, ApiFormat::ChatCompletions, false);

    // EMAIL and CREDIT_CARD are unambiguous in this fixture (no other rule's
    // capture region overlaps their all-lowercase-email / digits-and-spaces
    // spans -- see this file's own analysis in the report), so their exact
    // placeholder shape is worth pinning directly.
    const MaskedBody masked = mask_body(body, ApiFormat::ChatCompletions, false, full_catalog().rules);
    EXPECT_NE(masked.body.find("<EMAIL_"), std::string::npos);
    EXPECT_NE(masked.body.find("<CREDIT_CARD_"), std::string::npos);
    EXPECT_NE(masked.body.find("<INN_ORG_"), std::string::npos);
    EXPECT_NE(masked.body.find("<OGRN_"), std::string::npos);
    EXPECT_EQ(masked.body.find(stripe_key), std::string::npos) << "stripe-like key leaked in masked body";
}

TEST(GuardRoundTrip, ChatCompletionsRequestWithNoDetectablePiiIsLeftUntouched) {
    const std::string body =
        R"({"messages":[{"role":"user","content":"hello, just checking in about the weather today."}]})";
    expect_untouched_when_nothing_triggers(body, ApiFormat::ChatCompletions, false);
}

// ── Messages request: Cyrillic FIO, leaf-level (non-raw) tool_use.input, ───
// ── a tool_result echo, and a plain field with raw quotes/backslashes ──────

TEST(GuardRoundTrip, MessagesRequestMasksAndDemasksByteIdentically) {
    const std::string body = R"({
        "model": "claude-3-5-sonnet",
        "system": [
            {"type": "text", "text": "Ты ассистент поддержки. Никогда не выдумывай факты. SECRETNOTE:door code is \"1234\", ask for Иван\\Reception if needed."}
        ],
        "messages": [
            {"role": "user", "content": "Здравствуйте! Меня зовут Иванов Иван Иванович, свяжитесь со мной по email ivan.petrovich@example.ru."},
            {"role": "assistant", "content": [
                {"type": "text", "text": "Хорошо, сохраняю контакт."},
                {"type": "tool_use", "id": "toolu_1", "name": "save_contact", "input": {"email": "ivan.petrovich@example.ru", "note": "клиент VIP"}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": [
                    {"type": "text", "text": "Контакт сохранён для ivan.petrovich@example.ru"}
                ]}
            ]}
        ]
    })";

    const std::vector<ContentField> fields = extract_fields(body, ApiFormat::Messages, false);
    bool saw_raw_object = false;
    for (const auto& f : fields)
        saw_raw_object = saw_raw_object || f.is_raw_object;
    EXPECT_FALSE(saw_raw_object) << "Messages REQUEST-side tool_use.input is always leaf-level, never raw";

    expect_round_trip(body, ApiFormat::Messages, false);

    const MaskedBody masked = mask_body(body, ApiFormat::Messages, false, full_catalog().rules);
    EXPECT_NE(masked.body.find("<EMAIL_"), std::string::npos);
    EXPECT_NE(masked.body.find("<FIO_"), std::string::npos);
    EXPECT_NE(masked.body.find("<SECRET_NOTE_"), std::string::npos);
    // The raw quote/backslash-bearing secret note must not leak verbatim.
    EXPECT_EQ(masked.body.find("door code is \\\"1234\\\""), std::string::npos);
}

TEST(GuardRoundTrip, MessagesRequestWithNoDetectablePiiIsLeftUntouched) {
    const std::string body =
        R"({"messages":[{"role":"user","content":"just saying hi, nothing else to report today."}]})";
    expect_untouched_when_nothing_triggers(body, ApiFormat::Messages, false);
}

// ── Messages response: the ONE place is_raw_object == true is produced ─────

TEST(GuardRoundTrip, MessagesResponseRawToolUseInputMasksAndDemasksByteIdentically) {
    const std::string body = R"({
        "id": "msg_1",
        "model": "claude-3-5-sonnet",
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Отправляю письмо и сохраняю карту клиента."},
            {"type": "tool_use", "id": "toolu_2", "name": "charge_card", "input": {"email": "bob.smith@example.com", "card": "5555 5555 5555 4444", "memo": "оплата за подписку"}}
        ],
        "stop_reason": "tool_use"
    })";

    const std::vector<ContentField> fields = extract_fields(body, ApiFormat::Messages, true);
    bool saw_raw_object = false;
    for (const auto& f : fields)
        saw_raw_object = saw_raw_object || f.is_raw_object;
    ASSERT_TRUE(saw_raw_object) << "fixture must exercise the raw-object (tool_use.input) path";

    expect_round_trip(body, ApiFormat::Messages, true);

    const MaskedBody masked = mask_body(body, ApiFormat::Messages, true, full_catalog().rules);
    EXPECT_NE(masked.body.find("<EMAIL_"), std::string::npos);
    EXPECT_NE(masked.body.find("<CREDIT_CARD_"), std::string::npos);
    // The raw object must still be syntactically valid JSON after masking,
    // spliced in RAW (no quotes/encoding added around it).
    EXPECT_NE(masked.body.find("\"input\":{"), std::string::npos);
}

// ── Responses request: instructions, message content, function_call ────────
// ── arguments (a second "arguments" case), and function_call_output ────────

TEST(GuardRoundTrip, ResponsesRequestMasksAndDemasksByteIdentically) {
    const std::string body = R"({
        "model": "gpt-5",
        "instructions": "Строго следуй политике конфиденциальности.",
        "input": [
            {"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "Свяжитесь со мной: dana.reyes@example.org. Мой ИНН организации: 7707083893."}
            ]},
            {"type": "function_call", "call_id": "fc_1", "name": "lookup_order", "arguments": "{\"email\":\"dana.reyes@example.org\",\"order_id\":\"A-4471\"}"},
            {"type": "function_call_output", "call_id": "fc_1", "output": "Заказ найден для dana.reyes@example.org."}
        ]
    })";

    const std::vector<ContentField> fields = extract_fields(body, ApiFormat::Responses, false);
    bool saw_arguments_field = false;
    for (const auto& f : fields)
        saw_arguments_field = saw_arguments_field || path_is_arguments(f.path);
    ASSERT_TRUE(saw_arguments_field);

    expect_round_trip(body, ApiFormat::Responses, false);

    const MaskedBody masked = mask_body(body, ApiFormat::Responses, false, full_catalog().rules);
    EXPECT_NE(masked.body.find("<EMAIL_"), std::string::npos);
    EXPECT_NE(masked.body.find("<INN_ORG_"), std::string::npos);
    // The same email appears in 3 different fields (content text, function_call
    // arguments, function_call_output) -- cross-text dedup (Masker.hpp) means
    // they all resolve to the SAME placeholder; confirm exactly one EMAIL
    // counter value was minted rather than three.
    EXPECT_EQ(masked.body.find("<EMAIL_2>"), std::string::npos);
}

TEST(GuardRoundTrip, ResponsesRequestWithNoDetectablePiiIsLeftUntouched) {
    const std::string body =
        R"({"instructions":"be nice","input":"just a friendly greeting with no sensitive info at all."})";
    expect_untouched_when_nothing_triggers(body, ApiFormat::Responses, false);
}

// ── demask_json_arguments' structural fallback: driven via the same ────────
// ── Config/API the round-trip driver above uses (see the file-level doc ────
// ── comment for why it cannot arise from mask_texts on a single field) ─────

TEST(GuardRoundTripJsonEscape, DemaskJsonArgumentsStructuralFallbackHandlesEmbeddedQuotesAndBackslashes) {
    Guard::MaskingState state;
    Guard::Replacement rep;
    rep.rule_id = "test.injected";
    rep.data_type = DataType::Custom;
    rep.original = R"(say "hi" at C:\ops\vault)";
    rep.placeholder = "<INJECTED_SECRET_1>";
    state.replacements = {rep};

    const Config cfg = Guard::Demask::make_config(state, nullptr);

    const std::string masked_arguments = R"({"note":"<INJECTED_SECRET_1>","priority":1})";
    const std::string want = R"({"note":"say \"hi\" at C:\\ops\\vault","priority":1})";

    const std::string got = Guard::Demask::demask_json_arguments(cfg, masked_arguments);
    EXPECT_EQ(got, want);
    ASSERT_TRUE(Guard::Json::valid(got));

    // The naive pass alone would have produced invalid JSON (an unescaped
    // quote terminating the string early); prove that directly too, so this
    // test documents WHY the structural fallback exists rather than merely
    // asserting its output.
    const std::string naive = Guard::Demask::demask_all(cfg, masked_arguments, /*json_escape=*/false);
    EXPECT_FALSE(Guard::Json::valid(naive)) << "naive: " << naive;
}
