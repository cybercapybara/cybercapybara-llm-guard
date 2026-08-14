/**
 * @file test_guard_validators_checksums.cpp
 * @brief Unit tests for Guard's checksum validators, `is_known_validator`,
 *        and the checksum-validator slice of `passes_validators`.
 *
 * Ports every vector from the Go reference's
 * `pkg/guardrails/regex/validation/validation_test.go` that exercises
 * checksum-related code: `TestChecksumValidators` (luhn/snils/inn_person/
 * inn_org/ogrn/ogrnip/iban), the checksum-validator rows of `TestValidate`
 * and `TestValidate_RejectsInvalidCandidatesForEachValidator`, `TestIsKnown`
 * (all 16 names -- `is_known_validator` is a pure name lookup and doesn't
 * need the format/entropy/banlist/IP validators to exist yet), and the
 * `stripNonDigits`/`mod97DecimalString` cases from `TestInternalHelpers`.
 */

#include <string>

#include <gtest/gtest.h>

#include "guard/Rule.hpp"
#include "guard/Validators.hpp"

// ── Spot-check anchors (brief) ──────────────────────────────────────────

TEST(GuardValidatorsChecksums, SpotCheckAnchors) {
    EXPECT_TRUE(Guard::luhn_valid("4111111111111111"));
    EXPECT_FALSE(Guard::luhn_valid("4111111111111112"));
    EXPECT_TRUE(Guard::snils_valid("11223344595"));
    EXPECT_TRUE(Guard::inn_person_valid("500100732259"));
    EXPECT_TRUE(Guard::inn_org_valid("7707083893"));
    EXPECT_TRUE(Guard::ogrn_valid("1027700132195"));
    EXPECT_TRUE(Guard::iban_valid("GB82WEST12345698765432"));
    EXPECT_FALSE(Guard::iban_valid("GB82WEST12345698765431"));
}

// ── TestChecksumValidators/luhn ──────────────────────────────────────────

TEST(GuardValidatorsChecksums, LuhnSum) {
    EXPECT_EQ(Guard::detail::luhn_sum("79927398713"), 70);
}

TEST(GuardValidatorsChecksums, LuhnValid) {
    EXPECT_TRUE(Guard::luhn_valid("79927398713"));
    EXPECT_FALSE(Guard::luhn_valid(""));
    EXPECT_FALSE(Guard::luhn_valid("7992739871x"));
    EXPECT_FALSE(Guard::luhn_valid("79927398714"));
}

TEST(GuardValidatorsChecksums, LuhnCheckDigit) {
    EXPECT_EQ(Guard::detail::luhn_check_digit("7992739871"), '3');
}

// ── TestChecksumValidators/snils ─────────────────────────────────────────

TEST(GuardValidatorsChecksums, SnilsChecksum) {
    EXPECT_EQ(Guard::detail::snils_checksum("112233445"), "95");
    EXPECT_EQ(Guard::detail::snils_checksum("000029999"), "00");
    EXPECT_EQ(Guard::detail::snils_checksum("123"), "00");
}

TEST(GuardValidatorsChecksums, SnilsValid) {
    EXPECT_TRUE(Guard::snils_valid("11223344595"));
    EXPECT_FALSE(Guard::snils_valid("11223344596"));
    EXPECT_FALSE(Guard::snils_valid("1122334459x"));
    EXPECT_FALSE(Guard::snils_valid("112233445"));
}

// ── TestChecksumValidators/inn person ────────────────────────────────────

TEST(GuardValidatorsChecksums, InnPersonChecksums) {
    const auto [c1, c2] = Guard::detail::inn_person_checksums("5001007322");
    EXPECT_EQ(c1, '5');
    EXPECT_EQ(c2, '9');
}

TEST(GuardValidatorsChecksums, InnPersonValid) {
    EXPECT_TRUE(Guard::inn_person_valid("500100732259"));
    EXPECT_FALSE(Guard::inn_person_valid("500100732250"));
    EXPECT_FALSE(Guard::inn_person_valid("50010073225x"));
    EXPECT_FALSE(Guard::inn_person_valid("50010073225"));
}

// ── TestChecksumValidators/inn org ───────────────────────────────────────

TEST(GuardValidatorsChecksums, InnOrgChecksum) {
    EXPECT_EQ(Guard::detail::inn_org_checksum("770708389"), '3');
}

TEST(GuardValidatorsChecksums, InnOrgValid) {
    EXPECT_TRUE(Guard::inn_org_valid("7707083893"));
    EXPECT_FALSE(Guard::inn_org_valid("7707083894"));
    EXPECT_FALSE(Guard::inn_org_valid("770708389x"));
    EXPECT_FALSE(Guard::inn_org_valid("770708389"));
}

// ── TestChecksumValidators/ogrn ───────────────────────────────────────────

TEST(GuardValidatorsChecksums, OgrnCheckDigit) {
    EXPECT_EQ(Guard::detail::ogrn_check_digit("102770013219"), '5');
}

TEST(GuardValidatorsChecksums, OgrnValid) {
    EXPECT_TRUE(Guard::ogrn_valid("1027700132195"));
    EXPECT_FALSE(Guard::ogrn_valid("1027700132194"));
    EXPECT_FALSE(Guard::ogrn_valid("102770013219x"));
    EXPECT_FALSE(Guard::ogrn_valid("102770013219"));
}

// ── TestChecksumValidators/ogrnip ────────────────────────────────────────

TEST(GuardValidatorsChecksums, OgrnipCheckDigit) {
    EXPECT_EQ(Guard::detail::ogrnip_check_digit("30450011600015"), '7');
}

TEST(GuardValidatorsChecksums, OgrnipValid) {
    EXPECT_TRUE(Guard::ogrnip_valid("304500116000157"));
    EXPECT_FALSE(Guard::ogrnip_valid("304500116000158"));
    EXPECT_FALSE(Guard::ogrnip_valid("30450011600015x"));
    EXPECT_FALSE(Guard::ogrnip_valid("30450011600015"));
}

// ── TestChecksumValidators/iban ───────────────────────────────────────────

TEST(GuardValidatorsChecksums, IbanMod97) {
    EXPECT_EQ(Guard::detail::iban_mod97("GB", "WEST12345698765432"), "82");
}

TEST(GuardValidatorsChecksums, IbanValid) {
    EXPECT_TRUE(Guard::iban_valid("GB82 WEST 1234 5698 7654 32"));
    EXPECT_FALSE(Guard::iban_valid("GB83 WEST 1234 5698 7654 32"));
    EXPECT_FALSE(Guard::iban_valid("GB1"));
}

// ── TestInternalHelpers (checksum-relevant subset) ───────────────────────

TEST(GuardValidatorsChecksums, StripNonDigits) {
    EXPECT_EQ(Guard::detail::strip_non_digits("a1-2 3b"), "123");
}

TEST(GuardValidatorsChecksums, Mod97DecimalString) {
    EXPECT_EQ(Guard::detail::mod97_decimal_string("98"), 1);
}

// ── TestIsKnown (all 16 names) ────────────────────────────────────────────

TEST(GuardValidatorsChecksums, IsKnownValidator) {
    EXPECT_TRUE(Guard::is_known_validator("luhn"));
    EXPECT_TRUE(Guard::is_known_validator("snils"));
    EXPECT_TRUE(Guard::is_known_validator("inn_person"));
    EXPECT_TRUE(Guard::is_known_validator("inn_org"));
    EXPECT_TRUE(Guard::is_known_validator("ogrn"));
    EXPECT_TRUE(Guard::is_known_validator("ogrnip"));
    EXPECT_TRUE(Guard::is_known_validator("iban_mod97"));
    EXPECT_TRUE(Guard::is_known_validator("email_ascii"));
    EXPECT_TRUE(Guard::is_known_validator("payment_card"));
    EXPECT_TRUE(Guard::is_known_validator("payment_card_no_luhn"));
    EXPECT_TRUE(Guard::is_known_validator("entropy"));
    EXPECT_TRUE(Guard::is_known_validator("banlist"));
    EXPECT_TRUE(Guard::is_known_validator("ip_v4"));
    EXPECT_TRUE(Guard::is_known_validator("ip_v6"));
    EXPECT_TRUE(Guard::is_known_validator("ip_public"));
    EXPECT_TRUE(Guard::is_known_validator("ip_private"));
    EXPECT_FALSE(Guard::is_known_validator("unknown"));
    EXPECT_FALSE(Guard::is_known_validator(""));
}

// ── TestValidate / TestValidate_RejectsInvalidCandidatesForEachValidator
//    (checksum-validator rows) ─────────────────────────────────────────

namespace {

Guard::Rule rule_with_validators(std::vector<std::string> validators) {
    Guard::Rule r;
    r.validators = std::move(validators);
    return r;
}

}  // namespace

TEST(GuardValidatorsChecksums, PassesValidatorsNoValidatorsAcceptsCandidate) {
    EXPECT_TRUE(Guard::passes_validators("anything", Guard::Rule{}));
}

TEST(GuardValidatorsChecksums, PassesValidatorsLuhnStripsFormattingBeforeValidation) {
    EXPECT_TRUE(Guard::passes_validators("7992-7398-713", rule_with_validators({"luhn"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsLuhnRejectsInvalidChecksum) {
    EXPECT_FALSE(Guard::passes_validators("79927398714", rule_with_validators({"luhn"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsSnilsAcceptsValidFormattedValue) {
    EXPECT_TRUE(Guard::passes_validators("112-233-445 95", rule_with_validators({"snils"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsSnilsRejectsInvalidChecksum) {
    EXPECT_FALSE(Guard::passes_validators("11223344596", rule_with_validators({"snils"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsInnPersonAcceptsValidValue) {
    EXPECT_TRUE(Guard::passes_validators("500100732259", rule_with_validators({"inn_person"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsInnPersonRejectsInvalidChecksum) {
    EXPECT_FALSE(Guard::passes_validators("500100732250", rule_with_validators({"inn_person"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsInnOrgAcceptsValidValue) {
    EXPECT_TRUE(Guard::passes_validators("7707083893", rule_with_validators({"inn_org"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsInnOrgRejectsInvalidChecksum) {
    EXPECT_FALSE(Guard::passes_validators("7707083894", rule_with_validators({"inn_org"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsOgrnAcceptsValidValue) {
    EXPECT_TRUE(Guard::passes_validators("1027700132195", rule_with_validators({"ogrn"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsOgrnRejectsInvalidChecksum) {
    EXPECT_FALSE(Guard::passes_validators("1027700132194", rule_with_validators({"ogrn"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsOgrnipAcceptsValidValue) {
    EXPECT_TRUE(Guard::passes_validators("304500116000157", rule_with_validators({"ogrnip"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsOgrnipRejectsInvalidChecksum) {
    EXPECT_FALSE(Guard::passes_validators("304500116000158", rule_with_validators({"ogrnip"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsIbanAcceptsValidSpacedValue) {
    EXPECT_TRUE(Guard::passes_validators("GB82 WEST 1234 5698 7654 32", rule_with_validators({"iban_mod97"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsIbanRejectsInvalidChecksum) {
    EXPECT_FALSE(Guard::passes_validators("GB83 WEST 1234 5698 7654 32", rule_with_validators({"iban_mod97"})));
}

TEST(GuardValidatorsChecksums, PassesValidatorsUnknownValidatorRejectsCandidate) {
    EXPECT_FALSE(Guard::passes_validators("anything", rule_with_validators({"unknown"})));
}
