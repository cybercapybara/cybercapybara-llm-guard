/**
 * @file test_guard_validators_formats.cpp
 * @brief Unit tests for Guard's format/entropy/IP validators, banlist, and
 *        the remaining (non-checksum) slice of `passes_validators`.
 *
 * Ports every remaining vector from the Go reference's
 * `pkg/guardrails/regex/validation/validation_test.go`: `TestEmailASCIIValid`,
 * `TestPaymentCardValid`, `TestPaymentCardShape`, `TestShannonEntropy`,
 * `TestEntropySanityForNonPowerDistribution`, `TestIPValidationHelpersViaValidate`,
 * the format/entropy/banlist/IP rows of `TestValidate` and
 * `TestValidate_RejectsInvalidCandidatesForEachValidator`, and the remaining
 * `TestInternalHelpers` cases (allDigits/prefixInRange/isASCIILocalPartChar/
 * isASCIIDomainChar/isAlpha/banlisted/parseIPCandidate on whitespace-only
 * input). Checksum-only vectors live in test_guard_validators_checksums.cpp.
 */

#include <cmath>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "guard/Rule.hpp"
#include "guard/Validators.hpp"

namespace {

Guard::Rule rule_with_validators(std::vector<std::string> validators) {
    Guard::Rule r;
    r.validators = std::move(validators);
    return r;
}

// Mirrors the Go test helper validPAN(prefix, length): a Luhn-valid PAN of
// the given length starting with prefix.
std::string valid_pan(const std::string& prefix, std::size_t length) {
    if (length <= prefix.size())
        return prefix;
    std::string body = prefix + std::string(length - prefix.size() - 1, '0');
    body.push_back(Guard::detail::luhn_check_digit(body));
    return body;
}

}  // namespace

// ── TestEmailASCIIValid ───────────────────────────────────────────────────

TEST(GuardValidatorsFormats, EmailAsciiValid) {
    EXPECT_TRUE(Guard::email_ascii_valid("a.!#$%&'*+-/=?^_`{|}~@example.com"));
    EXPECT_TRUE(Guard::email_ascii_valid(" person@example.com "));
    EXPECT_FALSE(Guard::email_ascii_valid(""));
    EXPECT_FALSE(Guard::email_ascii_valid("person.example.com"));
    EXPECT_FALSE(Guard::email_ascii_valid("@example.com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@"));
    EXPECT_FALSE(Guard::email_ascii_valid("person..name@example.com"));
    EXPECT_FALSE(Guard::email_ascii_valid(".person@example.com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person.@example.com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person,name@example.com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@example"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@example..com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@-example.com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@example-.com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@example.123"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@exa_mple.com"));
    EXPECT_FALSE(Guard::email_ascii_valid(std::string(65, 'a') + "@example.com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@" + std::string(250, 'a') + ".com"));
    EXPECT_FALSE(Guard::email_ascii_valid("person@" + std::string(64, 'a') + ".com"));
    EXPECT_FALSE(Guard::email_ascii_valid(std::string(64, 'a') + "@" + std::string(185, 'b') + ".com"));
    // Brief anchors.
    EXPECT_TRUE(Guard::email_ascii_valid("a@b.co"));
    EXPECT_FALSE(Guard::email_ascii_valid("a..b@c.co"));
    EXPECT_FALSE(Guard::email_ascii_valid("a@b"));
}

// ── TestPaymentCardValid ──────────────────────────────────────────────────

TEST(GuardValidatorsFormats, PaymentCardValid) {
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("4", 13)));
    EXPECT_TRUE(Guard::payment_card_valid("4111111111111111"));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("4", 19)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("34", 15)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("37", 15)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("51", 16)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("2221", 16)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("2720", 16)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("6011", 16)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("644", 16)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("65", 19)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("62", 16)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("2200", 16)));
    EXPECT_TRUE(Guard::payment_card_valid(valid_pan("2204", 19)));

    EXPECT_FALSE(Guard::payment_card_valid(""));
    EXPECT_FALSE(Guard::payment_card_valid("411111111111111x"));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("4", 12)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("4", 20)));
    EXPECT_FALSE(Guard::payment_card_valid("4111111111111112"));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("99", 16)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("4", 15)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("34", 16)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("50", 16)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("56", 16)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("2220", 16)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("2721", 16)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("643", 16)));
    EXPECT_FALSE(Guard::payment_card_valid(valid_pan("2205", 16)));
}

// ── TestPaymentCardShape ──────────────────────────────────────────────────

TEST(GuardValidatorsFormats, PaymentCardShape) {
    EXPECT_TRUE(Guard::payment_card_shape("4279381155667788"));
    EXPECT_TRUE(Guard::payment_card_shape("2200345678901234"));
    EXPECT_TRUE(Guard::payment_card_shape("5123456789012349"));
    EXPECT_TRUE(Guard::payment_card_shape("341234567890123"));
    EXPECT_TRUE(Guard::payment_card_shape("4111111111111111"));
    EXPECT_FALSE(Guard::payment_card_shape("5123456789012"));
    EXPECT_FALSE(Guard::payment_card_shape("417500000000000"));
    EXPECT_FALSE(Guard::payment_card_shape("9912345678901234"));
    EXPECT_FALSE(Guard::payment_card_shape("411111111111"));
    EXPECT_FALSE(Guard::payment_card_shape("411111111111111x"));
}

// ── TestShannonEntropy / TestEntropySanityForNonPowerDistribution ────────

TEST(GuardValidatorsFormats, ShannonEntropy) {
    EXPECT_DOUBLE_EQ(Guard::shannon_entropy(""), 0.0);
    EXPECT_DOUBLE_EQ(Guard::shannon_entropy("aaaa"), 0.0);
    EXPECT_DOUBLE_EQ(Guard::shannon_entropy("abcd"), 2.0);
    EXPECT_NEAR(Guard::shannon_entropy("\xd0\xb0\xd0\xb1\xd0\xb2\xd0\xb3"), 2.0, 1e-6);  // "абвг"
    EXPECT_NEAR(Guard::shannon_entropy("\xd1\x8f\xd1\x8f\xd1\x8f\xd1\x8f"), 0.0, 1e-6);  // "яяяя"
}

TEST(GuardValidatorsFormats, ShannonEntropyNonPowerDistribution) {
    const double want = -(0.75 * std::log2(0.75)) - (0.25 * std::log2(0.25));
    EXPECT_NEAR(Guard::shannon_entropy("aaab"), want, 1e-6);
}

// ── TestIPValidationHelpersViaValidate ────────────────────────────────────

TEST(GuardValidatorsFormats, IpV4) {
    EXPECT_FALSE(Guard::passes_validators("not-ip", rule_with_validators({"ip_v4"})));
    EXPECT_TRUE(Guard::passes_validators("8.8.8.0/24", rule_with_validators({"ip_v4"})));
    EXPECT_FALSE(Guard::passes_validators("8.8.8.8", rule_with_validators({"ip_v6"})));
}

TEST(GuardValidatorsFormats, IpPublicAndPrivate) {
    EXPECT_TRUE(Guard::passes_validators("2001:4860:4860::8888", rule_with_validators({"ip_public"})));
    EXPECT_FALSE(Guard::passes_validators("127.0.0.1", rule_with_validators({"ip_public"})));
    EXPECT_TRUE(Guard::passes_validators("224.0.0.1", rule_with_validators({"ip_private"})));
    EXPECT_TRUE(Guard::passes_validators("0.0.0.0", rule_with_validators({"ip_private"})));
    EXPECT_FALSE(Guard::passes_validators("8.8.8.8", rule_with_validators({"ip_private"})));
}

TEST(GuardValidatorsFormats, IpPrimitivesDirect) {
    EXPECT_TRUE(Guard::ip_v4("8.8.8.8"));
    EXPECT_FALSE(Guard::ip_v4("2001:4860:4860::8888"));
    EXPECT_TRUE(Guard::ip_v6("[2001:4860:4860::8888]"));
    EXPECT_FALSE(Guard::ip_v6("8.8.8.8"));
    EXPECT_TRUE(Guard::ip_public("8.8.8.8"));
    EXPECT_FALSE(Guard::ip_public("10.1.2.3"));
    EXPECT_TRUE(Guard::ip_private("10.1.2.0/24"));
    EXPECT_FALSE(Guard::ip_private("8.8.8.8"));
}

// ── TestValidate (format/entropy/banlist/ip rows) ─────────────────────────

TEST(GuardValidatorsFormats, PassesValidatorsEmailAcceptsValidAsciiAddress) {
    EXPECT_TRUE(Guard::passes_validators("person.name+tag@example.com", rule_with_validators({"email_ascii"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsPaymentCardAcceptsValidVisa) {
    EXPECT_TRUE(Guard::passes_validators("4111 1111 1111 1111", rule_with_validators({"payment_card"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsEntropyRejectsLowEntropyCandidate) {
    auto rule = rule_with_validators({"entropy"});
    rule.entropy = 3;
    EXPECT_FALSE(Guard::passes_validators("aaaaaaaaaaaaaaaa", rule));
}

TEST(GuardValidatorsFormats, PassesValidatorsEntropyThresholdIsIgnoredWhenUnset) {
    // rule.entropy defaults to 0.0: the "entropy" validator is present but
    // inert until rule.entropy > 0 (see Validators.hpp file doc comment).
    EXPECT_TRUE(Guard::passes_validators("aaaaaaaaaaaaaaaa", rule_with_validators({"entropy"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsBanlistRejectsCaseInsensitiveExactMatch) {
    auto rule = rule_with_validators({"banlist"});
    rule.banlist = {"password"};
    EXPECT_FALSE(Guard::passes_validators("Password", rule));
}

TEST(GuardValidatorsFormats, PassesValidatorsIpv4AcceptsIpv4Address) {
    EXPECT_TRUE(Guard::passes_validators("8.8.8.8", rule_with_validators({"ip_v4"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsIpv6AcceptsBracketedIpv6Address) {
    EXPECT_TRUE(Guard::passes_validators("[2001:4860:4860::8888]", rule_with_validators({"ip_v6"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsPublicIpRejectsPrivateAddress) {
    EXPECT_FALSE(Guard::passes_validators("10.1.2.3", rule_with_validators({"ip_public"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsPrivateIpAcceptsCidrPrivateAddress) {
    EXPECT_TRUE(Guard::passes_validators("10.1.2.0/24", rule_with_validators({"ip_private"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsMultipleValidatorsShortCircuitOnFailure) {
    auto rule = rule_with_validators({"email_ascii", "banlist"});
    rule.banlist = {"person@example"};
    EXPECT_FALSE(Guard::passes_validators("person@example", rule));
}

// ── TestValidate_RejectsInvalidCandidatesForEachValidator (remaining rows) ─

TEST(GuardValidatorsFormats, PassesValidatorsEmailRejectsInvalidShape) {
    EXPECT_FALSE(Guard::passes_validators("person@example", rule_with_validators({"email_ascii"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsPaymentCardRejectsBadLuhn) {
    EXPECT_FALSE(Guard::passes_validators("4111111111111112", rule_with_validators({"payment_card"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsIpv4RejectsIpv6Value) {
    EXPECT_FALSE(Guard::passes_validators("2001:4860:4860::8888", rule_with_validators({"ip_v4"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsIpv6RejectsIpv4Value) {
    EXPECT_FALSE(Guard::passes_validators("8.8.8.8", rule_with_validators({"ip_v6"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsPublicIpParseFailure) {
    EXPECT_FALSE(Guard::passes_validators("not-ip", rule_with_validators({"ip_public"})));
}

TEST(GuardValidatorsFormats, PassesValidatorsPrivateIpParseFailure) {
    EXPECT_FALSE(Guard::passes_validators("not-ip", rule_with_validators({"ip_private"})));
}

// ── TestInternalHelpers (remaining cases) ─────────────────────────────────

TEST(GuardValidatorsFormats, Banlisted) {
    EXPECT_TRUE(Guard::detail::banlisted("Password", {"password"}));
    EXPECT_FALSE(Guard::detail::banlisted("password1", {"password"}));
}

TEST(GuardValidatorsFormats, AllDigits) {
    EXPECT_TRUE(Guard::detail::all_digits("123"));
    EXPECT_FALSE(Guard::detail::all_digits(""));
    EXPECT_FALSE(Guard::detail::all_digits("12x"));
}

TEST(GuardValidatorsFormats, PrefixInRange) {
    EXPECT_TRUE(Guard::detail::prefix_in_range("2221", 4, 2221, 2720));
    EXPECT_FALSE(Guard::detail::prefix_in_range("22", 4, 2221, 2720));
    EXPECT_FALSE(Guard::detail::prefix_in_range("22x1", 4, 2221, 2720));
    EXPECT_FALSE(Guard::detail::prefix_in_range("2721", 4, 2221, 2720));
}

TEST(GuardValidatorsFormats, AsciiLocalPartChar) {
    EXPECT_TRUE(Guard::detail::is_ascii_local_part_char('~'));
    EXPECT_TRUE(Guard::detail::is_ascii_local_part_char('a'));
    EXPECT_TRUE(Guard::detail::is_ascii_local_part_char('A'));
    EXPECT_TRUE(Guard::detail::is_ascii_local_part_char('1'));
    EXPECT_FALSE(Guard::detail::is_ascii_local_part_char(','));
}

TEST(GuardValidatorsFormats, AsciiDomainChar) {
    EXPECT_TRUE(Guard::detail::is_ascii_domain_char('-'));
    EXPECT_FALSE(Guard::detail::is_ascii_domain_char('_'));
}

TEST(GuardValidatorsFormats, IsAlpha) {
    EXPECT_TRUE(Guard::detail::is_alpha("COM"));
    EXPECT_FALSE(Guard::detail::is_alpha("c0m"));
    EXPECT_FALSE(Guard::detail::is_alpha(""));
}

TEST(GuardValidatorsFormats, ParseIpCandidateWhitespaceOnlyFails) {
    EXPECT_FALSE(Guard::detail::parse_ip_candidate("   ").has_value());
}

// ── is_known_validator (payment_card_no_luhn coverage) ────────────────────

TEST(GuardValidatorsFormats, PassesValidatorsPaymentCardNoLuhnAcceptsBadChecksum) {
    // Same PAN as TestPaymentCardShape's "visa 16 bad luhn": brand/length
    // shape is right, Luhn checksum is wrong -- payment_card_no_luhn still
    // accepts it (that's the point of the no-Luhn fallback validator).
    EXPECT_TRUE(Guard::passes_validators("4279381155667788", rule_with_validators({"payment_card_no_luhn"})));
    EXPECT_FALSE(Guard::passes_validators("4279381155667788", rule_with_validators({"payment_card"})));
}
