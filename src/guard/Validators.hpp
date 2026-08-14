/**
 * @file Validators.hpp
 * @brief The 16 named `rule.validators` checks plus the `entropy`/`banlist`
 *        rule parameters, and the dispatch that ANDs them together.
 * @details Ports `pkg/guardrails/regex/validation/checksums.go` from the Go
 *          reference field-for-field. This first slice lands the seven
 *          checksum primitives (luhn/snils/inn_person/inn_org/ogrn/ogrnip/
 *          iban_mod97) plus `is_known_validator` (all 16 names -- it is a
 *          pure name lookup, so it doesn't need the format/entropy/banlist/
 *          IP validators to exist yet) and the `passes_validators` dispatch
 *          skeleton. The format validators, entropy, banlist, and IP checks
 *          land in a follow-up commit on this branch; until then their
 *          dispatch entries fall through to `passes_validators`' unknown-name
 *          branch (`return false`), which is also the documented behavior
 *          for a genuinely unrecognized validator name.
 *
 *          `passes_validators` mirrors `Validate(candidate, rule)`: it
 *          strips `value` to digits ONCE (mirroring Go's `stripNonDigits`,
 *          computed once up front) and shares that string across every
 *          digit-based validator (luhn/snils/inn_person/inn_org/ogrn/
 *          ogrnip); IBAN gets the raw (untouched) value, matching
 *          `IBANMod97Valid` in the Go reference, which never sees the
 *          stripped form.
 */

#pragma once

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "guard/Rule.hpp"

namespace Guard {

namespace detail {

// Byte-wise ASCII-digit scan is equivalent to Go's rune-wise
// `for _, c := range s { if c >= '0' && c <= '9' ... }`: valid UTF-8 never
// encodes a continuation/lead byte in the 0x30-0x39 range, so a multi-byte
// sequence can never masquerade as an ASCII digit either way.
inline std::string strip_non_digits(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        if (c >= '0' && c <= '9')
            out.push_back(c);
    return out;
}

// digits must be ASCII '0'-'9' only; caller (luhn_valid) enforces that.
inline int luhn_sum(std::string_view digits) {
    int sum = 0;
    const std::size_t n = digits.size();
    const std::size_t parity = n % 2;
    for (std::size_t i = 0; i < n; ++i) {
        int d = digits[i] - '0';
        if (i % 2 == parity) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        sum += d;
    }
    return sum;
}

inline char luhn_check_digit(std::string_view prefix) {
    int sum = 0;
    const std::size_t n = prefix.size();
    const std::size_t parity = (n + 1) % 2;
    for (std::size_t i = 0; i < n; ++i) {
        int d = prefix[i] - '0';
        if (i % 2 == parity) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        sum += d;
    }
    const int check = (10 - (sum % 10)) % 10;
    return static_cast<char>('0' + check);
}

inline std::string snils_checksum(std::string_view nine_digits) {
    if (nine_digits.size() != 9)
        return "00";
    int sum = 0;
    for (std::size_t i = 0; i < 9; ++i)
        sum += (nine_digits[i] - '0') * static_cast<int>(9 - i);
    int checksum = sum % 101;
    if (checksum > 99)
        checksum = 0;
    std::string out(2, '0');
    out[0] = static_cast<char>('0' + checksum / 10);
    out[1] = static_cast<char>('0' + checksum % 10);
    return out;
}

inline std::pair<char, char> inn_person_checksums(std::string_view ten_digits) {
    auto d = [&](std::size_t i) { return ten_digits[i] - '0'; };
    const int v1 = ((7 * d(0) + 2 * d(1) + 4 * d(2) + 10 * d(3) + 3 * d(4) + 5 * d(5) + 9 * d(6) + 4 * d(7) +
                     6 * d(8) + 8 * d(9)) %
                    11) %
                   10;
    std::array<int, 11> digits{};
    for (std::size_t i = 0; i < 10; ++i)
        digits[i] = d(i);
    digits[10] = v1;
    static constexpr std::array<int, 11> kWeights{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8};
    int sum = 0;
    for (std::size_t i = 0; i < 11; ++i)
        sum += digits[i] * kWeights[i];
    const int v2 = (sum % 11) % 10;
    return {static_cast<char>('0' + v1), static_cast<char>('0' + v2)};
}

inline char inn_org_checksum(std::string_view nine_digits) {
    auto d = [&](std::size_t i) { return nine_digits[i] - '0'; };
    const int checksum =
        ((2 * d(0) + 4 * d(1) + 10 * d(2) + 3 * d(3) + 5 * d(4) + 9 * d(5) + 4 * d(6) + 6 * d(7) + 8 * d(8)) % 11) %
        10;
    return static_cast<char>('0' + checksum);
}

// Mirrors Go's `var n int64` explicitly (a 12-digit prefix, ~1e12, overflows
// a 32-bit int well before it overflows int64).
inline char ogrn_check_digit(std::string_view twelve_digits) {
    std::int64_t n = 0;
    for (char c : twelve_digits)
        n = n * 10 + (c - '0');
    return static_cast<char>('0' + (n % 11) % 10);
}

inline char ogrnip_check_digit(std::string_view fourteen_digits) {
    int remainder = 0;
    for (char c : fourteen_digits)
        remainder = (remainder * 10 + (c - '0')) % 13;
    return static_cast<char>('0' + remainder % 10);
}

// s must contain only ASCII digits.
inline int mod97_decimal_string(std::string_view s) {
    int remainder = 0;
    for (char c : s)
        remainder = (remainder * 10 + (c - '0')) % 97;
    return remainder;
}

inline std::string iban_mod97(std::string_view country_code, std::string_view bban) {
    std::string rearranged;
    rearranged.reserve(bban.size() + country_code.size() + 2);
    rearranged += bban;
    rearranged += country_code;
    rearranged += "00";
    for (char& c : rearranged)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    std::string num_str;
    num_str.reserve(rearranged.size() * 2);
    for (char c : rearranged) {
        if (c >= 'A' && c <= 'Z')
            num_str += std::to_string(c - 'A' + 10);
        else
            num_str.push_back(c);
    }

    const int check = 98 - mod97_decimal_string(num_str);
    std::string out(2, '0');
    out[0] = static_cast<char>('0' + check / 10);
    out[1] = static_cast<char>('0' + check % 10);
    return out;
}

}  // namespace detail

inline bool luhn_valid(std::string_view digits) {
    if (digits.empty())
        return false;
    for (char c : digits)
        if (c < '0' || c > '9')
            return false;
    return detail::luhn_sum(digits) % 10 == 0;
}

inline bool snils_valid(std::string_view digits) {
    if (digits.size() != 11)
        return false;
    for (char c : digits)
        if (c < '0' || c > '9')
            return false;
    const std::string checksum = detail::snils_checksum(digits.substr(0, 9));
    return digits[9] == checksum[0] && digits[10] == checksum[1];
}

inline bool inn_person_valid(std::string_view digits) {
    if (digits.size() != 12)
        return false;
    for (char c : digits)
        if (c < '0' || c > '9')
            return false;
    const auto [c1, c2] = detail::inn_person_checksums(digits.substr(0, 10));
    return digits[10] == c1 && digits[11] == c2;
}

inline bool inn_org_valid(std::string_view digits) {
    if (digits.size() != 10)
        return false;
    for (char c : digits)
        if (c < '0' || c > '9')
            return false;
    return digits[9] == detail::inn_org_checksum(digits.substr(0, 9));
}

inline bool ogrn_valid(std::string_view digits) {
    if (digits.size() != 13)
        return false;
    for (char c : digits)
        if (c < '0' || c > '9')
            return false;
    return digits[12] == detail::ogrn_check_digit(digits.substr(0, 12));
}

inline bool ogrnip_valid(std::string_view digits) {
    if (digits.size() != 15)
        return false;
    for (char c : digits)
        if (c < '0' || c > '9')
            return false;
    return digits[14] == detail::ogrnip_check_digit(digits.substr(0, 14));
}

// The IBAN alphabet is ASCII-only by spec (A-Z0-9), so an ASCII-only
// uppercase (rather than Go's Unicode-aware strings.ToUpper) is a deliberate
// simplification: it is exact for every conforming IBAN and only diverges
// from the Go reference on inputs already outside the IBAN charset, where
// both implementations already produce meaningless (but equally
// well-defined, non-crashing) output.
inline bool iban_valid(std::string_view iban_in) {
    std::string iban;
    iban.reserve(iban_in.size());
    for (char c : iban_in) {
        if (c == ' ')
            continue;
        iban.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if (iban.size() < 4)
        return false;

    const std::string rearranged = iban.substr(4) + iban.substr(0, 4);
    std::string num_str;
    num_str.reserve(rearranged.size() * 2);
    for (char c : rearranged) {
        if (c >= 'A' && c <= 'Z')
            num_str += std::to_string(c - 'A' + 10);
        else
            num_str.push_back(c);
    }

    return detail::mod97_decimal_string(num_str) == 1;
}

// ── Dispatch ─────────────────────────────────────────────────────────────

inline bool is_known_validator(std::string_view name) {
    static const std::unordered_set<std::string_view> kKnown = {
        "luhn",         "snils",       "inn_person", "inn_org",  "ogrn",       "ogrnip",
        "iban_mod97",   "email_ascii", "payment_card", "payment_card_no_luhn",
        "entropy",      "banlist",     "ip_v4",      "ip_v6",    "ip_public",  "ip_private",
    };
    return kKnown.count(name) != 0;
}

// AND over rule.validators, mirroring validate.go's Validate. Only the
// checksum branches are wired so far; the rest (added in a follow-up commit
// on this branch) fall through to the unknown-name branch, which is also
// the documented behavior for a genuinely unrecognized name.
inline bool passes_validators(std::string_view value, const Rule& rule) {
    const std::string digits = detail::strip_non_digits(value);

    for (const auto& validator : rule.validators) {
        if (validator == "luhn") {
            if (!luhn_valid(digits))
                return false;
        } else if (validator == "snils") {
            if (!snils_valid(digits))
                return false;
        } else if (validator == "inn_person") {
            if (!inn_person_valid(digits))
                return false;
        } else if (validator == "inn_org") {
            if (!inn_org_valid(digits))
                return false;
        } else if (validator == "ogrn") {
            if (!ogrn_valid(digits))
                return false;
        } else if (validator == "ogrnip") {
            if (!ogrnip_valid(digits))
                return false;
        } else if (validator == "iban_mod97") {
            if (!iban_valid(value))
                return false;
        } else {
            return false;
        }
    }

    return true;
}

}  // namespace Guard
