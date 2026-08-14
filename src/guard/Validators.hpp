/**
 * @file Validators.hpp
 * @brief The 16 named `rule.validators` checks plus the `entropy`/`banlist`
 *        rule parameters, and the dispatch that ANDs them together.
 * @details Ports `pkg/guardrails/regex/validation/{checksums,formats,entropy,
 *          validate}.go` from the Go reference field-for-field:
 *            - `passes_validators` mirrors `Validate(candidate, rule)`: it
 *              strips `value` to digits ONCE (mirroring Go's
 *              `stripNonDigits`, computed once up front) and shares that
 *              string across every digit-based validator (luhn/snils/
 *              inn_person/inn_org/ogrn/ogrnip/payment_card[_no_luhn]); IBAN
 *              and email get the raw (untouched) value, matching
 *              `IBANMod97Valid`/`EmailASCIIValid` in the Go reference, which
 *              never see the stripped form.
 *            - The `entropy` validator only rejects when BOTH the "entropy"
 *              name is present in `rule.validators` AND `rule.entropy > 0`
 *              (see `validate.go`'s `case rule.ValidatorEntropy`). A rule
 *              that lists `entropy` but leaves `entropy: 0` (the field's
 *              zero value) passes trivially, regardless of value — this is
 *              deliberate Go behavior (`TestValidate/entropy_threshold_is_
 *              ignored_when_unset`), not a gap. `rule.entropy` never gates
 *              anything unless "entropy" also appears in `rule.validators`;
 *              Go wires no automatic/implicit application from the field
 *              alone.
 *            - The `banlist` validator does a case-insensitive EXACT match
 *              (`strings.ToLower(candidate) == banned`), not a substring
 *              search — confirmed by `validate.go`'s `banlisted` helper and
 *              its test (`banlisted("password1", ["password"])` is false).
 *              `rule.banlist` entries are already lowercased by the YAML
 *              loader (RulesYaml.hpp); only the candidate needs lowering
 *              here, via the same Unicode-aware `to_lower_utf8` the loader
 *              uses (Go's `strings.ToLower` is Unicode-aware too).
 *            - Unknown validator name -> the whole call returns false at
 *              runtime (`default: return false` in Go's `Validate`).
 *              Rejecting an unrecognized name at *compile* time is
 *              Registry::compile_rule's job in a later task, not this one.
 *          `is_known_validator` covers all 16 names Go's `IsKnown` in
 *          `registry.go` recognizes (its own test table only exercises 15 of
 *          them, omitting `payment_card_no_luhn` — a gap in the Go test, not
 *          in the Go implementation, which does list it; ours covers all
 *          16, matching the implementation).
 */

#pragma once

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "guard/Rule.hpp"
#include "guard/Unicode.hpp"

namespace Guard {

namespace detail {

// Explicit ASCII-only fold, deliberately not std::toupper: std::toupper is
// locale-dependent (its behavior for values outside the "C" locale's basic
// execution charset is unspecified, and some locales remap bytes std::toupper
// would otherwise leave alone), and IBAN input is ASCII-only by spec anyway
// -- same convention as Unicode.hpp's ASCII-only helpers.
inline char ascii_upper_char(char c) {
    return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
}

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

inline bool banlisted(std::string_view candidate, const std::vector<std::string>& banlist) {
    const std::string lower = to_lower_utf8(candidate);
    for (const auto& banned : banlist)
        if (lower == banned)
            return true;
    return false;
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

    static constexpr std::array<int, 10> kWeights1{7, 2, 4, 10, 3, 5, 9, 4, 6, 8};
    int sum1 = 0;
    for (std::size_t i = 0; i < 10; ++i)
        sum1 += d(i) * kWeights1[i];
    const int v1 = (sum1 % 11) % 10;

    std::array<int, 11> digits{};
    for (std::size_t i = 0; i < 10; ++i)
        digits[i] = d(i);
    digits[10] = v1;
    static constexpr std::array<int, 11> kWeights2{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8};
    int sum2 = 0;
    for (std::size_t i = 0; i < 11; ++i)
        sum2 += digits[i] * kWeights2[i];
    const int v2 = (sum2 % 11) % 10;

    return {static_cast<char>('0' + v1), static_cast<char>('0' + v2)};
}

inline char inn_org_checksum(std::string_view nine_digits) {
    auto d = [&](std::size_t i) { return nine_digits[i] - '0'; };
    static constexpr std::array<int, 9> kWeights{2, 4, 10, 3, 5, 9, 4, 6, 8};
    int sum = 0;
    for (std::size_t i = 0; i < 9; ++i)
        sum += d(i) * kWeights[i];
    const int checksum = (sum % 11) % 10;
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
        c = ascii_upper_char(c);

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
        iban.push_back(detail::ascii_upper_char(c));
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

// ── Format validators (Task 1.3) ────────────────────────────────────────

namespace detail {

inline bool is_ascii_local_part_char(char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return true;
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '/':
        case '=':
        case '?':
        case '^':
        case '_':
        case '`':
        case '{':
        case '|':
        case '}':
        case '~':
            return true;
        default:
            return false;
    }
}

inline bool is_ascii_domain_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
}

inline bool is_alpha(std::string_view s) {
    if (s.empty())
        return false;
    for (char c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
            return false;
    return true;
}

// Splits on '.', including empty parts for consecutive/leading/trailing dots
// (the caller has usually already rejected those shapes, but this mirrors
// Go's unconditional strings.Split so both languages see the same parts).
inline std::vector<std::string> split_dot(std::string_view s) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (true) {
        const auto dot = s.find('.', start);
        if (dot == std::string_view::npos) {
            parts.emplace_back(s.substr(start));
            break;
        }
        parts.emplace_back(s.substr(start, dot - start));
        start = dot + 1;
    }
    return parts;
}

}  // namespace detail

// Uses the repo's ASCII-only ascii_trim rather than porting a Unicode-aware
// TrimSpace. This is a real divergence, not a no-op one: Go's strings.
// TrimSpace also strips Unicode whitespace (e.g. U+00A0 NBSP), so an
// NBSP-wrapped candidate that Go's EmailASCIIValid would accept fails here
// (the NBSP survives into the shape checks and none of them accept it). It
// is unreachable in practice, though: candidates only ever reach this
// validator as regex capture groups from the shipped catalog patterns, none
// of which can match leading/trailing Unicode whitespace into the captured
// span, so no real candidate exercises the gap.
inline bool email_ascii_valid(std::string_view candidate) {
    const std::string s = detail::ascii_trim(std::string(candidate));
    if (s.empty() || s.size() > 254)
        return false;

    const auto at = s.find('@');
    if (at == std::string::npos)
        return false;
    const std::string local = s.substr(0, at);
    const std::string domain = s.substr(at + 1);
    if (local.empty() || domain.empty())
        return false;
    if (local.find("..") != std::string::npos || local.front() == '.' || local.back() == '.')
        return false;
    if (local.size() > 64 || domain.size() > 253)
        return false;

    for (const auto& part : detail::split_dot(local)) {
        if (part.empty())
            return false;
        for (char c : part)
            if (!detail::is_ascii_local_part_char(c))
                return false;
    }

    const auto labels = detail::split_dot(domain);
    if (labels.size() < 2)
        return false;
    for (std::size_t i = 0; i < labels.size(); ++i) {
        const auto& label = labels[i];
        if (label.empty() || label.size() > 63)
            return false;
        if (label.front() == '-' || label.back() == '-')
            return false;
        for (char c : label)
            if (!detail::is_ascii_domain_char(c))
                return false;
        if (i == labels.size() - 1 && !detail::is_alpha(label))
            return false;
    }
    return true;
}

namespace detail {

inline bool all_digits(std::string_view s) {
    if (s.empty())
        return false;
    for (char c : s)
        if (c < '0' || c > '9')
            return false;
    return true;
}

inline bool has_prefix_digits(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

inline bool prefix_in_range(std::string_view s, std::size_t prefix_len, int lo, int hi) {
    if (s.size() < prefix_len)
        return false;
    int n = 0;
    for (std::size_t i = 0; i < prefix_len; ++i) {
        const char c = s[i];
        if (c < '0' || c > '9')
            return false;
        n = n * 10 + (c - '0');
    }
    return n >= lo && n <= hi;
}

}  // namespace detail

// Brand/length table ported verbatim from formats.go's PaymentCardShape:
// Visa 4 (13/16/19); Amex 34|37 (15); Mastercard 51-55|2221-2720 (16);
// Discover 6011|644-649|65 (16-19); UnionPay 62 (16-19); Mir 2200-2204
// (16-19). This matches the brief's summary table exactly -- no divergence
// found against the Go source.
inline bool payment_card_shape(std::string_view digits) {
    if (!detail::all_digits(digits) || digits.size() < 13 || digits.size() > 19)
        return false;

    if (detail::has_prefix_digits(digits, "4"))
        return digits.size() == 13 || digits.size() == 16 || digits.size() == 19;
    if (detail::has_prefix_digits(digits, "34") || detail::has_prefix_digits(digits, "37"))
        return digits.size() == 15;
    if (detail::prefix_in_range(digits, 2, 51, 55) || detail::prefix_in_range(digits, 4, 2221, 2720))
        return digits.size() == 16;
    if (detail::has_prefix_digits(digits, "6011") || detail::prefix_in_range(digits, 3, 644, 649) ||
        detail::has_prefix_digits(digits, "65"))
        return digits.size() >= 16 && digits.size() <= 19;
    if (detail::has_prefix_digits(digits, "62"))
        return digits.size() >= 16 && digits.size() <= 19;
    if (detail::prefix_in_range(digits, 4, 2200, 2204))
        return digits.size() >= 16 && digits.size() <= 19;
    return false;
}

inline bool payment_card_valid(std::string_view digits) {
    return payment_card_shape(digits) && luhn_valid(digits);
}

// ── Shannon entropy ──────────────────────────────────────────────────────

namespace detail {

struct Utf8Decoded {
    char32_t codepoint;
    std::size_t length;
};

// Mirrors Go's `for range` over a string: on invalid/truncated UTF-8 it
// yields U+FFFD and advances exactly one byte, matching utf8.DecodeRuneInString.
inline Utf8Decoded decode_utf8(std::string_view s, std::size_t i) {
    const auto cont = [&](std::size_t idx) -> int {
        if (idx >= s.size())
            return -1;
        const auto c = static_cast<unsigned char>(s[idx]);
        if ((c & 0xC0) != 0x80)
            return -1;
        return c & 0x3F;
    };

    const auto c0 = static_cast<unsigned char>(s[i]);
    if ((c0 & 0x80) == 0)
        return {c0, 1};

    if ((c0 & 0xE0) == 0xC0) {
        const int c1 = cont(i + 1);
        if (c1 < 0)
            return {0xFFFD, 1};
        const auto cp = static_cast<char32_t>(((c0 & 0x1Fu) << 6) | static_cast<unsigned>(c1));
        if (cp < 0x80)
            return {0xFFFD, 1};
        return {cp, 2};
    }
    if ((c0 & 0xF0) == 0xE0) {
        const int c1 = cont(i + 1);
        const int c2 = cont(i + 2);
        if (c1 < 0 || c2 < 0)
            return {0xFFFD, 1};
        const unsigned hi = (c0 & 0x0Fu) << 12;
        const unsigned mid = static_cast<unsigned>(c1) << 6;
        const auto cp = static_cast<char32_t>(hi | mid | static_cast<unsigned>(c2));
        // Overlong (cp < 0x800) and UTF-8-encoded surrogates (U+D800-U+DFFF
        // have no valid UTF-8 encoding -- surrogates are UTF-16-only code
        // points) are both invalid: Go's utf8.DecodeRuneInString rejects
        // both and yields RuneError for exactly the lead byte, which is what
        // returning {0xFFFD, 1} here does too (the caller retries from the
        // very next byte, byte-at-a-time, same as Go's `for range`).
        if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))
            return {0xFFFD, 1};
        return {cp, 3};
    }
    if ((c0 & 0xF8) == 0xF0) {
        const int c1 = cont(i + 1);
        const int c2 = cont(i + 2);
        const int c3 = cont(i + 3);
        if (c1 < 0 || c2 < 0 || c3 < 0)
            return {0xFFFD, 1};
        const unsigned hi = (c0 & 0x07u) << 18;
        const unsigned mid1 = static_cast<unsigned>(c1) << 12;
        const unsigned mid2 = static_cast<unsigned>(c2) << 6;
        const auto cp = static_cast<char32_t>(hi | mid1 | mid2 | static_cast<unsigned>(c3));
        if (cp < 0x10000 || cp > 0x10FFFF)
            return {0xFFFD, 1};
        return {cp, 4};
    }
    return {0xFFFD, 1};
}

}  // namespace detail

inline double shannon_entropy(std::string_view s) {
    if (s.empty())
        return 0.0;

    bool ascii = true;
    for (unsigned char c : s) {
        if (c > 127) {
            ascii = false;
            break;
        }
    }

    if (ascii) {
        std::array<int, 256> freq{};
        for (unsigned char c : s)
            ++freq[c];
        const double n = static_cast<double>(s.size());
        double entropy = 0.0;
        for (int count : freq) {
            if (count == 0)
                continue;
            const double p = count / n;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    std::unordered_map<char32_t, std::size_t> freq;
    std::size_t total = 0;
    std::size_t i = 0;
    while (i < s.size()) {
        const auto decoded = detail::decode_utf8(s, i);
        ++freq[decoded.codepoint];
        ++total;
        i += decoded.length;
    }
    const double n = static_cast<double>(total);
    double entropy = 0.0;
    for (const auto& [codepoint, count] : freq) {
        const double p = static_cast<double>(count) / n;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ── IP validators ────────────────────────────────────────────────────────
//
// Ported from formats.go's parseIPCandidate/isPrivateOrLocal (net/netip).
// isPrivateOrLocal ORs private, loopback, multicast, link-local-unicast,
// link-local-multicast, interface-local-multicast, and unspecified — but
// link-local-multicast (224.0.0.0/24, ff02::/16) and interface-local-
// multicast (ff01::/16) are both strict subsets of "multicast"
// (224.0.0.0/4, ff00::/8), so ORing just {private, loopback, multicast,
// link-local-unicast, unspecified} below is boolean-identical to Go's
// seven-way OR while avoiding two redundant predicates.
//
// IPv4 is parsed by hand rather than via inet_pton: libc's dotted-quad
// parsing is platform-defined and disagrees with Go's net/netip in exactly
// the cases that matter for a masking filter -- e.g. macOS's libc accepts a
// leading-zero octet ("010.1.2.3", historically read as octal by some
// stacks) that both Go and strict dotted-quad reject. try_parse_v4 below
// enforces net/netip's strict grammar itself: exactly four decimal octets,
// each 1-3 digits, value 0-255, no leading zeros.
//
// Zone identifiers ("fe80::1%eth0") are valid IPv6 literals per Go's
// net/netip, but glibc/musl and macOS's libc disagree on whether inet_pton
// accepts the "%zone" suffix at all. The regex-driven candidates this
// scanner ever sees can't carry one (no rule captures a literal '%'), so
// rather than chase three divergent platform behaviors, parse_ip_candidate
// rejects any candidate containing '%' outright -- a deliberate, documented
// divergence from Go (which accepts zones): conservative and portable.

namespace detail {

struct ParsedIp {
    bool is_v4{false};
    std::array<unsigned char, 4> v4bytes{};
    std::array<unsigned char, 16> v6bytes{};
};

// Strict dotted-quad: exactly 4 '.'-separated decimal octets, each 1-3
// digits, value 0-255, no leading zeros on a multi-digit octet (so "0" is
// fine but "010" is not). No use of inet_pton -- see the file-level comment
// above for why libc's own dotted-quad parsing isn't trustworthy here.
inline bool try_parse_v4(const std::string& s, std::array<unsigned char, 4>& out) {
    std::size_t start = 0;
    for (int octet_idx = 0; octet_idx < 4; ++octet_idx) {
        const bool last = octet_idx == 3;
        const auto dot = s.find('.', start);
        std::size_t end{};
        if (last) {
            if (dot != std::string::npos)
                return false;  // trailing garbage after the 4th octet
            end = s.size();
        } else {
            if (dot == std::string::npos)
                return false;  // fewer than 4 octets
            end = dot;
        }

        const std::string_view octet(s.data() + start, end - start);
        if (octet.empty() || octet.size() > 3)
            return false;
        if (octet.size() > 1 && octet[0] == '0')
            return false;  // no leading zeros (Go's net/netip rejects "010")

        int value = 0;
        for (char c : octet) {
            if (c < '0' || c > '9')
                return false;
            value = value * 10 + (c - '0');
        }
        if (value > 255)
            return false;

        out[static_cast<std::size_t>(octet_idx)] = static_cast<unsigned char>(value);
        start = end + 1;
    }
    return true;
}

inline bool try_parse_v6(const std::string& s, std::array<unsigned char, 16>& out) {
    in6_addr addr{};
    if (inet_pton(AF_INET6, s.c_str(), &addr) != 1)
        return false;
    static_assert(sizeof(addr) == 16, "unexpected in6_addr size");
    const auto* bytes = reinterpret_cast<const unsigned char*>(&addr);
    for (int i = 0; i < 16; ++i)
        out[static_cast<std::size_t>(i)] = bytes[i];
    return true;
}

inline bool is_v4_mapped_v6(const std::array<unsigned char, 16>& b) {
    for (int i = 0; i < 10; ++i)
        if (b[static_cast<std::size_t>(i)] != 0)
            return false;
    return b[10] == 0xff && b[11] == 0xff;
}

inline ParsedIp unmap_v6(const std::array<unsigned char, 16>& b) {
    ParsedIp p;
    p.is_v4 = true;
    p.v4bytes = {b[12], b[13], b[14], b[15]};
    return p;
}

// Trims whitespace, then either:
//   - a CIDR form ("addr/bits"): parsed strictly -- if the address part
//     doesn't parse or bits overflows the family's width, the whole
//     candidate fails (no fallback to plain-address parsing), matching
//     netip.ParsePrefix's all-or-nothing behavior; the prefix length is
//     otherwise not used (a v4-in-v6 mapped address is still unmapped).
//   - otherwise: leading/trailing '[' and ']' are trimmed (any mix, any
//     count -- mirrors strings.Trim(s, "[]")), then parsed as a plain
//     address.
inline std::optional<ParsedIp> parse_ip_candidate(std::string_view candidate) {
    const std::string s = ascii_trim(std::string(candidate));
    if (s.empty())
        return std::nullopt;
    // Zone suffixes: rejected outright, see the file-level comment above.
    if (s.find('%') != std::string::npos)
        return std::nullopt;

    const auto slash = s.find('/');
    if (slash != std::string::npos) {
        const std::string addr_part = s.substr(0, slash);
        const std::string prefix_part = s.substr(slash + 1);
        if (prefix_part.empty())
            return std::nullopt;
        for (char c : prefix_part)
            if (c < '0' || c > '9')
                return std::nullopt;
        int bits = 0;
        for (char c : prefix_part) {
            bits = bits * 10 + (c - '0');
            if (bits > 128) {
                bits = 129;
                break;
            }
        }

        std::array<unsigned char, 4> v4{};
        if (try_parse_v4(addr_part, v4)) {
            if (bits > 32)
                return std::nullopt;
            ParsedIp p;
            p.is_v4 = true;
            p.v4bytes = v4;
            return p;
        }
        std::array<unsigned char, 16> v6{};
        if (try_parse_v6(addr_part, v6)) {
            if (bits > 128)
                return std::nullopt;
            return is_v4_mapped_v6(v6) ? unmap_v6(v6) : ParsedIp{false, {}, v6};
        }
        return std::nullopt;
    }

    std::size_t begin = 0;
    std::size_t end = s.size();
    while (begin < end && (s[begin] == '[' || s[begin] == ']'))
        ++begin;
    while (end > begin && (s[end - 1] == '[' || s[end - 1] == ']'))
        --end;
    const std::string trimmed = s.substr(begin, end - begin);

    std::array<unsigned char, 4> v4{};
    if (try_parse_v4(trimmed, v4)) {
        ParsedIp p;
        p.is_v4 = true;
        p.v4bytes = v4;
        return p;
    }
    std::array<unsigned char, 16> v6{};
    if (try_parse_v6(trimmed, v6))
        return is_v4_mapped_v6(v6) ? unmap_v6(v6) : ParsedIp{false, {}, v6};
    return std::nullopt;
}

inline bool is_private_v4(const std::array<unsigned char, 4>& b) {
    return b[0] == 10 || (b[0] == 172 && (b[1] & 0xf0) == 16) || (b[0] == 192 && b[1] == 168);
}
inline bool is_loopback_v4(const std::array<unsigned char, 4>& b) {
    return b[0] == 127;
}
inline bool is_multicast_v4(const std::array<unsigned char, 4>& b) {
    return (b[0] & 0xf0) == 0xe0;
}
inline bool is_link_local_v4(const std::array<unsigned char, 4>& b) {
    return b[0] == 169 && b[1] == 254;
}
inline bool is_unspecified_v4(const std::array<unsigned char, 4>& b) {
    return b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0;
}

inline bool is_private_v6(const std::array<unsigned char, 16>& b) {
    return (b[0] & 0xfe) == 0xfc;
}
inline bool is_loopback_v6(const std::array<unsigned char, 16>& b) {
    for (int i = 0; i < 15; ++i)
        if (b[static_cast<std::size_t>(i)] != 0)
            return false;
    return b[15] == 1;
}
inline bool is_multicast_v6(const std::array<unsigned char, 16>& b) {
    return b[0] == 0xff;
}
inline bool is_link_local_v6(const std::array<unsigned char, 16>& b) {
    return b[0] == 0xfe && (b[1] & 0xc0) == 0x80;
}
inline bool is_unspecified_v6(const std::array<unsigned char, 16>& b) {
    for (unsigned char byte : b)
        if (byte != 0)
            return false;
    return true;
}

inline bool is_private_or_local(const ParsedIp& p) {
    if (p.is_v4)
        return is_private_v4(p.v4bytes) || is_loopback_v4(p.v4bytes) || is_multicast_v4(p.v4bytes) ||
               is_link_local_v4(p.v4bytes) || is_unspecified_v4(p.v4bytes);
    return is_private_v6(p.v6bytes) || is_loopback_v6(p.v6bytes) || is_multicast_v6(p.v6bytes) ||
           is_link_local_v6(p.v6bytes) || is_unspecified_v6(p.v6bytes);
}

}  // namespace detail

inline bool ip_v4(std::string_view value) {
    const auto p = detail::parse_ip_candidate(value);
    return p.has_value() && p->is_v4;
}

inline bool ip_v6(std::string_view value) {
    const auto p = detail::parse_ip_candidate(value);
    return p.has_value() && !p->is_v4;
}

inline bool ip_public(std::string_view value) {
    const auto p = detail::parse_ip_candidate(value);
    return p.has_value() && !detail::is_private_or_local(*p);
}

inline bool ip_private(std::string_view value) {
    const auto p = detail::parse_ip_candidate(value);
    return p.has_value() && detail::is_private_or_local(*p);
}

// ── Dispatch ─────────────────────────────────────────────────────────────

inline bool is_known_validator(std::string_view name) {
    static const std::unordered_set<std::string_view> kKnown = {
        "luhn",
        "snils",
        "inn_person",
        "inn_org",
        "ogrn",
        "ogrnip",
        "iban_mod97",
        "email_ascii",
        "payment_card",
        "payment_card_no_luhn",
        "entropy",
        "banlist",
        "ip_v4",
        "ip_v6",
        "ip_public",
        "ip_private",
    };
    return kKnown.count(name) != 0;
}

// AND over rule.validators, mirroring validate.go's Validate: each name maps
// to one branch; "entropy"/"banlist" additionally consult rule.entropy /
// rule.banlist (see the file-level doc comment for their exact gating); an
// unrecognized name fails the whole call (matches Go's `default: return
// false`).
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
        } else if (validator == "email_ascii") {
            if (!email_ascii_valid(value))
                return false;
        } else if (validator == "payment_card") {
            if (!payment_card_valid(digits))
                return false;
        } else if (validator == "payment_card_no_luhn") {
            if (!payment_card_shape(digits))
                return false;
        } else if (validator == "entropy") {
            if (rule.entropy > 0 && shannon_entropy(value) < rule.entropy)
                return false;
        } else if (validator == "banlist") {
            if (detail::banlisted(value, rule.banlist))
                return false;
        } else if (validator == "ip_v4") {
            if (!ip_v4(value))
                return false;
        } else if (validator == "ip_v6") {
            if (!ip_v6(value))
                return false;
        } else if (validator == "ip_public") {
            if (!ip_public(value))
                return false;
        } else if (validator == "ip_private") {
            if (!ip_private(value))
                return false;
        } else {
            return false;
        }
    }

    return true;
}

}  // namespace Guard
