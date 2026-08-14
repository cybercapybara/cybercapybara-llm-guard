/**
 * @file Unicode.hpp
 * @brief Shared case-folding/trim helpers for the masking engine.
 * @details Two families live here so there is exactly one home for each:
 *            - ASCII-only helpers (`detail::ascii_to_upper`,
 *              `detail::ascii_trim`) for structural values that are ASCII by
 *              construction (DataType names, filesystem paths) — cheap, no
 *              utf8proc dependency.
 *            - `to_lower_utf8`, a Unicode-aware lowercase for anything that
 *              flows from free-form catalog text an operator may write in
 *              any script. The real ported catalogs (`configs/rules.yaml`)
 *              contain Cyrillic rule keywords ("ИНН", "ОГРН", "ОГРНИП"); a
 *              byte-wise `std::tolower` only touches ASCII and would leave
 *              those uppercase, silently breaking a case-sensitive keyword
 *              prefilter once one lands downstream (a masking miss / PII
 *              leak, not just a cosmetic bug). This mirrors Go's
 *              `strings.ToLower`, which is Unicode-aware by default.
 *          Invalid UTF-8 bytes pass through `to_lower_utf8` unchanged — it
 *          never throws — matching Go's lenient handling of invalid runes.
 */

#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

#include <utf8proc.h>

namespace Guard {

namespace detail {

// Only ever applied to values that are ASCII by construction. User-authored
// rule text (keywords/banlist) must go through to_lower_utf8 below instead.
inline std::string ascii_to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

inline std::string ascii_trim(const std::string& s) {
    auto not_space = [](unsigned char c) { return std::isspace(c) == 0; };
    auto begin = std::find_if(s.begin(), s.end(), not_space);
    auto end = std::find_if(s.rbegin(), s.rend(), not_space).base();
    if (begin >= end)
        return "";
    return std::string(begin, end);
}

inline bool is_ascii(std::string_view s) {
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return c < 0x80; });
}

}  // namespace detail

/**
 * @brief Unicode-aware lowercase over UTF-8 input.
 * @details Fast path: an all-ASCII input never touches utf8proc. Otherwise
 *          decodes one codepoint at a time via `utf8proc_iterate`, maps it
 *          through `utf8proc_tolower` (simple case folding — e.g. Cyrillic
 *          "ОГРН" -> "огрн", Greek "Σ" -> "σ"), and re-encodes with
 *          `utf8proc_encode_char`. A byte sequence utf8proc can't decode is
 *          copied through unchanged and the cursor advances by exactly one
 *          byte, so this function is total (never throws) even on
 *          arbitrary/corrupt input.
 */
inline std::string to_lower_utf8(std::string_view s) {
    if (detail::is_ascii(s)) {
        std::string out(s);
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return out;
    }

    std::string out;
    out.reserve(s.size());
    std::size_t i = 0;
    while (i < s.size()) {
        utf8proc_int32_t codepoint = 0;
        const auto* remaining_start = reinterpret_cast<const utf8proc_uint8_t*>(s.data() + i);
        const auto remaining_len = static_cast<utf8proc_ssize_t>(s.size() - i);
        const utf8proc_ssize_t consumed = utf8proc_iterate(remaining_start, remaining_len, &codepoint);
        if (consumed <= 0) {
            // Invalid byte: pass through unchanged, advance one byte. Never
            // throws -- parity with Go's lenient invalid-rune handling.
            out.push_back(s[i]);
            ++i;
            continue;
        }

        const utf8proc_int32_t lower = utf8proc_tolower(codepoint);
        utf8proc_uint8_t buf[4];
        const utf8proc_ssize_t written = utf8proc_encode_char(lower, buf);
        if (written > 0) {
            out.append(reinterpret_cast<const char*>(buf), static_cast<std::size_t>(written));
        } else {
            // Unreachable in practice (tolower always yields an encodable
            // codepoint), but fall back to the original bytes rather than
            // dropping the character if it ever happens.
            out.append(s.data() + i, static_cast<std::size_t>(consumed));
        }
        i += static_cast<std::size_t>(consumed);
    }
    return out;
}

}  // namespace Guard
