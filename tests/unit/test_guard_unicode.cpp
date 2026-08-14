/**
 * @file test_guard_unicode.cpp
 * @brief Unit tests for Guard::to_lower_utf8 (src/guard/Unicode.hpp).
 *
 * Guards against the ASCII-only-lowercase divergence from Go's
 * strings.ToLower: the real ported catalogs (configs/rules.yaml) carry
 * Cyrillic rule keywords ("ИНН", "ОГРН", "ОГРНИП"), and a byte-wise
 * std::tolower would silently leave those uppercase.
 */

#include <string>

#include <gtest/gtest.h>

#include "guard/Unicode.hpp"

namespace {

TEST(GuardUnicode, AsciiFastPath) {
    EXPECT_EQ(Guard::to_lower_utf8("Hello World"), "hello world");
    EXPECT_EQ(Guard::to_lower_utf8("ALL_CAPS_123"), "all_caps_123");
    EXPECT_EQ(Guard::to_lower_utf8("already lower"), "already lower");
    EXPECT_EQ(Guard::to_lower_utf8(""), "");
}

TEST(GuardUnicode, CyrillicLowercases) {
    // The exact keywords carried by configs/rules.yaml's pii.docs.* rules.
    EXPECT_EQ(Guard::to_lower_utf8("ОГРН"), "огрн");
    EXPECT_EQ(Guard::to_lower_utf8("ОГРНИП"), "огрнип");
    EXPECT_EQ(Guard::to_lower_utf8("ИНН"), "инн");
    EXPECT_EQ(Guard::to_lower_utf8("Инн"), "инн");
    EXPECT_EQ(Guard::to_lower_utf8("ИНН:"), "инн:");
}

TEST(GuardUnicode, GreekEdgeCase) {
    // Simple case folding: standalone capital Sigma maps to lowercase sigma
    // (not the context-sensitive final-sigma "ς" form, which needs
    // locale-aware processing utf8proc's simple tolower doesn't attempt).
    EXPECT_EQ(Guard::to_lower_utf8("Σ"), "σ");
    EXPECT_EQ(Guard::to_lower_utf8("ΑΒΓ"), "αβγ");
}

TEST(GuardUnicode, MixedScriptAndAscii) {
    EXPECT_EQ(Guard::to_lower_utf8("Secret ИНН 123"), "secret инн 123");
}

TEST(GuardUnicode, AlreadyLowercaseIsIdempotent) {
    EXPECT_EQ(Guard::to_lower_utf8("огрн"), "огрн");
    EXPECT_EQ(Guard::to_lower_utf8("σ"), "σ");
}

TEST(GuardUnicode, InvalidUtf8BytePassesThroughUnchanged) {
    // 0xFF is never a valid UTF-8 lead byte.
    const std::string invalid = std::string("x") + std::string(1, static_cast<char>(0xFF)) + "y";
    EXPECT_EQ(Guard::to_lower_utf8(invalid), invalid);
}

TEST(GuardUnicode, InvalidUtf8ByteMixedWithValidTextStillLowercasesTheRest) {
    const std::string input = std::string("ABC") + std::string(1, static_cast<char>(0xFF)) + "DEF";
    const std::string expected = std::string("abc") + std::string(1, static_cast<char>(0xFF)) + "def";
    EXPECT_EQ(Guard::to_lower_utf8(input), expected);
}

}  // namespace
