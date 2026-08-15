/**
 * @file ApiFormat.hpp
 * @brief The three LLM wire formats the gateway proxies.
 * @details Lives in `Guard::` rather than `Guard::Extract::` per
 *          `phase2-interfaces.md`: the gateway/route layer (a later phase)
 *          needs to select a format before any extraction happens, and
 *          `Guard::Demask::make_config`-adjacent request-scoped plumbing
 *          also names it outside the extractor namespace. Split into its
 *          own header (rather than folded into `Extract.hpp`) so the
 *          per-format extractor headers landing in Tasks 2.2-2.4 (each
 *          touching only their own file) don't collide on a shared
 *          `Extract.hpp` edit.
 */

#pragma once

namespace Guard {

/// Wire format of an LLM request/response body.
enum class ApiFormat {
    ChatCompletions,  // OpenAI-compatible /v1/chat/completions
    Messages,         // Anthropic /v1/messages
    Responses,        // OpenAI /v1/responses
};

}  // namespace Guard
