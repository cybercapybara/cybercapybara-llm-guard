/**
 * @file Api.hpp
 * @brief API module aggregator: endpoint registry + controllers + middleware.
 * @details The layer is split so includers pay only for what they use:
 *            - Endpoints.hpp    — route registry (single source of truth)
 *            - RequestUtils.hpp — parse_int / clamp_int / pagination helpers
 *            - Middleware.hpp   — advice chain + OTel glue (the heavy include)
 *          Controllers include the first two directly and must NOT include
 *          this header (that used to form an include cycle).
 */

#pragma once

#include <spdlog/spdlog.h>

#include "api/Endpoints.hpp"
#include "api/RequestUtils.hpp"

// Controllers self-register with Drogon when their TU is compiled — pulling
// them in here is what puts the routes into main.cpp's binary.
#include "api/HealthController.hpp"
#include "api/Middleware.hpp"

namespace Api {

/**
 * @brief Register all API middleware (controllers register themselves).
 * @details The middleware order matters — each sync-advice runs in registration
 *          order and may short-circuit the chain. Tracing is registered last on
 *          the pre-path so it fires only for requests that will actually reach
 *          a handler.
 */
inline void register_controllers() {
    spdlog::info("Registering API controllers");
    middleware::ensure_http_metric_families();
    // Content-Type check runs first so a malformed mutation request is
    // rejected before any handler work.
    middleware::register_content_type_check();
    middleware::register_cors();
    middleware::register_security_headers();
    middleware::register_tracing_pre();
    middleware::register_access_log_post();
    register_docs_endpoints();
}

}  // namespace Api
