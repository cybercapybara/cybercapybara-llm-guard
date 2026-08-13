/**
 * @file Endpoints.hpp
 * @brief Endpoint registry — the single source of truth for routes.
 * @details `docs/openapi.yaml` is checked against this list in CI via
 *          scripts/check-openapi-drift.sh; `--print-routes` prints it.
 *          Add a line here for every new ADD_METHOD_TO.
 */

#pragma once

#include <string>
#include <vector>

namespace Api {

/**
 * @brief Endpoint metadata: method, path, description
 */
struct EndpointInfo {
    std::string method;
    std::string path;
    std::string description;
};

/**
 * @brief Single source of truth for all registered API endpoints
 */
inline const std::vector<EndpointInfo>& get_endpoints() {
    static const std::vector<EndpointInfo> endpoints = {
        {"GET", "/", "Endpoint discovery"},
        {"GET", "/healthz", "Liveness probe"},
        {"GET", "/ready", "Readiness probe"},
        {"GET", "/health", "Detailed health check"},
    };
    return endpoints;
}

}  // namespace Api
