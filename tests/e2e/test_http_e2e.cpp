/**
 * @file test_http_e2e.cpp
 * @brief End-to-end tests over REAL HTTP.
 *
 * Every other suite drives controller methods directly, which means the
 * middleware chain registered in Api::register_controllers() — content-type
 * check, security headers, tracing headers, Drogon routing, serialization on
 * the wire — never executes in tests. This binary closes that gap: it boots
 * Core, registers the controllers, runs the real Drogon server on a loopback
 * port in a background thread, and talks to it with drogon::HttpClient.
 *
 * Built as a SEPARATE executable (llm_guard_e2e): drogon::app() is a
 * process-wide singleton whose run()/quit() cycle is once-per-process, so it
 * cannot coexist with suites that reset global state between tests.
 *
 * Requires the Postgres + Redis sidecars (same as the integration bucket).
 * Run inside Docker:  make test-e2e
 */

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#include <drogon/HttpClient.h>
#include <drogon/drogon.h>
#include <gtest/gtest.h>
#include <trantor/net/EventLoopThread.h>

#include <nlohmann/json.hpp>

#include "api/Api.hpp"
#include "core/Core.hpp"
#include "test_helpers.hpp"

using json = nlohmann::json;
using namespace drogon;

namespace {

constexpr uint16_t kPort = 18098;

bool g_env_ok = false;

std::string base_url() {
    return "http://127.0.0.1:" + std::to_string(kPort);
}

/**
 * Dedicated event loop for every HttpClient in this binary.
 *
 * newHttpClient(url) with no explicit loop falls back to app().getLoop() — a
 * lazily constructed static EventLoop that binds to whichever thread touches
 * it first. That races the server thread's app().run(): if the main thread
 * (client) constructs it first, run() aborts with trantor's "It is forbidden
 * to run loop on threads other than event-loop thread" FATAL. Keeping clients
 * on a private loop means the main thread never touches the app loop at all.
 */
trantor::EventLoop* client_loop() {
    static trantor::EventLoopThread th("e2eClient");
    static const bool started = (th.run(), true);
    (void)started;
    return th.getLoop();
}

/**
 * Boots Core + Drogon exactly once for the whole binary. Tests skip when
 * the sidecars are unreachable (g_env_ok stays false).
 */
class HttpServerEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        std::filesystem::create_directories("logs");
        if (!TestHelpers::is_postgres_available() || !TestHelpers::is_redis_available()) {
            return;  // tests will GTEST_SKIP
        }

        json cfg = json::parse(TestHelpers::minimal_config());
        cfg["database"]["migrations_enabled"] = true;
        cfg["database"]["migrations_dir"] = "migrations";

        config_path_ = TestHelpers::create_temp_config(cfg.dump(2), "e2e_test_config.json");
        Core::initialize(config_path_);

        Api::register_controllers();
        app().addListener("127.0.0.1", kPort).setThreadNum(1);
        server_thread_ = std::thread([] { app().run(); });

        // Wait until the server actually accepts: poll /healthz.
        auto client = HttpClient::newHttpClient(base_url(), client_loop());
        for (int i = 0; i < 100; ++i) {
            auto req = HttpRequest::newHttpRequest();
            req->setPath("/healthz");
            auto [ok, resp] = client->sendRequest(req, /*timeout=*/1.0);
            if (ok == ReqResult::Ok && resp && resp->statusCode() == k200OK) {
                g_env_ok = true;
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        ADD_FAILURE() << "e2e server did not become ready on " << base_url();
    }

    void TearDown() override {
        if (server_thread_.joinable()) {
            app().quit();
            server_thread_.join();
        }
        TestHelpers::reset_all_globals();
        TestHelpers::remove_temp_config(config_path_);
    }

private:
    std::string config_path_;
    std::thread server_thread_;
};

#define REQUIRE_E2E_ENV() \
    if (!g_env_ok)        \
    GTEST_SKIP() << "Postgres/Redis sidecars unavailable — e2e server not started"

// ---------------------------------------------------------------------------
// Small sync-request helper.
// ---------------------------------------------------------------------------

HttpResponsePtr send(const HttpRequestPtr& req) {
    auto client = HttpClient::newHttpClient(base_url(), client_loop());
    auto [ok, resp] = client->sendRequest(req, /*timeout=*/5.0);
    EXPECT_EQ(ok, ReqResult::Ok) << "transport error talking to e2e server";
    EXPECT_NE(resp, nullptr);
    return resp;
}

// ---------------------------------------------------------------------------
// Liveness over the wire. The single surviving e2e case: it proves the whole
// stack (Core boot -> Drogon listener -> middleware chain -> controller ->
// JSON response) works end to end, and keeps the harness alive for the
// proxy suites that land in a later phase.
// ---------------------------------------------------------------------------

TEST(HealthE2E, LivenessOverRealHttp) {
    REQUIRE_E2E_ENV();
    auto req = HttpRequest::newHttpRequest();
    req->setPath("/healthz");
    auto resp = send(req);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->statusCode(), k200OK);
    auto body = json::parse(std::string(resp->getBody()));
    EXPECT_EQ(body["status"], "alive");
}

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new HttpServerEnvironment);
    return RUN_ALL_TESTS();
}
