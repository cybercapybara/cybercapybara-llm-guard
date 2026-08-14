/**
 * @file test_guard_scanner_concurrency.cpp
 * @brief Many threads matching the SAME compiled RE2 objects at once.
 *
 * This is the test the CI `tsan` job exists for, and the reason that job
 * links a dependency tree compiled with -fsanitize=thread
 * (triplets/x64-linux-tsan.cmake, docker/Dockerfile stage `tsan-deps`).
 *
 * A `const RE2` is documented as safe to match from several threads at once:
 * the DFA state cache it mutates behind that const is guarded by an internal
 * `absl::Mutex`. TSan only knows that if Abseil itself was instrumented --
 * Abseil's Mutex/SpinLock establish their happens-before edges with raw
 * atomics and futexes, not the pthread primitives TSan intercepts, and its
 * annotations (`ABSL_TSAN_MUTEX_*`) compile to nothing unless the library is
 * built under TSan. Against an uninstrumented Abseil this suite reports
 * phantom races inside `absl::synchronization_internal`; against the
 * instrumented tree it is clean, and a REAL race in the scanner still fails
 * the job.
 *
 * The scanner's other concurrency path (`detail::scan_parallel`) is covered
 * in test_guard_scanner.cpp, but it buckets rules across workers so each RE2
 * is touched by exactly one thread -- it never exercises the shared-object
 * case this suite pins.
 */

#include <atomic>
#include <cstddef>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "guard/Registry.hpp"
#include "guard/Rule.hpp"
#include "guard/Scanner.hpp"

namespace {

Guard::Rule make_concurrency_rule(std::string id, std::string regex) {
    Guard::Rule r;
    r.id = std::move(id);
    r.name = r.id;
    r.data_type = Guard::DataType::Custom;
    r.regex = std::move(regex);
    r.masking.placeholder = "TEST";
    return r;
}

}  // namespace

TEST(GuardScannerConcurrency, SharedCompiledRulesMatchedFromManyThreads) {
    std::vector<Guard::Rule> defs;
    defs.push_back(make_concurrency_rule("rule-token", "sk-[a-z0-9]+"));
    defs.push_back(make_concurrency_rule("rule-card", "[0-9]{16}"));
    defs.push_back(make_concurrency_rule("rule-email", "[a-z]+@[a-z]+\\.com"));

    auto registry = Guard::Registry::build(defs);
    ASSERT_NE(registry, nullptr);

    std::vector<const Guard::CompiledRule*> rules;
    rules.reserve(defs.size());
    for (const auto& d : defs) {
        const Guard::CompiledRule* cr = registry->by_id(d.id);
        ASSERT_NE(cr, nullptr);
        rules.push_back(cr);
    }

    // Three rules and a short text keep this on scan_rules' serial path, so
    // every worker below runs all three RE2 objects itself -- the point of
    // the exercise. Each rule matches exactly once, none of the spans
    // overlap, so resolve_conflicts coalesces nothing.
    const std::string text = "token sk-abc123 card 4111111111111111 mail alice@example.com end";
    const std::size_t expected = Guard::scan_rules(text, rules).size();
    ASSERT_EQ(expected, 3u);

    constexpr int kThreads = 8;
    constexpr int kIterations = 200;

    // Worker threads record disagreement in an atomic flag instead of calling
    // gtest assertion macros, which are not safe off the main thread.
    std::atomic<bool> mismatched{false};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&rules, &text, &mismatched, expected]() {
            for (int n = 0; n < kIterations; ++n) {
                if (Guard::scan_rules(text, rules).size() != expected)
                    mismatched.store(true, std::memory_order_relaxed);
            }
        });
    }
    for (auto& t : workers)
        t.join();

    EXPECT_FALSE(mismatched.load());
}
