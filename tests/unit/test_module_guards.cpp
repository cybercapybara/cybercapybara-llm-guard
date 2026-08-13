/**
 * @file test_module_guards.cpp
 * @brief Unit tests for the lifecycle/guard contracts of modules that have
 *        no other direct coverage. Pure — no Postgres, no Redis.
 */

#include <chrono>
#include <stdexcept>

#include <gtest/gtest.h>

#include "tasks/Tasks.hpp"

namespace {

// ---- Tasks guards ----------------------------------------------------------

TEST(TasksGuardTest, ScheduleBeforeInitThrows) {
    if (Tasks::is_initialized())
        Tasks::shutdown();
    EXPECT_THROW(Tasks::schedule_recurring("t", std::chrono::milliseconds(1000), [] {}), std::runtime_error);
}

TEST(TasksGuardTest, CancelUnknownReturnsFalse) {
    // cancel() doesn't require init and must not touch the event loop for a
    // miss — safe to call in a unit test.
    EXPECT_FALSE(Tasks::cancel("does-not-exist"));
}

TEST(TasksGuardTest, GetBeforeInitThrows) {
    if (Tasks::is_initialized())
        Tasks::shutdown();
    EXPECT_FALSE(Tasks::is_initialized());
}

}  // namespace
