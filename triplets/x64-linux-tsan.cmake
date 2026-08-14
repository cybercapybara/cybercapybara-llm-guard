# vcpkg overlay triplet: x64-linux, with re2 + abseil compiled under
# ThreadSanitizer.
#
# WHY THIS EXISTS
# The CI `tsan` job builds first-party code with -fsanitize=thread. If it links
# against the ordinary (uninstrumented) dependency tree, TSan cannot see the
# synchronization *inside* those libraries: Abseil's SpinLock/Mutex and RE2's
# lazy-init are built on raw atomics + futexes, not pthread primitives, so
# TSan's interceptors never learn about the happens-before edges they
# establish. Concurrent RE2::Match then reports phantom races in
# absl::synchronization_internal — false positives that make the gate useless.
# Compiling the deps with -fsanitize=thread hands TSan the annotations it needs.
#
# Used only by the `tsan-deps` / `tsan-builder` stages in docker/Dockerfile
# (--overlay-triplets=/app/triplets). Nothing else in the build ever selects
# this triplet, so the plain builder path and its vcpkg binary cache are
# untouched.
#
# Base settings are a verbatim copy of vcpkg's built-in x64-linux triplet —
# keep the linkage identical to the default so the two trees stay ABI-alike.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)

# NOTE: do NOT add `set(VCPKG_BUILD_TYPE release)` here, tempting as it is —
# it halves the cold build, and it breaks the link. vcpkg's libpq wrapper
# (ports/libpq/vcpkg-cmake-wrapper.cmake) attaches the static pgport/pgcommon
# archives to PostgreSQL::PostgreSQL through a pair of generator expressions:
# the release ones guarded by $<$<NOT:$<CONFIG:DEBUG>>:...>, the debug ones
# only if they are found under debug/lib. This tree's one consumer is a
# CMAKE_BUILD_TYPE=Debug build, so with a release-only tree it gets NEITHER,
# and libpq.a fails to link with undefined references to pg_b64_encode,
# pg_hmac_*, scram_*, pg_strcasecmp … (measured, PR #9 run 1). Both variants
# it is, exactly like the plain tree.

# WHY ONLY re2 + abseil, AND NOT THE WHOLE TREE
# Whole-tree instrumentation was tried first (PR #9 run 2) and every port
# compiled and linked fine under -fsanitize=thread — openssl and libpq
# included, so no port had to be excluded for build reasons. What it did do
# was hand TSan a REAL, pre-existing race it had never been able to see:
# civetweb's mg_stop racing its own worker threads on ctx->stop_flag
# (civetweb.c:20369), reached from prometheus::Exposer's ctor/dtor in
# tests/unit/test_observability.cpp. That is an upstream defect in a library
# two dependency hops away, not something this repo can fix, and a gate that
# is red for third-party reasons is a gate people learn to ignore.
#
# Narrowing to re2 + abseil keeps exactly the soundness this triplet exists
# for -- those two are what the scanner runs concurrently, and Abseil's
# ABSL_TSAN_MUTEX_* annotations only compile in when Abseil itself is built
# under TSan -- while leaving every other library exactly as invisible to TSan
# as it was before this triplet existed. Nothing got worse; one thing got
# sound.
#
# Widening later (drogon/trantor, once the SSE work has the unit bucket
# driving an event loop) is a one-line change to the regex below, plus a look
# at whatever new third-party reports it surfaces. The alternative -- keeping
# whole-tree instrumentation and carrying a TSan suppressions file for
# civetweb -- was rejected: a suppression list is a standing invitation to
# silence real findings.
#
# -O1: TSan's own recommendation — keeps the instrumented code fast enough to
#      be usable while preserving frame fidelity.
# -g1: line tables only. Full -g adds gigabytes to the layer (and to the CI
#      cache) for variable/type info no TSan report needs; -g1 still yields
#      file:line in every stack frame.
# -fno-omit-frame-pointer: matches the first-party ENABLE_TSAN flags in
#      CMakeLists.txt so stacks unwind cleanly across the boundary.
# VCPKG_LINKER_FLAGS: ports that link executables during their own build need
#      the runtime on the link line too, or they fail with undefined
#      references to __tsan_*.
#
# This does NOT make the build cheaper than whole-tree: the triplet NAME is
# part of every package's ABI hash, so the entire tree is built fresh either
# way. It is only the instrumentation (and its report surface) that narrows.
if(PORT MATCHES "^(re2|abseil)$")
    set(VCPKG_C_FLAGS "-fsanitize=thread -fno-omit-frame-pointer -O1 -g1")
    set(VCPKG_CXX_FLAGS "-fsanitize=thread -fno-omit-frame-pointer -O1 -g1")
    set(VCPKG_LINKER_FLAGS "-fsanitize=thread")
endif()
