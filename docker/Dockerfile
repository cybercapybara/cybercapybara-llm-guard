# Multi-stage Dockerfile for llm-guard

ARG APP_BINARY=llm_guard
ARG TEST_BINARY=llm_guard_tests_unit

# Stage 1: Build environment
#
# Split in two: `toolchain` ends with the dependency tree installed but BEFORE
# any source is copied, `builder` adds the sources and compiles. The split is
# purely structural — the layer sequence, and therefore every cache key on the
# builder path, is unchanged — and it exists so the TSan stages further down
# can branch off the deps layer instead of hanging off `builder`. Branching off
# `builder` would put them after `COPY . .`, i.e. every source edit would
# invalidate the ~30-minute instrumented dependency build.
FROM ubuntu:24.04 AS toolchain

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (gcc-13/g++-13 are in noble's main, no PPA needed)
RUN apt-get update && apt-get install -y \
    git \
    pkg-config \
    libssl-dev \
    libcurl4-openssl-dev \
    zlib1g-dev \
    libjsoncpp-dev \
    uuid-dev \
    libpq-dev \
    libhiredis-dev \
    curl \
    wget \
    zip \
    unzip \
    tar \
    autoconf \
    automake \
    libtool \
    bison \
    flex \
    linux-libc-dev \
    gnupg \
    python3 \
    python3-pip \
    ninja-build \
    gcc-13 \
    g++-13 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100 \
    && update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-13 100 \
    && rm -rf /var/lib/apt/lists/*

# Install CMake 3.20+ from Kitware APT repository
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null && \
    echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ noble main' | tee /etc/apt/sources.list.d/kitware.list >/dev/null && \
    apt-get update && \
    apt-get install -y cmake && \
    rm -rf /var/lib/apt/lists/*

# Install vcpkg for dependency management.
# VCPKG_REF pins the vcpkg checkout to a known-good commit so the manifest
# baseline in /app/vcpkg.json resolves identically across machines.
# Override at build time only if you need a newer registry snapshot
# (you'll also want to bump builtin-baseline in vcpkg.json to match).
ARG VCPKG_REF=c4aad2868cfbe7c364192d5de82385647f8425b1
WORKDIR /opt
RUN git clone --filter=blob:none https://github.com/microsoft/vcpkg.git && \
    cd vcpkg && \
    git checkout "$VCPKG_REF" && \
    ./bootstrap-vcpkg.sh

ENV VCPKG_ROOT=/opt/vcpkg
ENV PATH="${VCPKG_ROOT}:${PATH}"

# Manifest mode: copy only vcpkg.json so a source-only change doesn't
# bust this layer.
WORKDIR /app
COPY vcpkg.json ./

# Pre-build the whole dependency set in its own layer, BEFORE the sources
# arrive. This is the ~35-minute part of a cold build; keyed only on
# vcpkg.json it survives every source-only change — both in the local layer
# cache and via CI's gha/GHCR cache-from. --x-install-root matches the CMake
# toolchain default (${CMAKE_BINARY_DIR}/vcpkg_installed), so the configure
# step below finds everything installed and its manifest install is a no-op.
# BuildKit cache mounts keep vcpkg source tarballs and built-package archives
# across builds (and across FAILED builds — without them, one flaky download
# or compile error discards the whole dependency set with the RUN layer).
# The id= carries TARGETARCH: in a multi-arch buildx run both platform legs
# execute concurrently, and an UNSCOPED cache mount is shared between them —
# vcpkg then extracts tools (ninja) into the same path from both legs and one
# leg executes the other's binary (release v1.5.0 failed exactly this way).
ARG TARGETARCH
RUN --mount=type=cache,target=/opt/vcpkg/downloads,id=vcpkg-downloads-${TARGETARCH} \
    --mount=type=cache,target=/root/.cache/vcpkg,id=vcpkg-cache-${TARGETARCH} \
    vcpkg install --x-install-root=/app/build/vcpkg_installed

# Stage 1b: the builder proper — sources on top of the finished toolchain.
FROM toolchain AS builder
ARG TARGETARCH

# Copy source code (after the dep layer, so editing src/ never rebuilds deps).
COPY . .

# Build application — the configure-time manifest install just validates the
# already-populated /app/build/vcpkg_installed from the layer above.
# ENABLE_WERROR=ON activates -Werror for the CI gate (see CMakeLists.txt).
# Pass --build-arg ENABLE_WERROR=ON from CI; defaults to OFF for local builds.
ARG ENABLE_WERROR=OFF

RUN --mount=type=cache,target=/opt/vcpkg/downloads,id=vcpkg-downloads-${TARGETARCH} \
    --mount=type=cache,target=/root/.cache/vcpkg,id=vcpkg-cache-${TARGETARCH} \
    mkdir -p build && cd build && \
    cmake .. \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_WERROR=${ENABLE_WERROR} \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake && \
    cmake --build . --config Release -j$(nproc)

# Stage 2: Test runner (reuses builder, only runs tests)
FROM builder AS test-runner
ARG TEST_BINARY=llm_guard_tests_unit
ENV TEST_BINARY=${TEST_BINARY}

WORKDIR /app

# Create logs directory for observability tests
RUN mkdir -p logs

# Default env vars for Docker network (overridden by docker-compose)
ENV TEST_PG_HOST=localhost
ENV TEST_REDIS_HOST=127.0.0.1

ENTRYPOINT ["sh", "-c", "exec /app/build/$TEST_BINARY \"$@\"", "--"]
CMD ["--gtest_color=yes"]

# Stage 2b: Sanitizer test build (ASan + UBSan)
# Built as its own image layer so CI's test:sanitizers can `--cache-from` it and
# skip the recompile on an unchanged tree (registry-backed → shared across all
# runners; a host ccache can't survive true-dind jobs).
# VCPKG_INSTALLED_DIR reuses the deps the builder already installed under
# /app/build — without it a fresh `cmake -B build-san` would reinstall the whole
# dependency set from source (no binary cache inside the image).
# Reusing an UNINSTRUMENTED dependency tree is sound for ASan/UBSan: both work
# by instrumenting memory accesses in the code under test, and an uninstrumented
# library simply contributes no checks. TSan is different — see the tsan-deps
# stage below, which is why it does NOT reuse this tree.
FROM builder AS sanitizer-builder
# NOTE (council backlog, measured 2026-06): extending ASan to the integration
# bucket here is deferred until T1 Phase 2 (app_core). Compiling the integration
# TUs under ASan — heavy headers, no shared object file — OOM'd an 8 GB buildkit
# VM at ~24/39 (rpc EOF), and would risk the same on CI runners. Once the heavy
# bodies live in a single app_core .cpp, instrumenting them once is cheap; until
# then sanitizers cover the unit bucket only.
RUN cmake -B build-san -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_SANITIZERS=ON \
    -DVCPKG_INSTALLED_DIR=/app/build/vcpkg_installed \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake && \
    cmake --build build-san -j"$(nproc)" --target llm_guard_tests_unit

# Stage 2c: ThreadSanitizer dependency tree.
#
# Unlike ASan, TSan cannot be sound against uninstrumented libraries. Abseil's
# Mutex/SpinLock and RE2's lazy initialisation synchronise through raw atomics
# and futexes rather than pthread primitives, so TSan's interceptors see no
# happens-before edge and report phantom races inside
# absl::synchronization_internal the moment two threads call RE2::Match. The
# only fix is to compile the dependency tree itself with -fsanitize=thread, in
# its OWN install root under its own triplet (triplets/x64-linux-tsan.cmake) —
# the triplet name is part of vcpkg's ABI hash, so this tree can never collide
# with, or invalidate, the plain one in /app/build/vcpkg_installed.
#
# It hangs off `toolchain`, not `builder`: keyed on vcpkg.json + the triplet
# file only, it survives every source-only change exactly like the plain dep
# layer does. Cache mounts get their own -tsan- ids — sharing the plain ids
# would let two concurrently-scheduled stages race on vcpkg's extracted tools
# (the failure mode the id=TARGETARCH comment above describes).
FROM toolchain AS tsan-deps
ARG TARGETARCH
COPY triplets/ /app/triplets/
RUN --mount=type=cache,target=/opt/vcpkg/downloads,id=vcpkg-downloads-tsan-${TARGETARCH} \
    --mount=type=cache,target=/root/.cache/vcpkg,id=vcpkg-cache-tsan-${TARGETARCH} \
    vcpkg install \
    --triplet x64-linux-tsan \
    --overlay-triplets=/app/triplets \
    --x-install-root=/app/build-tsan/vcpkg_installed

# Stage 2d: ThreadSanitizer test build.
# Also branches off `toolchain` rather than `builder` — the tsan job has no use
# for the Release binaries the builder stage produces, and skipping them saves a
# full app compile per run. The instrumented tree is copied in from tsan-deps.
FROM toolchain AS tsan-builder
ARG TARGETARCH
COPY --from=tsan-deps /app/build-tsan/vcpkg_installed /app/build-tsan/vcpkg_installed
COPY . .
# VCPKG_TARGET_TRIPLET + VCPKG_OVERLAY_TRIPLETS make the configure-time manifest
# install resolve to the already-populated instrumented tree (a no-op), and make
# find_package() look under vcpkg_installed/x64-linux-tsan. The cache mounts are
# insurance: if that install ever decides to rebuild something, it restores from
# the binary cache instead of recompiling a port under TSan.
RUN --mount=type=cache,target=/opt/vcpkg/downloads,id=vcpkg-downloads-tsan-${TARGETARCH} \
    --mount=type=cache,target=/root/.cache/vcpkg,id=vcpkg-cache-tsan-${TARGETARCH} \
    cmake -B build-tsan -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_TSAN=ON \
    -DVCPKG_TARGET_TRIPLET=x64-linux-tsan \
    -DVCPKG_OVERLAY_TRIPLETS=/app/triplets \
    -DVCPKG_INSTALLED_DIR=/app/build-tsan/vcpkg_installed \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake && \
    cmake --build build-tsan -j"$(nproc)" --target llm_guard_tests_unit

# Stage 3: Shared runtime base
FROM ubuntu:24.04 AS runtime-base

# Runtime dependencies (noble ships GCC 13 libstdc++ in main, no PPA needed).
# t64 transition renamed libssl3 → libssl3t64 and libhiredis0.14 → libhiredis1.1.0.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    libssl3t64 \
    libpq5 \
    libhiredis1.1.0 \
    libjsoncpp25 \
    libcurl4t64 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
    # ca-certificates: --no-install-recommends skips it, and without the CA
    # bundle every outbound TLS from the app fails (curl: "Problem with the
    # SSL CA cert").

# Create app user (noble's base image already has uid 1000 "ubuntu" — drop it first)
RUN userdel -r ubuntu 2>/dev/null || true && \
    useradd -m -u 1000 appuser && \
    mkdir -p /app/logs /app/config && \
    chown -R appuser:appuser /app

WORKDIR /app

# Stage 4: API runtime
FROM runtime-base AS runtime
ARG APP_BINARY=llm_guard
ENV APP_BINARY=${APP_BINARY}

COPY --from=builder --chown=appuser:appuser /app/build/${APP_BINARY} /app/
COPY --from=builder --chown=appuser:appuser /app/config /app/config/
COPY --from=builder --chown=appuser:appuser /app/migrations /app/migrations/

USER appuser

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["sh", "-c", "exec /app/$APP_BINARY \"$@\"", "--"]
CMD ["config/config.json"]
