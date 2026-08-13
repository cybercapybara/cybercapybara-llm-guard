# C++ API Template — Docker Compose shortcuts
# Usage: make up | make up-full | make down | make test | make logs

-include project.env
PROJECT_NAME ?= llm-guard
REGISTRY     ?= docker.io/library
# Minimum src/ LINE coverage for `make coverage` to pass — a regression floor,
# not a target. Start conservative; raise it once you've measured your real
# number (run `make coverage` and read the printed summary). Override per-run:
# `make coverage COVERAGE_MIN=55`.
COVERAGE_MIN ?= 54

IMAGE     := $(REGISTRY)/$(PROJECT_NAME)
GIT_SHA   := $(shell git rev-parse --short HEAD)
# GHCR namespace where builder-cache.yml publishes the builder stage.
# Override via GHCR_ORG in project.env if your fork lives under a different org.
GHCR_ORG  ?= cybercapybara
GHCR_REPO := ghcr.io/$(GHCR_ORG)/$(PROJECT_NAME)
# Canonical upstream template cache — a fresh fork's own GHCR is empty until its
# CI runs, so `make warm-cache` falls back here to skip the first cold build.
UPSTREAM_GHCR ?= ghcr.io/cybercapybara/llm-guard

# Prefer the Compose v2 plugin (`docker compose`) when present; fall back to
# the standalone v1 binary. CI images ship only the plugin, older dev
# machines only the binary — hardcoding either breaks the other.
COMPOSE_BIN := $(shell docker compose version >/dev/null 2>&1 && echo docker compose || echo docker-compose)
COMPOSE := $(COMPOSE_BIN) -f docker/docker-compose.yml
# Every optional profile — for targets that must see the WHOLE stack
# (down/ps/up-everything). Keep in sync with docker-compose.yml profiles.
ALL_PROFILES := --profile with-monitoring
ENV     := --env-file docker/.env

.PHONY: up up-pull up-monitoring up-build quickstart dev down down-v dev-reset \
        test test-unit test-quick test-e2e test-local test-unit-local test-integration-local test-watch \
        build build-local warm-cache configure-local compile-commands \
        watch coverage \
        logs logs-pretty tail-trace ps health routes doctor env-check prod-check \
        psql redis-cli redis-flush migrate migrate-local migrate-status migrate-reset \
        new-endpoint new-migration ci-local helm-lint helm-validate \
        bench bench-all image push \
        fmt lint-format lint-format-fix lint tidy lint-openapi \
        smoke clean clean-logs clean-docs clean-build dist-clean \
        help

# ── Startup targets ──────────────────────────────────────────────

# up-* targets PULL the prebuilt public image that CI publishes on master, then
# start — no local compile on your mac.
# Infra images (postgres/redis) pull as usual; the app uses `--pull
# missing` so a fork that built its own image (or renamed it) isn't clobbered by
# the upstream `:latest` — and a fresh clone gets a clear "build it" error rather
# than silently running someone else's binary. `make up-pull` force-refreshes the
# upstream images; `make quickstart` / `make up-build` build your own code.
up:                ## Base stack (app + PostgreSQL + Redis)
	$(COMPOSE) $(ENV) up -d --pull missing

up-pull:           ## Like `up` but force-pull the upstream public images (refresh :latest)
	$(COMPOSE) $(ENV) up -d --pull always

up-monitoring:     ## + Prometheus + Grafana + Jaeger
	$(COMPOSE) --env-file docker/.env.monitoring --profile with-monitoring up -d --pull missing

up-build:          ## Like up-monitoring but BUILD the app image locally (no pull) — for local code changes
	$(COMPOSE) --env-file docker/.env.monitoring $(ALL_PROFILES) up -d --build

quickstart:        ## One-shot: BUILD your code + Postgres + Redis, wait for ready, hit / and /healthz
	$(COMPOSE) $(ENV) up -d --build
	@echo "==> Waiting for /healthz (up to 60s)"
	@for i in $$(seq 1 30); do \
	    if curl -fsS -o /dev/null http://localhost:8080/healthz; then break; fi; \
	    sleep 2; \
	done
	@echo "==> GET /"
	@curl -fsS http://localhost:8080/ | head -60 || true
	@echo
	@echo "==> GET /healthz"
	@curl -fsS http://localhost:8080/healthz
	@echo
	@echo "==> Ready. Tail logs with: make logs"
	@echo "    Metrics: http://localhost:9090/metrics"

dev:               ## Rebuild the app image and recreate only the app container
	$(COMPOSE) $(ENV) build app
	$(COMPOSE) $(ENV) up -d --no-deps --force-recreate app
	@echo "==> app restarted; logs: make logs"

# ── Shutdown targets ─────────────────────────────────────────────

down:              ## Stop all containers
	$(COMPOSE) $(ALL_PROFILES) down

down-v:            ## Stop all + remove volumes
	$(COMPOSE) $(ALL_PROFILES) down -v

dev-reset: down-v  ## Nuke volumes + logs and bring the base stack back up
	@find logs -mindepth 1 -not -name '.gitkeep' -delete 2>/dev/null || true
	$(MAKE) up

# ── Development targets ──────────────────────────────────────────

test:              ## Run all tests in Docker (rebuild image, ~2 min cold)
	@# `run --rm` instead of `up --abort-on-container-exit`: abort stops EVERY
	@# container in the compose project — including a dev stack you have up.
	$(COMPOSE) $(ENV) --profile test build test-runner
	$(COMPOSE) $(ENV) --profile test run --rm -e TEST_BINARY=llm_guard_tests_unit test-runner
	$(COMPOSE) $(ENV) --profile test run --rm -e TEST_BINARY=llm_guard_tests_integration test-runner
	@$(MAKE) --no-print-directory test-e2e

test-e2e:          ## Run the HTTP end-to-end binary (real Drogon server + client)
	$(COMPOSE) $(ENV) --profile test run --rm -e TEST_BINARY=llm_guard_e2e test-runner

test-quick:        ## Re-run tests against existing image (no rebuild, ~5 s)
	@# Fast TDD loop: rebuild the test-runner layer only if it already exists,
	@# otherwise fall through to the full `make test`. Good for "edit test, run".
	@if docker image inspect $${TEST_IMAGE:-llm-guard:test-latest} >/dev/null 2>&1; then \
		$(COMPOSE) $(ENV) --profile test run --rm -e TEST_BINARY=llm_guard_tests_unit test-runner && \
		$(COMPOSE) $(ENV) --profile test run --rm -e TEST_BINARY=llm_guard_tests_integration test-runner ; \
	else \
		echo "No cached test-runner image, doing a full build first..." ; \
		$(MAKE) test ; \
	fi

test-unit:         ## Run only unit tests (no Postgres/Redis needed at runtime)
	$(COMPOSE) $(ENV) --profile test run --rm -e TEST_BINARY=llm_guard_tests_unit test-runner

lint-format:       ## Check clang-format compliance across src/ and tests/
	@if command -v clang-format >/dev/null 2>&1; then \
		find src tests -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.h' \) \
			-exec clang-format --dry-run --Werror --style=file {} + ; \
	else \
		echo "Using dockerized clang-format (silkeh/clang:17)" ; \
		docker run --rm -v $(PWD):/app -w /app silkeh/clang:17 \
			bash -c "find src tests -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.h' \) | xargs clang-format --dry-run --Werror --style=file" ; \
	fi

lint-format-fix:   ## Rewrite src/ and tests/ in place using clang-format
	@if command -v clang-format >/dev/null 2>&1; then \
		find src tests -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.h' \) \
			-exec clang-format -i --style=file {} + ; \
	else \
		docker run --rm -v $(PWD):/app -w /app silkeh/clang:17 \
			bash -c "find src tests -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.h' \) | xargs clang-format -i --style=file" ; \
	fi

fmt: lint-format-fix  ## Shorthand: rewrite all source files with clang-format

lint: lint-format  ## Shorthand: check formatting compliance

lint-openapi:      ## Run spectral lint over docs/openapi.yaml
	@./scripts/lint-openapi.sh

ci-local:          ## Reproduce CI locally: format check + drift + spectral + tidy + tests
	@echo "==> [1/6] clang-format check"
	@$(MAKE) --no-print-directory lint-format
	@echo "==> [2/6] OpenAPI drift + routes registered"
	@./scripts/check-openapi-drift.sh
	@./scripts/check-routes-registered.sh
	@echo "==> [3/6] helm render validate"
	@$(MAKE) --no-print-directory helm-validate
	@echo "==> [4/6] spectral lint"
	@$(MAKE) --no-print-directory lint-openapi
	@echo "==> [5/6] clang-tidy (best-effort)"
	@$(MAKE) --no-print-directory tidy || echo "(tidy skipped or noisy — not gating)"
	@echo "==> [6/6] full test suite"
	@$(MAKE) --no-print-directory test
	@echo "==> ci-local: all checks passed"

helm-lint:         ## helm lint + helm template render for both charts
	@command -v helm >/dev/null 2>&1 || { echo "helm not installed — brew install helm"; exit 1; }
	@for chart in helm/*/; do \
		if [ -f "$$chart/Chart.yaml" ]; then \
			echo "==> helm lint $$chart" ; \
			helm lint "$$chart" || exit 1 ; \
			echo "==> helm template $$chart (smoke)" ; \
			helm template _smoke "$$chart" >/dev/null || exit 1 ; \
		fi ; \
	done
	@echo "==> helm-lint: all charts pass"

helm-validate:     ## Render the cpp-env umbrella + assert deploy-path invariants (port/host/probes)
	@./scripts/check-helm-render.sh

tidy:              ## Run clang-tidy via the builder image (CI-parity)
	@echo "Running clang-tidy inside the builder image (may take a few minutes)..."
	@$(COMPOSE) $(ENV) build app >/dev/null 2>&1 || true
	@docker image inspect $(IMAGE):$(GIT_SHA) >/dev/null 2>&1 || { \
		echo "ERROR: image $(IMAGE):$(GIT_SHA) not found — run 'make image' first." >&2 ; exit 1 ; }
	docker run --rm -v $(PWD):/app -w /app --entrypoint /bin/bash \
		$(IMAGE):$(GIT_SHA) -c "apt-get update -qq && apt-get install -y -qq clang-tidy \
			&& run-clang-tidy -p build -quiet -header-filter='src/.*' src/"

warm-cache:        ## Pull a CI-built builder image to skip the cold vcpkg build (~30 min -> ~3)
	@# Try the fork's own GHCR first, then fall back to the upstream template
	@# cache (a fresh fork's GHCR is empty until its first CI run). Same vcpkg
	@# dependency layers, so either primes the build.
	@for ref in $(GHCR_REPO)/builder:cache $(UPSTREAM_GHCR)/builder:cache ; do \
		echo "Trying $$ref ..." ; \
		if docker pull "$$ref" 2>/dev/null ; then \
			docker tag "$$ref" llm-guard:builder-latest ; \
			echo "==> Cache primed from $$ref — make build / make test reuse the dependency layers." ; \
			exit 0 ; \
		fi ; \
	done ; \
	echo "==> No prebuilt builder cache (tried fork + upstream) — builds compile deps from source (~30 min cold; needs a Docker VM with >=8GiB, see 'make doctor')."

build:             ## Rebuild app image only
	$(COMPOSE) $(ENV) build app

logs:              ## Tail app logs
	$(COMPOSE) logs -f app

logs-pretty:       ## Tail app logs through jq (best-effort; falls back to plain)
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq not installed — falling back to plain logs"; \
		$(COMPOSE) logs -f --no-log-prefix app; \
	else \
		$(COMPOSE) logs -f --no-log-prefix app | \
			jq -rR 'fromjson? // .' 2>/dev/null; \
	fi

tail-trace:        ## Filter app logs by trace id: make tail-trace TID=<id>
	@if [ -z "$(TID)" ]; then echo "Usage: make tail-trace TID=<trace-id>"; exit 1; fi
	$(COMPOSE) logs -f --no-log-prefix app | grep --line-buffered -E "(tid=$(TID)|trace_id=$(TID)|\"trace.id\":\"$(TID)\")"

ps:                ## Show running containers
	$(COMPOSE) $(ALL_PROFILES) ps

# ── Local toolchain shortcuts (no Docker rebuild) ────────────────
# These targets target the local host: configure once with a CMake preset,
# then build/test against it. Uses CMakePresets.json (dev / dev-asan /
# coverage / release) so cmake invocations stay short.

configure-local:   ## cmake configure with the `dev` preset (Debug, vcpkg toolchain)
	@command -v cmake >/dev/null 2>&1 || { echo "cmake missing — install it (brew install cmake / apt install cmake)"; exit 1; }
	@if [ -z "$${VCPKG_ROOT:-}" ]; then echo "ERROR: set VCPKG_ROOT before running this (point at your vcpkg checkout)"; exit 2; fi
	cmake --preset $(or $(PRESET),dev)

compile-commands:  ## Generate compile_commands.json (for clangd/IDE) and symlink to repo root
	@$(MAKE) --no-print-directory configure-local PRESET=$(or $(PRESET),dev)
	@ln -sf "build/$(or $(PRESET),dev)/compile_commands.json" compile_commands.json
	@echo "==> compile_commands.json -> build/$(or $(PRESET),dev)/compile_commands.json"

build-local:       ## Build native binaries via the `dev` preset (no Docker)
	@$(MAKE) --no-print-directory compile-commands PRESET=$(or $(PRESET),dev)
	cmake --build --preset $(or $(PRESET),dev) -j

test-local:        ## Run native gtest binary; pass NAME=<filter> to scope: make test-local NAME=Pagination*
	@$(MAKE) --no-print-directory build-local PRESET=$(or $(PRESET),dev)
	@./build/$(or $(PRESET),dev)/llm_guard_tests_unit \
		--gtest_color=yes \
		$(if $(NAME),--gtest_filter=$(NAME))
	@./build/$(or $(PRESET),dev)/llm_guard_tests_integration \
		--gtest_color=yes \
		$(if $(NAME),--gtest_filter=$(NAME))

test-unit-local:   ## Run only unit tests natively (no Postgres/Redis required)
	@$(MAKE) --no-print-directory build-local PRESET=$(or $(PRESET),dev)
	@./build/$(or $(PRESET),dev)/llm_guard_tests_unit \
		--gtest_color=yes

test-integration-local: ## Run only integration tests natively (needs the stack: make up)
	@$(MAKE) --no-print-directory build-local PRESET=$(or $(PRESET),dev)
	@TEST_PG_HOST=$${TEST_PG_HOST:-127.0.0.1} \
	 TEST_REDIS_HOST=$${TEST_REDIS_HOST:-127.0.0.1} \
	 ./build/$(or $(PRESET),dev)/llm_guard_tests_integration \
		--gtest_color=yes

test-watch:        ## Re-run unit tests on src/ or tests/ change (watchexec or entr)
	@if command -v watchexec >/dev/null 2>&1; then \
		watchexec -e hpp,cpp,h -w src -w tests -- $(MAKE) test-unit-local ; \
	elif command -v entr >/dev/null 2>&1; then \
		find src tests -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.h' \) \
			| entr -r $(MAKE) test-unit-local ; \
	else \
		echo "ERROR: install watchexec (brew install watchexec) or entr (brew install entr) first" >&2 ; \
		exit 1 ; \
	fi

watch:             ## Rebuild + restart on src/ change (needs entr or watchexec)
	@if command -v watchexec >/dev/null 2>&1; then \
		watchexec -e hpp,cpp,h,json -w src -w config -- $(MAKE) dev ; \
	elif command -v entr >/dev/null 2>&1; then \
		find src config -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.h' -o -name '*.json' \) \
			| entr -r $(MAKE) dev ; \
	else \
		echo "ERROR: install watchexec (brew install watchexec) or entr (brew install entr) first" >&2 ; \
		exit 1 ; \
	fi

coverage:          ## Build with coverage, run tests, emit HTML + fail under COVERAGE_MIN% line coverage
	@command -v gcovr >/dev/null 2>&1 || { echo "gcovr missing — pip install gcovr"; exit 1; }
	cmake --preset coverage
	cmake --build --preset coverage -j
	@# Run EVERY bucket, not just unit — otherwise the report counts only the
	@# unit-reachable code and badly understates the DB / cache
	@# paths that ONLY the integration + e2e buckets exercise. integration/e2e
	@# need Postgres + Redis (run `make up` first); each is `|| true` so a missing
	@# sidecar degrades the number instead of aborting the whole report.
	@echo "==> running all test buckets (integration/e2e need Postgres+Redis — make up first)"
	@./build/coverage/llm_guard_tests_unit --gtest_color=yes || true
	@./build/coverage/llm_guard_tests_integration --gtest_color=yes || true
	@./build/coverage/llm_guard_e2e --gtest_color=yes || true
	@mkdir -p coverage
	@# --fail-under-line makes this a gate: gcovr exits non-zero (failing the
	@# target / CI) when src/ line coverage drops below COVERAGE_MIN. A floor,
	@# not a ceiling — bump COVERAGE_MIN as real coverage climbs.
	gcovr -r . --filter 'src/.*' --html-details coverage/index.html --print-summary \
		--fail-under-line $(COVERAGE_MIN)
	@echo "==> open coverage/index.html (line floor: $(COVERAGE_MIN)%)"

# ── Inspection / health ──────────────────────────────────────────

routes:            ## Print the registered endpoint table (no DB required)
	@$(COMPOSE) exec app ./llm_guard --print-routes 2>/dev/null || \
	    ./build/dev/llm_guard --print-routes 2>/dev/null || \
	    { echo 'ERROR: neither a running container nor a local build was found. Try make up or make build-local.'; exit 1; }

health:             ## curl /healthz, /ready, and tease /metrics
	@printf '\n== /healthz ==\n'  ; curl -fsS http://localhost:8080/healthz  || echo
	@printf '\n== /ready ==\n'    ; curl -fsS http://localhost:8080/ready    || echo
	@printf '\n== /metrics (head) ==\n' ; curl -fsS http://localhost:9090/metrics 2>/dev/null | head -10 || echo '(not running)'

doctor:            ## Sanity-check the local toolchain
	@printf 'docker:      ' ; command -v docker     >/dev/null && docker --version     || echo MISSING
	@printf 'docker compose: ' ; (docker compose version 2>/dev/null || command -v docker-compose >/dev/null && docker-compose --version) || echo MISSING
	@printf 'docker memory: ' ; mem=$$(docker info --format '{{.MemTotal}}' 2>/dev/null) ; \
		if [ -n "$$mem" ] && [ "$$mem" -gt 0 ] 2>/dev/null ; then \
			gib=$$(( mem / 1073741824 )) ; \
			if [ "$$gib" -lt 6 ] ; then \
				echo "$${gib}GiB — TOO LOW. The cold vcpkg build OOMs the buildkit VM and shows up as 'EOF' / 'rpc Unavailable' (looks like a code bug). Give the VM >=8GiB, e.g. 'colima stop && colima start --cpu 4 --memory 8', then 'make warm-cache'." ; \
			else echo "$${gib}GiB OK" ; fi ; \
		else echo "(docker not running)" ; fi
	@printf 'cmake:       ' ; command -v cmake      >/dev/null && cmake --version | head -1 || echo MISSING
	@printf 'ninja:       ' ; command -v ninja      >/dev/null && ninja --version           || echo MISSING
	@printf 'g++:         ' ; command -v g++        >/dev/null && g++ --version | head -1   || echo "(optional, use Docker)"
	@printf 'clang-format: ' ; command -v clang-format >/dev/null && clang-format --version || echo "(optional, Docker fallback)"
	@printf 'clang-tidy:  ' ; command -v clang-tidy >/dev/null && clang-tidy --version | head -1 || echo "(optional, Docker fallback)"
	@printf 'jq:          ' ; command -v jq         >/dev/null && jq --version            || echo "(optional, used by logs-pretty)"
	@printf 'gcovr:       ' ; command -v gcovr      >/dev/null && gcovr --version | head -1 || echo '(optional, used by make coverage)'
	@printf 'wrk:         ' ; command -v wrk        >/dev/null && wrk --version 2>&1 | head -1 || echo '(optional, used by make bench)'
	@printf 'watchexec:   ' ; command -v watchexec  >/dev/null && watchexec --version | head -1 || echo '(optional, used by make watch)'
	@printf 'VCPKG_ROOT:  ' ; if [ -n "$${VCPKG_ROOT:-}" ]; then echo "$$VCPKG_ROOT"; else echo "(optional, required only for build-local)"; fi

# ── Database / cache shortcuts ───────────────────────────────────

psql:              ## Open a psql shell against the running postgres container
	$(COMPOSE) exec postgres psql -U postgres -d appdb

redis-cli:         ## Open redis-cli against the running redis container
	$(COMPOSE) exec redis redis-cli

redis-flush:       ## FLUSHDB on the dev redis (won't touch test-redis)
	$(COMPOSE) exec redis redis-cli FLUSHDB

migrate:           ## Apply pending migrations using the running app container (RUN_MIGRATIONS_ONLY=1)
	$(COMPOSE) run --rm -e RUN_MIGRATIONS_ONLY=1 app

migrate-local:     ## Apply pending migrations natively (requires build-local + reachable Postgres)
	@if [ ! -x ./build/$(or $(PRESET),dev)/llm_guard ]; then \
		echo "==> No native build at build/$(or $(PRESET),dev)/ — running build-local first"; \
		$(MAKE) --no-print-directory build-local PRESET=$(or $(PRESET),dev); \
	fi
	./build/$(or $(PRESET),dev)/llm_guard --run-migrations $(or $(CONFIG),config/config.json)

migrate-status:    ## List pending migrations without applying (exits 1 if any pending)
	$(COMPOSE) run --rm app --verify-migrations || true

migrate-reset:     ## DESTRUCTIVE: drop the appdb schema and re-apply all migrations
	@printf '\e[31mThis will DROP every table in appdb. Type "yes" to continue:\e[0m '
	@read confirm && [ "$$confirm" = yes ] || { echo "aborted"; exit 1; }
	$(COMPOSE) exec postgres psql -U postgres -d appdb -c \
		"DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO postgres; GRANT ALL ON SCHEMA public TO public;"
	$(MAKE) migrate

prod-check:        ## Validate production config + env semantics (docs off, JSON logs, secrets)
	@./scripts/prod-check.sh config/config.production.json

env-check:         ## Verify required env vars referenced in config/config.json are set
	@./scripts/env-check.sh $(or $(CONFIG),config/config.json)

new-endpoint:      ## Scaffold a controller: make new-endpoint NAME=Orders METHOD=Get PATH=/api/orders [WITH_TEST=1] [PATCH_OPENAPI=1]
	@if [ -z "$(NAME)" ] || [ -z "$(METHOD)" ] || [ -z "$(PATH_)" ]; then \
		echo "Usage: make new-endpoint NAME=OrdersController METHOD=Get PATH_=/api/orders [WITH_TEST=1] [PATCH_OPENAPI=1]"; \
		echo "(uses PATH_ instead of PATH because Make's PATH is the shell PATH)"; \
		exit 1; \
	fi
	./scripts/new-endpoint.sh \
		$(if $(WITH_TEST),--with-test) \
		$(if $(PATCH_OPENAPI),--patch-openapi) \
		$(NAME) $(METHOD) $(PATH_)

new-migration:     ## Generate the next migrations/NNN_<slug>.sql: make new-migration SLUG=add_users
	@if [ -z "$(SLUG)" ]; then echo "Usage: make new-migration SLUG=<short_description>"; exit 1; fi
	./scripts/new-migration.sh $(SLUG)

init:              ## Rebrand the template for your fork: make init NAME=my-service [REGISTRY=docker.io/myorg]
	@if [ -z "$(NAME)" ]; then echo "Usage: make init NAME=my-service [REGISTRY=docker.io/myorg]"; exit 1; fi
	./scripts/init-project.sh $(NAME) $(REGISTRY)

bench:             ## Run benchmark with a preset: make bench P=baseline E=/healthz
	./scripts/bench.sh $(or $(P),baseline) $(or $(E),/healthz)

bench-all:         ## Run all benchmark presets against an endpoint: make bench-all E=/healthz
	./scripts/bench.sh all $(or $(E),/healthz)

# ── Image targets ───────────────────────────────────────────────

image:             ## Build and tag the app Docker image
	docker build --target runtime -f docker/Dockerfile \
		-t $(IMAGE):$(GIT_SHA) -t $(IMAGE):latest .

push:              ## Push Docker images to registry
	@if [ "$(REGISTRY)" = "docker.io/library" ]; then \
		echo "ERROR: REGISTRY is the default docker.io/library (the official-images namespace)." >&2 ; \
		echo "       Set REGISTRY=<your registry/namespace> in project.env or the environment." >&2 ; \
		exit 1 ; \
	fi
	docker push $(IMAGE):$(GIT_SHA)
	docker push $(IMAGE):latest

# ── Smoke dev helper ─────────────────────────────────────────────

smoke:             ## curl the running stack through the health/meta endpoints
	./scripts/smoke.sh

# ── Cleanup ──────────────────────────────────────────────────────

clean-build:       ## Remove the local build/ directory
	rm -rf build compile_commands.json

clean-logs:        ## Truncate the logs/ directory (keeps .gitkeep)
	@find logs -mindepth 1 -not -name '.gitkeep' -delete 2>/dev/null || true
	@echo "==> logs/ cleared"

clean-docs:        ## Remove generated Doxygen output (docs/html, docs/latex, docs/xml)
	rm -rf docs/html docs/latex docs/xml

clean: clean-build clean-logs clean-docs  ## Remove build/, logs (except .gitkeep), and Doxygen output

dist-clean: clean  ## clean + drop vcpkg_installed and coverage report
	rm -rf vcpkg_installed coverage

# ── Help ─────────────────────────────────────────────────────────

help:              ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
