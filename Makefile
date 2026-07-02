# Single source of truth for how tests and gates run.
#
# .github/workflows/ci.yml invokes these targets directly (make test-cover,
# make smoke, make integration, make fuzz-smoke, make docs-drift, make
# tidy-check, make vuln) so local and CI run byte-for-byte the same commands.
# The only CI jobs that don't shell out to make are `lint` (uses the
# golangci-lint action for PR-diff `only-new-issues` behavior; `make lint` is
# the local equivalent) and `docker` (uses buildx layer caching; `make
# ci-docker` is the local equivalent).
#
# `make ci` runs the subset of jobs that don't need external services and
# should match the gating PR check most contributors care about (lint, tidy,
# vuln, build, unit tests, smoke, integration with stubs, fuzz smoke).
#
# `make ci-full` adds the real-backend integration tests using the local
# docker-compose stack (postgres). `make ci-docker` covers the container
# build smoke.
#
# Tool versions are pinned to match CI; see GOLANGCI_LINT_VERSION /
# GOVULNCHECK_VERSION below. Bump them in lockstep with the workflow.

SHELL := /bin/bash

GOLANGCI_LINT_VERSION ?= v2.12.1
GOVULNCHECK_VERSION   ?= v1.1.4

GO              ?= go
GOLANGCI_LINT   ?= golangci-lint
GOVULNCHECK     ?= govulncheck
BUF             ?= buf

# CI uses --new-from-rev against the merge base; locally we diff against
# origin/main so contributors only see issues their branch introduced.
LINT_BASE_REV   ?= origin/main

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Aggregate targets
# ---------------------------------------------------------------------------

.PHONY: ci
ci: lint tidy-check vuln build test smoke integration fuzz-smoke ## Run all CI gates that don't need external services
	@echo "==> make ci: all gates passed"

.PHONY: ci-full
ci-full: ci ci-real-services ## ci + integration tests against the real docker-compose backends
	@echo "==> make ci-full: passed (incl. real services)"

.PHONY: ci-real-services
ci-real-services: services-up realpostgres services-down ## Run realpostgres tests against compose
	@echo "==> real-services tests passed"

.PHONY: ci-docker
ci-docker: ## Container build smoke (mirrors the docker CI job)
	docker build --target server -t workspaces:ci .
	@echo "==> docker build smoke passed"

# ---------------------------------------------------------------------------
# Individual gates — each maps to one job in .github/workflows/ci.yml
# ---------------------------------------------------------------------------

.PHONY: lint
lint: ## golangci-lint, only new issues vs $(LINT_BASE_REV)
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "golangci-lint not installed. Run 'make install-tools' or:"; \
		echo "  brew install golangci-lint   # or"; \
		echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"; \
		exit 1; \
	}
	$(GOLANGCI_LINT) run --config=.golangci.yml --new-from-rev=$(LINT_BASE_REV) ./...

.PHONY: lint-all
lint-all: ## golangci-lint over the entire tree (no new-from-rev gating)
	$(GOLANGCI_LINT) run --config=.golangci.yml ./...

.PHONY: tidy
tidy: ## Run go mod tidy in place
	$(GO) mod tidy

.PHONY: tidy-check
tidy-check: ## Verify go.mod / go.sum are already tidy
	$(GO) mod tidy
	@if ! git diff --exit-code -- go.mod go.sum; then \
		echo "go.mod / go.sum out of sync — run 'make tidy' and commit the result." >&2; \
		exit 1; \
	fi

.PHONY: vuln
vuln: ## govulncheck against the configured CVE database
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || { \
		echo "govulncheck not installed. Run 'make install-tools' or:"; \
		echo "  go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)"; \
		exit 1; \
	}
	$(GOVULNCHECK) ./...

.PHONY: build
build: ## go build ./...
	$(GO) build ./...

.PHONY: test
test: ## Unit tests with race detector
	$(GO) test -count=1 -race -timeout=1200s ./...

.PHONY: test-postgres-local
test-postgres-local: services-up ## Postgres-driver tests against the local docker-compose postgres (additive; brings up compose, sets the DSN)
	GATEWAY_TEST_POSTGRES_DSN=postgres://workspaces:workspaces@localhost:5432/workspaces?sslmode=disable \
		$(GO) test -race -timeout=300s ./internal/repo/postgres/...

.PHONY: test-cover
test-cover: ## Unit+e2e tests, merged coverage, skip-guard (when a test DSN is set), per-package gates — the CI "Build + Test + Coverage" job
	bash scripts/run-coverage.sh
	@if [ -n "$$GATEWAY_TEST_POSTGRES_DSN$$WORKSPACES_TEST_POSTGRES_DSN" ]; then \
		echo "==> test DSN set — verifying the Postgres suite actually runs (no silent skip)"; \
		out=$$($(GO) test -count=1 -run . -v ./internal/repo/postgres/... 2>&1); \
		echo "$$out"; \
		if grep -qE '^--- SKIP|^=== SKIP|no tests to run' <<<"$$out"; then \
			echo "::error::Postgres tests SKIPPED while a test DSN is set — the database is not reachable. Failing instead of passing silently." >&2; \
			exit 1; \
		fi; \
	fi
	bash scripts/coverage-gate.sh cover.out 68 internal/
	bash scripts/coverage-gate.sh cover.out 65 pkg/
	bash scripts/coverage-gate.sh cover.out --config .coverage-gates.yml

.PHONY: smoke
smoke: ## Boot smoke tests (tests/smoke)
	@if compgen -G "tests/smoke/*.go" > /dev/null; then \
		$(GO) test -tags=smoke -timeout=120s ./tests/smoke/...; \
	else \
		echo "no smoke tests under tests/smoke — skipping"; \
	fi

.PHONY: integration
integration: ## Integration tests with stub backends
	@if compgen -G "tests/integration/*.go" > /dev/null; then \
		$(GO) test -tags=integration -race -timeout=180s ./tests/integration/...; \
	else \
		echo "no integration tests under tests/integration — skipping"; \
	fi

.PHONY: realpostgres
realpostgres: ## Integration tests against a real postgres (expects GATEWAY_POSTGRES_DSN)
	@if [ -z "$$GATEWAY_POSTGRES_DSN" ]; then \
		echo "GATEWAY_POSTGRES_DSN is unset — start the stack with 'make services-up'"; \
		exit 1; \
	fi
	@if compgen -G "tests/integration/*_realpostgres_test.go" > /dev/null; then \
		$(GO) test -tags=realpostgres -race -timeout=300s ./tests/integration/...; \
	fi
	GATEWAY_TEST_POSTGRES_DSN=$$GATEWAY_POSTGRES_DSN \
		$(GO) test -race -timeout=300s -skip='^TestPostgresConformance$$' ./internal/repo/postgres/...

# ---------------------------------------------------------------------------
# Conformance — runs the driver-agnostic Repository conformance suite against
# each driver. Skips a driver if its backing-service env-var is unset so a
# developer running this without `make services-up` still gets a useful local
# signal from the memory entry.
# ---------------------------------------------------------------------------

.PHONY: conformance-all
conformance-all: conformance-memory conformance-postgres ## Run the conformance suite for every driver
	@echo "==> conformance-all: passed (skipped drivers whose env-vars were unset)"

.PHONY: conformance-memory
conformance-memory: ## Conformance suite against the in-memory driver
	$(GO) test -race -count=1 -timeout=300s -run='^TestMemoryConformance$$' ./internal/repo/memory/...

.PHONY: conformance-postgres
conformance-postgres: ## Conformance suite against a real postgres (skips if GATEWAY_TEST_POSTGRES_DSN unset)
	@if [ -z "$$GATEWAY_TEST_POSTGRES_DSN" ] && [ -n "$$GATEWAY_POSTGRES_DSN" ]; then \
		GATEWAY_TEST_POSTGRES_DSN="$$GATEWAY_POSTGRES_DSN" $(GO) test -race -count=1 -timeout=300s -run='^TestPostgresConformance$$' ./internal/repo/postgres/...; \
	else \
		$(GO) test -race -count=1 -timeout=300s -run='^TestPostgresConformance$$' ./internal/repo/postgres/...; \
	fi

.PHONY: fuzz-smoke
fuzz-smoke: ## Replay the committed fuzz seed corpus only (no live -fuzz) — the CI PR gate
	@set -eu; \
	pkgs=$$( \
		grep -rEl --include='*_test.go' '^func Fuzz[A-Za-z0-9_]+\(' . \
			| sed -E 's|/[^/]+$$||' \
			| sort -u \
	); \
	if [ -z "$$pkgs" ]; then \
		echo "no fuzz targets — skipping"; \
		exit 0; \
	fi; \
	$(GO) test -race -timeout=120s $$pkgs

.PHONY: fuzz
fuzz: ## Fuzz smoke — runs each fuzz target with seed corpus + 15s fuzzing
	@set -euo pipefail; \
	targets=$$( \
		grep -rEn --include='*_test.go' '^func (Fuzz[A-Za-z0-9_]+)\(' . \
			| sed -E 's|^(.*)/[^/]+:[0-9]+:func (Fuzz[A-Za-z0-9_]+).*$$|\1 \2|' \
			| sort -u \
	); \
	if [ -z "$$targets" ]; then \
		echo "no fuzz targets — skipping"; \
		exit 0; \
	fi; \
	echo "$$targets" | while read -r dir name; do \
		echo "==> fuzz $$name in $$dir"; \
		$(GO) test -run="^$${name}$$" -timeout=120s "./$$dir"; \
		$(GO) test -run='^$$' -fuzz="^$${name}$$" -fuzztime=15s -parallel=4 -timeout=120s "./$$dir"; \
	done

# ---------------------------------------------------------------------------
# Proto — buf lint + codegen
# ---------------------------------------------------------------------------

CONNECT_OPENAPI_VERSION ?= v0.18.0

.PHONY: docs-gen
docs-gen: ## Regenerate the docs reference JSON (config + audit/metrics) from code
	$(GO) generate ./internal/config/... ./internal/service/...
	@echo "==> docs reference JSON regenerated → docs-site/src/data/generated"

.PHONY: docs-drift
docs-drift: ## Check docs name only real identifiers + generated JSON is fresh
	$(GO) test -count=1 ./internal/docscheck/...

.PHONY: proto
proto: ## Regenerate Go stubs + OpenAPI + proto reference from proto
	$(BUF) generate
	$(MAKE) openapi
	$(MAKE) protodoc

.PHONY: protodoc
protodoc: ## Generate the HTML proto reference + raw .proto for the docs site
	mkdir -p docs-site/public/proto
	$(BUF) generate --template buf.gen.protodoc.yaml
	python3 scripts/protodoc-postprocess.py docs-site/public/proto/index.html
	cp proto/workspace/v1/workspace.proto docs-site/public/proto/workspace-v1.proto
	@echo "==> proto reference generated → docs-site/public/proto (index.html + raw .proto)"

.PHONY: buf-lint
buf-lint: ## Lint the proto sources
	$(BUF) lint

.PHONY: openapi
openapi: ## Regenerate the OpenAPI spec and publish it to the docs site (Scalar)
	GOBIN=$(CURDIR)/.bin $(GO) install github.com/sudorandom/protoc-gen-connect-openapi@$(CONNECT_OPENAPI_VERSION)
	$(BUF) generate --template buf.gen.openapi.yaml
	perl -0pi -e 's/^  title: workspace\.v1\n/  title: Workspaces API\n  description: |\n    Zanzibar-inspired workspace authorization service. Internal, service-to-service: callers present a bearer service credential; the acting user and subject are request fields. Connect protocol over HTTP POST + JSON.\n/m' gen/openapi/workspace/v1/workspace.openapi.yaml
	mkdir -p docs-site/public/openapi
	cp gen/openapi/workspace/v1/workspace.openapi.yaml docs-site/public/openapi/workspace-v1.yaml
	@echo "==> OpenAPI regenerated → docs-site/public/openapi/workspace-v1.yaml"

# ---------------------------------------------------------------------------
# Local services (docker-compose) for the real-backend tests
# ---------------------------------------------------------------------------

.PHONY: services-up
services-up: ## Start the local docker-compose stack (postgres) and wait for ready
	docker compose up -d postgres
	@echo "waiting for postgres:5432..."
	@for i in $$(seq 1 30); do (echo > /dev/tcp/localhost/5432) >/dev/null 2>&1 && break || sleep 1; done

.PHONY: services-down
services-down: ## Stop the local docker-compose stack
	docker compose down

# ---------------------------------------------------------------------------
# Tooling install
# ---------------------------------------------------------------------------

.PHONY: install-tools
install-tools: ## Install pinned versions of lint + vuln tooling
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "}; /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
