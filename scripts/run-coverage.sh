#!/usr/bin/env bash

set -euo pipefail

rm -f cover.out cover.*.out

profiles=()
unit_coverpkg=./internal/...,./pkg/...,./cmd/...
tagged_coverpkg=./internal/...,./pkg/...

go test -count=1 -race -timeout=1200s \
  -coverprofile=cover.unit.out \
  -coverpkg="$unit_coverpkg" \
  ./...
profiles+=(cover.unit.out)

if [[ "${RUN_INTEGRATION_COVERAGE:-}" == "1" ]]; then
  go test -count=1 -tags=integration -race -timeout=180s \
    -coverprofile=cover.integration.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/integration/...
  profiles+=(cover.integration.out)
fi

# E2E suite — drives the public HTTP/JSON wire format (no Connect-Go
# codegen import). Exercises the same handler chain as the container,
# in-process via httptest. Contributes coverage of internal/connect,
# internal/middleware, internal/app, internal/service, and
# internal/repo/memory.
#
# Timeout is 600s (not 180s): every test boots a full app.New under
# -race. On a 2-core CI runner the whole-suite wall-clock is well past
# the old 180s budget even though the suite passes; 600s matches the
# headroom the realpostgres suite already uses.
if [[ "${RUN_INTEGRATION_COVERAGE:-}" == "1" ]] && compgen -G "tests/e2e/*.go" > /dev/null; then
  go test -count=1 -tags=e2e -race -timeout=600s \
    -coverprofile=cover.e2e.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/e2e/...
  profiles+=(cover.e2e.out)
fi

if [[ -n "${GATEWAY_POSTGRES_DSN:-}" ]]; then
  go test -count=1 -tags=realpostgres -race -timeout=300s \
    -coverprofile=cover.realpostgres.out \
    -coverpkg="$tagged_coverpkg" \
    ./tests/integration/...
  profiles+=(cover.realpostgres.out)
fi

if [[ -n "${GATEWAY_TEST_POSTGRES_DSN:-}" ]]; then
  go test -count=1 -race -timeout=300s \
    -coverprofile=cover.postgres.out \
    -coverpkg="$tagged_coverpkg" \
    ./internal/repo/postgres/...
  profiles+=(cover.postgres.out)
fi

head -n 1 "${profiles[0]}" > cover.out
for profile in "${profiles[@]}"; do
  tail -n +2 "$profile" >> cover.out
done
