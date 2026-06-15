#!/usr/bin/env bash
#
# run-coverage.sh — produce a merged race-enabled coverage profile (cover.out)
# over the service packages, for the coverage gate.
#
# A single `go test ./...` run covers everything: the unit tests, the
# black-box e2e suite under ./tests (which drives the full handler chain in
# process), and — when GATEWAY_TEST_POSTGRES_DSN / WORKSPACES_TEST_POSTGRES_DSN
# points at a database — the Postgres conformance suite. cmd/ is the thin
# container entrypoint and is exercised by the container-smoke job instead, so
# it is left out of -coverpkg to keep the gate meaningful.

set -euo pipefail

rm -f cover.out

go test -count=1 -race -timeout=1200s \
  -coverprofile=cover.out \
  -coverpkg=./internal/...,./pkg/... \
  ./...
