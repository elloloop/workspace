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

# COVERAGE_PART runs one part of that run, so CI can run the parts in
# parallel and merge their profiles (scripts/merge-coverage.sh):
#   unit:<i>/<n>  the i-th of n round-robin shards of the packages, less
#                 ./tests and ./internal/repo/postgres
#   e2e:<i>/<n>   the i-th of n round-robin shards of the ./tests suite,
#                 split by test name
#   postgres      ./internal/repo/postgres
# Unset, it is the single run above, writing cover.out.

set -euo pipefail

coverpkg=./internal/...,./pkg/...
part="${COVERAGE_PART:-}"

rm -f cover.out cover.*.out

if [[ -z "$part" ]]; then
  go test -count=1 -race -timeout=1200s \
    -coverprofile=cover.out \
    -coverpkg="$coverpkg" \
    ./...
  exit 0
fi

module="$(go list -m)"
pkgs=()
run=()
case "$part" in
  unit:*)
    shard="${part#unit:}"
    mapfile -t pkgs < <(go list ./... \
      | grep -vxF -e "$module/tests" -e "$module/internal/repo/postgres" \
      | awk -v i="${shard%/*}" -v n="${shard#*/}" '(NR - 1) % n == i - 1')
    ;;
  e2e:*)
    shard="${part#e2e:}"
    names="$(grep -hoE '^func Test[A-Za-z0-9_]+' tests/*_test.go | sed 's/^func //' | sort \
      | awk -v i="${shard%/*}" -v n="${shard#*/}" '(NR - 1) % n == i - 1' | paste -sd '|' -)"
    pkgs=(./tests)
    run=(-run "^(${names})\$")
    ;;
  postgres)
    pkgs=(./internal/repo/postgres/...)
    ;;
  *)
    echo "run-coverage: unknown COVERAGE_PART: $part" >&2
    exit 2
    ;;
esac

if [[ ${#pkgs[@]} -eq 0 ]]; then
  echo "run-coverage: $part selects no packages" >&2
  exit 2
fi

go test -count=1 -race -timeout=1200s ${run[@]+"${run[@]}"} \
  -coverprofile="cover.${part//[:\/]/-}.out" \
  -coverpkg="$coverpkg" \
  "${pkgs[@]}"
