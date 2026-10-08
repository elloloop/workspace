#!/usr/bin/env bash
#
# merge-coverage.sh — concatenate go coverage profiles into one.
#
# Usage: merge-coverage.sh <out> <profile> [<profile>...]
#
# The profiles share one mode line; coverage-gate.sh counts a block covered
# if any profile hit it, so plain concatenation is a correct merge.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <out> <profile> [<profile>...]" >&2
  exit 2
fi

out="$1"; shift
head -n 1 "$1" > "$out"
for profile in "$@"; do
  tail -n +2 "$profile" >> "$out"
done
