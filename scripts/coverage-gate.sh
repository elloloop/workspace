#!/usr/bin/env bash
#
# coverage-gate.sh — fail CI if coverage drops below configured thresholds.
#
# Usage:
#   coverage-gate.sh <profile> --config <config>
#   coverage-gate.sh <profile> <threshold> <prefix> [<prefix>...]
#
# Example:
#   coverage-gate.sh cover.out --config .coverage-gates.yml
#   coverage-gate.sh cover.out 80 internal/ pkg/
#
# The script is intentionally dependency-free — only awk + go tool cover.

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <profile> <threshold> <prefix> [<prefix>...]" >&2
  exit 2
fi

PROFILE="$1"; shift

if [[ ! -f "$PROFILE" ]]; then
  echo "coverage-gate: profile not found: $PROFILE" >&2
  exit 2
fi

tmp="$(mktemp)"
config_tmp=""
seen_tmp=""
trap 'rm -f "$tmp" ${config_tmp:-} ${seen_tmp:-}' EXIT

module="$(go list -m 2>/dev/null || true)"

awk -v module="$module" 'NR > 1 {
  key = $1
  stmts[key] = $2            # numStmts is identical across appearances
  if ($3 > 0) hit[key] = 1
}
END {
  for (k in stmts) {
    n = split(k, a, ":")
    file = a[1]
    m = split(file, p, "/")
    pkg = p[1]
    for (i = 2; i < m; i++) pkg = pkg "/" p[i]
    if (module != "" && index(pkg, module "/") == 1) {
      pkg = substr(pkg, length(module) + 2)
    }
    s[pkg] += stmts[k]
    if (k in hit) c[pkg] += stmts[k]
  }
  for (k in s) printf "%s %d %d\n", k, s[k], c[k]+0
}' "$PROFILE" > "$tmp"

if [[ "${1:-}" == "--config" ]]; then
  if [[ $# -ne 2 ]]; then
    echo "usage: $0 <profile> --config <config>" >&2
    exit 2
  fi
  CONFIG="$2"
  if [[ ! -f "$CONFIG" ]]; then
    echo "coverage-gate: config not found: $CONFIG" >&2
    exit 2
  fi

  config_tmp="$(mktemp)"
  awk '
    /^[[:space:]]*($|#)/ { next }
    /^[[:space:]]*default:[[:space:]]*/ {
      line=$0; sub(/^[[:space:]]*default:[[:space:]]*/, "", line); sub(/[[:space:]]+#.*$/, "", line)
      print "default\t" line
      next
    }
    /^[[:space:]]*include:[[:space:]]*$/ { section="include"; next }
    /^[[:space:]]*exclude:[[:space:]]*$/ { section="exclude"; next }
    /^[[:space:]]*packages:[[:space:]]*$/ { section="packages"; next }
    section == "include" && /^[[:space:]]*-[[:space:]]*/ {
      line=$0; sub(/^[[:space:]]*-[[:space:]]*/, "", line); sub(/[[:space:]]+#.*$/, "", line)
      print "include\t" line
      next
    }
    section == "exclude" && /^[[:space:]]*-[[:space:]]*/ {
      line=$0; sub(/^[[:space:]]*-[[:space:]]*/, "", line); sub(/[[:space:]]+#.*$/, "", line)
      print "exclude\t" line
      next
    }
    section == "packages" && /^[[:space:]]*[^[:space:]#][^:]*:[[:space:]]*/ {
      line=$0; sub(/^[[:space:]]*/, "", line); sub(/[[:space:]]+#.*$/, "", line)
      split(line, parts, ":")
      key=parts[1]
      value=line; sub(/^[^:]*:[[:space:]]*/, "", value)
      print "package\t" key "\t" value
      next
    }
    {
      print "coverage-gate: unsupported config line: " NR ": " $0 > "/dev/stderr"
      exit 2
    }
  ' "$CONFIG" > "$config_tmp"

  default_threshold="$(awk -F '\t' '$1 == "default" { print $2 }' "$config_tmp")"
  if [[ -z "$default_threshold" ]]; then
    echo "coverage-gate: config missing default threshold" >&2
    exit 2
  fi

  includes=()
  while IFS=$'\t' read -r _ include; do
    includes+=("$include")
  done < <(awk -F '\t' '$1 == "include" { print $1 "\t" $2 }' "$config_tmp")
  if [[ ${#includes[@]} -eq 0 ]]; then
    includes=("internal/" "pkg/")
  fi

  # Excluded prefixes are dropped from the gate entirely (build-time tooling like
  # cmd/ and the code generators, validated by their output, not line coverage).
  excludes=()
  while IFS=$'\t' read -r _ exclude; do
    excludes+=("$exclude")
  done < <(awk -F '\t' '$1 == "exclude" { print $1 "\t" $2 }' "$config_tmp")

  seen_tmp="$(mktemp)"

  fail=0
  while read -r pkg stmts cov; do
    included=0
    for include in "${includes[@]}"; do
      case "$pkg" in
        "$include"* ) included=1 ;;
      esac
    done
    if [[ $included -eq 0 ]]; then
      continue
    fi
    excluded=0
    for exclude in "${excludes[@]}"; do
      case "$pkg" in
        *"$exclude"* ) excluded=1 ;;
      esac
    done
    if [[ $excluded -eq 1 ]]; then
      continue
    fi

    threshold="$(awk -F '\t' -v pkg="$pkg" -v fallback="$default_threshold" '
      $1 == "package" && $2 == pkg { print $3; found=1 }
      END { if (!found) print fallback }
    ' "$config_tmp")"
    if awk -F '\t' -v pkg="$pkg" '$1 == "package" && $2 == pkg { found=1 } END { exit found ? 0 : 1 }' "$config_tmp"; then
      echo "$pkg" >> "$seen_tmp"
    fi
    pct=$(awk -v c="$cov" -v t="$stmts" 'BEGIN { printf "%.2f", (c/t)*100 }')
    cmp=$(awk -v p="$pct" -v th="$threshold" 'BEGIN { print (p+0 < th+0) ? "fail" : "ok" }')
    if [[ "$cmp" == "fail" ]]; then
      echo "coverage-gate: FAIL  $pkg  $pct% < $threshold% ($cov/$stmts stmts)"
      fail=1
    else
      echo "coverage-gate: ok    $pkg  $pct% >= $threshold% ($cov/$stmts stmts)"
    fi
  done < "$tmp"

  while IFS=$'\t' read -r _ pkg _; do
    if ! grep -Fxq "$pkg" "$seen_tmp"; then
      echo "coverage-gate: FAIL  $pkg  no statements found"
      fail=1
    fi
  done < <(awk -F '\t' '$1 == "package" { print $1 "\t" $2 "\t" $3 }' "$config_tmp")

  exit "$fail"
fi

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <profile> <threshold> <prefix> [<prefix>...]" >&2
  exit 2
fi

THRESHOLD="$1"; shift
PREFIXES=("$@")

fail=0
for prefix in "${PREFIXES[@]}"; do
  total=0; covered=0
  while read -r pkg stmts cov; do
    case "$pkg" in
      *"$prefix"*) total=$((total + stmts)); covered=$((covered + cov)) ;;
    esac
  done < "$tmp"

  if [[ $total -eq 0 ]]; then
    echo "coverage-gate: no statements found for prefix '$prefix' — skipping"
    continue
  fi

  pct=$(awk -v c="$covered" -v t="$total" 'BEGIN { printf "%.2f", (c/t)*100 }')
  cmp=$(awk -v p="$pct" -v th="$THRESHOLD" 'BEGIN { print (p+0 < th+0) ? "fail" : "ok" }')
  if [[ "$cmp" == "fail" ]]; then
    echo "coverage-gate: FAIL  $prefix  $pct% < $THRESHOLD% ($covered/$total stmts)"
    fail=1
  else
    echo "coverage-gate: ok    $prefix  $pct% >= $THRESHOLD% ($covered/$total stmts)"
  fi
done

exit "$fail"
