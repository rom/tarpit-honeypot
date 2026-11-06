#!/usr/bin/env bash
#
# check-coverage.sh — per-package Go test-coverage gate.
#
# Enforces a FLOOR of 80% statement coverage on every package, with two
# escape hatches, both explicit and auditable:
#
#   EXCLUDE      packages with nothing meaningful to unit-test in CI (the
#                command mains, the PostgreSQL backend that needs a live DB).
#   GRANDFATHER  packages that are below the floor TODAY. Each is pinned a little
#                under its current level so the gate (a) passes now, (b) blocks
#                any regression below that level, and (c) is a visible debt list
#                to burn down to 80%. Raise a package's tests past 80%, then
#                delete its line here — the gate then holds it to the full floor.
#
# Usage:  scripts/check-coverage.sh            # runs the suite with -cover
#         COVER_OUT=cover.txt scripts/check-coverage.sh   # reuse a saved run
#         FLOOR=75 scripts/check-coverage.sh    # override the floor
#
# Exit non-zero if any package is below its required threshold, or if the test
# run itself failed.
set -euo pipefail

FLOOR="${FLOOR:-80}"
MODULE="github.com/rom/tarpit-honeypot"

# Packages not subject to the gate, each with the reason it can't be unit-tested
# meaningfully in CI.
declare -A EXCLUDE=(
  ["cmd/tarpit-honeypot"]="binary main; exercised by integration, not unit tests"
  ["cmd/tarpit-testharness"]="CLI main; exercised end-to-end, not unit tests"
  ["internal/store/pgstore"]="PostgreSQL backend; needs a live database to test"
)

# Known debt: packages below the 80% floor today, each pinned a little under its
# current coverage (headroom for run-to-run variance in the integration-driven
# packages). Burn these down to >=80 and remove the line. DO NOT raise a number
# to make a regression pass — fix the tests instead.
declare -A GRANDFATHER=(
  ["internal/privdrop"]=3
  ["internal/canary"]=4
  ["internal/tunnet"]=17
  ["internal/sandbox"]=29
  ["internal/retention"]=29
  ["internal/listener"]=32
  ["internal/honeynet"]=32
  ["internal/sink"]=33
  ["internal/sniffer"]=34
  ["internal/identity"]=34
  ["internal/cli"]=35
  ["internal/config"]=44
  ["internal/dnscanary"]=49
  ["internal/intel"]=63
  ["internal/sensor"]=64
  ["internal/archetype"]=68
  ["internal/artifactscan"]=68
  ["internal/detect"]=69
  ["internal/event"]=70
  ["internal/fakefiles"]=70
  ["internal/shell"]=71
  ["internal/ui"]=71
  ["internal/listener/handler"]=75
)

# 1. Obtain per-package coverage.
cover_out="$(mktemp)"
trap 'rm -f "$cover_out"' EXIT
if [[ -n "${COVER_OUT:-}" && -f "${COVER_OUT}" ]]; then
  cp "${COVER_OUT}" "$cover_out"
else
  echo ">> running: go test -cover ./..."
  # -p 2 keeps peak memory modest on small runners; coverage is deterministic.
  if ! go test -cover -covermode=atomic -p 2 ./... >"$cover_out" 2>&1; then
    echo "!! test run FAILED — coverage gate cannot pass until tests pass:"
    grep -E '^(---|FAIL|panic:|\s+.*\.go:[0-9])' "$cover_out" | head -40 || true
    exit 1
  fi
fi

# A failing suite in a reused COVER_OUT must still fail the gate.
if grep -qE '^FAIL' "$cover_out"; then
  echo "!! test run contains FAIL lines:"; grep -E '^FAIL' "$cover_out"; exit 1
fi

# 2. Evaluate each package.
fail=0
promotable=()
printf '%-48s %8s %8s  %s\n' "PACKAGE" "COV%" "FLOOR" "STATUS"
printf '%-48s %8s %8s  %s\n' "-------" "----" "-----" "------"

while IFS= read -r line; do
  # Match "<...>/pkg   coverage: 12.3% of statements"
  [[ "$line" == *"coverage:"* ]] || continue
  [[ "$line" == *"[no statements]"* ]] && continue   # nothing to measure
  pkg="$(sed -E "s#.*${MODULE}/([^[:space:]]+).*#\1#" <<<"$line")"
  pct="$(sed -E 's#.*coverage: ([0-9.]+)%.*#\1#' <<<"$line")"
  [[ "$pkg" == "$line" || -z "$pct" ]] && continue

  if [[ -n "${EXCLUDE[$pkg]:-}" ]]; then
    printf '%-48s %8s %8s  SKIP (%s)\n' "$pkg" "$pct" "-" "${EXCLUDE[$pkg]}"
    continue
  fi

  req="$FLOOR"
  tag=""
  if [[ -n "${GRANDFATHER[$pkg]:-}" ]]; then
    req="${GRANDFATHER[$pkg]}"
    tag=" (grandfathered; raise to ${FLOOR})"
    # Flag debt that has quietly climbed past the floor so it can be promoted.
    if awk "BEGIN{exit !($pct >= $FLOOR)}"; then
      promotable+=("$pkg ($pct%)")
    fi
  fi

  if awk "BEGIN{exit !($pct + 0.05 < $req)}"; then
    printf '%-48s %8s %8s  BELOW%s\n' "$pkg" "$pct" "$req" "$tag"
    fail=1
  else
    printf '%-48s %8s %8s  ok%s\n' "$pkg" "$pct" "$req" "$tag"
  fi
done < "$cover_out"

echo
if [[ ${#promotable[@]} -gt 0 ]]; then
  echo ">> These grandfathered packages are now >= ${FLOOR}% — remove them from GRANDFATHER so the full floor applies:"
  printf '   - %s\n' "${promotable[@]}"
  echo
fi

if [[ "$fail" -ne 0 ]]; then
  echo "FAIL: at least one package is below its coverage threshold (floor=${FLOOR}%)."
  exit 1
fi
echo "PASS: every package meets its coverage threshold (floor=${FLOOR}%, grandfathered debt pinned)."
