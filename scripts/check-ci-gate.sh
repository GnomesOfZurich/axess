#!/usr/bin/env bash
# axess: every CI job is a need of the "Release Gate" job.
#
# The main branch ruleset requires "Release Gate" plus the named jobs; the
# gate is what covers the matrix entries (Build Check, Feature Isolation,
# Factor Isolation), whose check names change whenever a row is added. A
# job added to ci.yml but not to the gate's `needs` would run, could fail,
# and would not block the release pull request. This refuses that by name,
# and refuses a need that names no job.
#
# Usage: ./scripts/check-ci-gate.sh [WORKFLOW]   (default: .github/workflows/ci.yml)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="${1:-$AXESS_DIR/.github/workflows/ci.yml}"
GATE=release_gate

# Job ids: two-space keys under the top-level `jobs:`.
jobs="$(awk '/^jobs:/ { in_jobs = 1; next } in_jobs && /^[^ #]/ { in_jobs = 0 }
  in_jobs && /^  [A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*$/ { sub(/^  /, ""); sub(/:.*/, ""); print }' "$WORKFLOW" | sort)"

# The gate's needs, written as a block list.
needs="$(awk -v gate="$GATE" '
  $0 ~ "^  " gate ":" { in_gate = 1; next }
  in_gate && /^  [A-Za-z_]/ { in_gate = 0 }
  in_gate && /^    needs:/ { in_needs = 1; next }
  in_gate && in_needs && /^      - / { sub(/^      - /, ""); sub(/[[:space:]#].*/, ""); print; next }
  in_gate && in_needs && /^    [A-Za-z]/ { in_needs = 0 }' "$WORKFLOW" | sort)"

if ! printf '%s\n' "$jobs" | grep -qx "$GATE"; then
  echo "REFUSED: $WORKFLOW has no '$GATE' job." >&2
  exit 1
fi
if [ -z "$needs" ]; then
  echo "REFUSED: '$GATE' in $WORKFLOW lists no needs (write them as a block list)." >&2
  exit 1
fi

errors=0
for job in $jobs; do
  [ "$job" = "$GATE" ] && continue
  if ! printf '%s\n' "$needs" | grep -qx "$job"; then
    echo "REFUSED: job '$job' is not in the needs of '$GATE', so it cannot block a release pull request." >&2
    errors=$((errors + 1))
  fi
done
for need in $needs; do
  if ! printf '%s\n' "$jobs" | grep -qx "$need"; then
    echo "REFUSED: '$GATE' needs '$need', which is not a job in $WORKFLOW." >&2
    errors=$((errors + 1))
  fi
done
if [ "$errors" -gt 0 ]; then
  exit 1
fi

count="$(printf '%s\n' "$needs" | wc -l | tr -d ' ')"
echo "OK: '$GATE' needs all $count other jobs in $(basename "$WORKFLOW")."
