#!/usr/bin/env bash
# axess: crafted cases for scripts/coverage-badge.sh (write and check; the
# measured mode needs a coverage run and is exercised by the Coverage job).
#
# Usage: ./scripts/coverage-badge-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$SCRIPT_DIR/coverage-badge.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-coverage-badge.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BADGE="$WORK/coverage.svg"

passed=0
failed=0

# case NAME EXPECTED_EXIT FRAGMENT ARGS...
case_() {
  local name="$1" want="$2" fragment="$3" out status
  shift 3
  out="$("$TOOL" --badge "$BADGE" "$@" 2>&1)"
  status=$?
  if [ "$status" -eq "$want" ] && printf '%s' "$out" | grep -qF -- "$fragment"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment', got exit $status:" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

case_ "check without a badge refused" 1 "no coverage badge" check 80
case_ "write rounds half up" 0 "Coverage badge: 83% (measured 82.50%), brightgreen" write 82.50
case_ "written badge carries the figure" 0 "committed coverage badge (83%)" check 83
case_ "check inside the tolerance passes" 0 "within 1 point" check 82.10
case_ "check at the tolerance passes" 0 "within 1 point" check 84.00
case_ "check below the tolerance refused" 1 "says 83% and this run measured 81.90%" check 81.90
case_ "check above the tolerance refused" 1 "says 83% and this run measured 84.01%" check 84.01
case_ "check of a non-number refused" 1 "is not a percentage" check 'n/a'
case_ "check over 100 refused" 1 "is not a percentage" check 100.5
case_ "check without a figure is a usage error" 2 "Usage:" check
case_ "write below 80 is yellow" 0 "79% (measured 79.49%), yellow" write 79.49
case_ "write below 60 is red" 0 "59% (measured 59.4%), red" write 59.4
printf '<svg><text>coverage</text></svg>\n' > "$BADGE"
case_ "badge without a percentage refused" 1 "carries no percentage" check 80

echo "coverage-badge: $passed passed, $failed failed."
[ "$failed" -eq 0 ]
