#!/usr/bin/env bash
# axess: crafted cases for the width of the mutation sweep.
#
# mutants.yml names two widths at its top, MUTANTS_WIDTH_RELEASE for the
# sweep a push to a release branch starts and MUTANTS_WIDTH_SWEEP for every
# other, and `scripts/mutants-sweep.sh width EVENT` picks one; the plan job
# hands it to the shard jobs. These cases read the two values from the
# workflow, resolve each trigger through the script and hold the workflow
# to its wiring: the plan job resolves the width from the event, and every
# `max-parallel` of the workflow is that width. Nothing builds.
#
# Usage: ./scripts/check-mutants-width-tests.sh

# The cases match workflow text that holds `${{ ... }}` literally.
# shellcheck disable=SC2016
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWEEP="$SCRIPT_DIR/mutants-sweep.sh"
WORKFLOW="${WORKFLOW:-$SCRIPT_DIR/../.github/workflows/mutants.yml}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-mutants-width.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# top NAME: the value the top-level `env:` of the workflow gives NAME.
top() {
  awk -v name="$1" '/^env:/ { in_env = 1; next } in_env && /^[^ #]/ { in_env = 0 }
    in_env && $1 == name ":" { print $2 }' "$WORKFLOW"
}
RELEASE="$(top MUTANTS_WIDTH_RELEASE)"
SWEEP_WIDTH="$(top MUTANTS_WIDTH_SWEEP)"

# holds NAME FRAGMENT: the workflow holds the fragment as a whole line.
holds() {
  if grep -qxF -- "$2" "$WORKFLOW"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $1: $WORKFLOW has no line '$2'" >&2
  fi
}

# resolve NAME EVENT WANTED_EXIT FRAGMENT RELEASE SWEEP: the script's width
# for the event with the two widths set to RELEASE and SWEEP, where "-"
# leaves one unset.
resolve() {
  local name="$1" event="$2" want="$3" fragment="$4" release="$5" sweep="$6" out
  out="$(
    unset MUTANTS_WIDTH_RELEASE MUTANTS_WIDTH_SWEEP
    [ "$release" = - ] || export MUTANTS_WIDTH_RELEASE="$release"
    [ "$sweep" = - ] || export MUTANTS_WIDTH_SWEEP="$sweep"
    "$SWEEP" width "$event" 2>"$WORK/stderr"
  )"
  judge "$name" "$want" "$fragment" "$?" "$out"
}

# The two widths the workflow names, as whole numbers above 0.
for pair in "MUTANTS_WIDTH_RELEASE=$RELEASE" "MUTANTS_WIDTH_SWEEP=$SWEEP_WIDTH"; do
  case "${pair#*=}" in
    "" | *[!0-9]* | 0*)
      failed=$((failed + 1))
      echo "FAIL: the top of mutants.yml names ${pair%%=*} as a whole number above 0, got '${pair#*=}'" >&2 ;;
    *) passed=$((passed + 1)) ;;
  esac
done

# Each trigger resolves to the width the workflow names for it.
resolve "a push to a release branch takes the release width" push 0 "$RELEASE" "$RELEASE" "$SWEEP_WIDTH"
resolve "the weekly sweep takes the sweep width" schedule 0 "$SWEEP_WIDTH" "$RELEASE" "$SWEEP_WIDTH"
resolve "a dispatched sweep takes the sweep width" workflow_dispatch 0 "$SWEEP_WIDTH" "$RELEASE" "$SWEEP_WIDTH"
resolve "a pull request takes the sweep width" pull_request 0 "$SWEEP_WIDTH" "$RELEASE" "$SWEEP_WIDTH"
# The script refuses a width it cannot use, rather than a default.
resolve "an unset release width is refused" push 64 "MUTANTS_WIDTH_RELEASE is ''" - "$SWEEP_WIDTH"
resolve "an unset sweep width is refused" schedule 64 "MUTANTS_WIDTH_SWEEP is ''" "$RELEASE" -
resolve "a width that is not a number is refused" push 64 "MUTANTS_WIDTH_RELEASE is 'wide'" wide -
resolve "a width of zero is refused" schedule 64 "MUTANTS_WIDTH_SWEEP is '0'" - 0
resolve "a width with a leading zero is refused" push 64 "MUTANTS_WIDTH_RELEASE is '016'" 016 -

# The wiring: the triggers the release width is for, the plan job resolving
# the width from the event, and every max-parallel taking it.
holds "a push to the release branches starts a sweep" "    branches: [release/next, 'release/*.x']"
holds "the plan job reads the event" "          EVENT: \${{ github.event_name }}"
holds "the plan job resolves the width" '          echo "width=$(scripts/mutants-sweep.sh width "$EVENT")" >> "$GITHUB_OUTPUT"'
holds "the plan job hands the width on" "      width: \${{ steps.plan.outputs.width }}"
widths="$(grep -cE '^[[:space:]]*max-parallel:' "$WORKFLOW")"
named="$(grep -cxF '      max-parallel: ${{ fromJSON(needs.plan.outputs.width) }}' "$WORKFLOW")"
if [ "$widths" -eq 2 ] && [ "$named" -eq 2 ]; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: the shard and retry jobs take the width the plan job resolves, and no other max-parallel stands: $named of $widths do" >&2
fi

echo "check-mutants-width crafted cases: $passed passed, $failed failed (release width $RELEASE, sweep width $SWEEP_WIDTH)"
[ "$failed" -eq 0 ]
