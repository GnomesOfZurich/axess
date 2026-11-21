#!/usr/bin/env bash
# axess: crafted cases for scripts/check-workflow-pins.sh.
#
# Each case writes one or more files into a temporary directory (workflows
# at the top, the scripts they run below it), runs the check against that
# directory and asserts the exit status and a fragment of the output. The
# refusals are the contract, so a case that fails for a different reason
# than the one named fails here. The cases stand in
# scripts/check-workflow-pins-cases/, one file per part of the check. Each
# file runs in a shell of its own, all of them at once, and so do the files
# of unit cases: a file takes what it needs from helpers.sh and from no
# other file. A new one is a name in CASE_FILES and a line in `cases` that
# sources it: each file is named where it is run, so that the pin check,
# which reads this script, reads every file it runs. The counts and the
# failures are printed in the order of the list.
#
# A workflow a case writes gets `permissions: contents: read` appended, so
# that its jobs hold a token that can only read; a case about permissions
# sets TRAILER to the empty string. Then the readers and the rules run their
# own cases (scripts/lib/*_tests.py), which pin every node, word, verdict,
# note and refusal they return.
#
# Usage: ./scripts/check-workflow-pins-tests.sh

# The cases hold shell text as data: a dollar sign or a backslash in single
# quotes is meant as written.
# shellcheck disable=SC2016,SC1003
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="${CHECK:-$SCRIPT_DIR/check-workflow-pins.sh}"
CASES="$SCRIPT_DIR/check-workflow-pins-cases"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/axess-workflow-pins.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

CASE_FILES=(actions installs scripts readers jobs held held-readers held-steps boundary hosts arithmetic downloads)
UNIT_FILES=()

READ_ONLY='
permissions:
  contents: read'

# case_ NAME EXPECTED_EXIT FRAGMENT FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3" trailer="${TRAILER-$READ_ONLY}"
  shift 3
  local dir="$WORK/$passed-$failed"
  mkdir -p "$dir"
  while [ $# -gt 0 ]; do
    mkdir -p "$(dirname "$dir/$1")"
    case "$1" in
      */*) printf '%s\n' "$2" > "$dir/$1"; chmod +x "$dir/$1" ;;
      *) printf '%s%s\n' "$2" "$trailer" > "$dir/$1" ;;
    esac
    shift 2
  done
  local out status
  out="$("$CHECK" "$dir" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$dir"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

SHA='0123456789abcdef0123456789abcdef01234567'
DIGEST='sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

# cases NAME: one file of cases; its counts go to a file.
cases() {
  WORK="$ROOT/$1"
  mkdir -p "$WORK"
  passed=0
  failed=0
  # shellcheck source=check-workflow-pins-cases/helpers.sh
  . "$CASES/helpers.sh"
  # A directive stands in front of a whole command, never one branch of a
  # case: the directory below tells the reader where each file sourced
  # here lies.
  # shellcheck source-path=SCRIPTDIR/check-workflow-pins-cases
  case "$1" in
    actions) . "$CASES/actions.sh" ;;
    installs) . "$CASES/installs.sh" ;;
    scripts) . "$CASES/scripts.sh" ;;
    readers) . "$CASES/readers.sh" ;;
    jobs) . "$CASES/jobs.sh" ;;
    held) . "$CASES/held.sh" ;;
    held-readers) . "$CASES/held-readers.sh" ;;
    held-steps) . "$CASES/held-steps.sh" ;;
    boundary) . "$CASES/boundary.sh" ;;
    hosts) . "$CASES/hosts.sh" ;;
    arithmetic) . "$CASES/arithmetic.sh" ;;
    downloads) . "$CASES/downloads.sh" ;;
    *) echo "FAIL: no file of cases is named $1" >&2; return 1 ;;
  esac
  echo "$passed $failed" > "$ROOT/$1.count"
}
# unit NAME COMMAND...: one file of unit cases, the readers and the rules
# case by case in Python; its output and its status go to files.
unit() {
  local name="$1"
  shift
  UNIT_FILES+=("$name")
  (
    "$@" > "$ROOT/$name.unit" 2>&1
    echo $? > "$ROOT/$name.status"
  ) &
}

for file in "${CASE_FILES[@]}"; do
  (cases "$file") 2> "$ROOT/$file.failures" &
done
unit workflow_yaml python3 -I -B "$SCRIPT_DIR/lib/workflow_yaml_tests.py"
unit shell_words python3 -I -B "$SCRIPT_DIR/lib/shell_words_tests.py"
unit workflow_expressions python3 -I -B "$SCRIPT_DIR/lib/workflow_expressions_tests.py"
unit cargo_config python3 -I -B "$SCRIPT_DIR/lib/cargo_config_tests.py"
unit workflow_runners python3 -I -B "$SCRIPT_DIR/lib/workflow_runners_tests.py"
unit workflow_runners_more python3 -I -B "$SCRIPT_DIR/lib/workflow_runners_more_tests.py"
unit workflow_programs python3 -I -B "$SCRIPT_DIR/lib/workflow_programs_tests.py"
unit workflow_held python3 -I -B "$SCRIPT_DIR/lib/workflow_held_tests.py"
unit workflow_installs python3 -I -B "$SCRIPT_DIR/lib/workflow_installs_tests.py"
unit workflow_installs_more python3 -I -B "$SCRIPT_DIR/lib/workflow_installs_more_tests.py"
unit workflow_pins python3 -I -B "$SCRIPT_DIR/lib/workflow_pins_tests.py"
unit workflow_jobs python3 -I -B "$SCRIPT_DIR/lib/workflow_jobs_tests.py"
unit workflow_values python3 -I -B "$SCRIPT_DIR/lib/workflow_values_tests.py"
unit workflow_downloads python3 -I -B "$SCRIPT_DIR/lib/workflow_downloads_tests.py"
wait

passed=0
failed=0
for file in "${CASE_FILES[@]}"; do
  cat "$ROOT/$file.failures" >&2
  if [ -f "$ROOT/$file.count" ]; then
    read -r file_passed file_failed < "$ROOT/$file.count"
    passed=$((passed + file_passed))
    failed=$((failed + file_failed))
  else
    echo "FAIL: the cases of $file.sh did not run to their end" >&2
    failed=$((failed + 1))
  fi
done
units=0
for unit in "${UNIT_FILES[@]}"; do
  cat "$ROOT/$unit.unit"
  [ "$(cat "$ROOT/$unit.status" 2>/dev/null)" = 0 ] || units=$((units + 1))
done

echo "check-workflow-pins tests: $passed passed, $failed failed; $units unit file(s) failed"
[ "$failed" -eq 0 ] && [ "$units" -eq 0 ]
