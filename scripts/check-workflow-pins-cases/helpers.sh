# shellcheck shell=bash disable=SC2016,SC2034,SC2154
# Helpers for the cases of scripts/check-workflow-pins.sh. Sourced by
# scripts/check-workflow-pins-tests.sh before each file of cases, so that a
# file runs on its own, in a shell of its own, beside the others.

# block_case NAME EXPECTED_EXIT FRAGMENT LINE [LINE...]: the lines as a
# `run: |` script whose first line is line 5 of the file.
block_case() {
  local name="$1" want="$2" fragment="$3" body="" line
  shift 3
  for line in "$@"; do
    body="$body
          $line"
  done
  case_ "$name" "$want" "$fragment" b.yml "jobs:
  a:
    steps:
      - run: |$body"
}
HELD="a job that names a secret runs what the check does not read: job a"

# held_case NAME EXPECTED_EXIT FRAGMENT LINE [LINE...]: the lines as the
# script of a job that names a secret; the first is line 7 of the file.
# The files of HELD_FILES (FILE CONTENT...) stand in the repository.
held_case() {
  local name="$1" want="$2" fragment="$3" body="" line
  shift 3
  for line in "$@"; do
    body="$body
          $line"
  done
  case_ "$name" "$want" "$fragment" h.yml "jobs:
  a:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - run: |$body" ${HELD_FILES[@]+"${HELD_FILES[@]}"}
}
# free_case NAME LINE [LINE...]: the same script in a job that holds
# nothing, where it passes.
free_case() {
  local name="$1" body="" line
  shift
  for line in "$@"; do
    body="$body
          $line"
  done
  case_ "$name" 0 "OK: every action" h.yml "jobs:
  a:
    steps:
      - run: |$body" ${HELD_FILES[@]+"${HELD_FILES[@]}"}
}
HELD_FILES=()
config_case() { # config_case NAME EXPECTED_EXIT FRAGMENT FILE CONTENT
  case_ "$1" "$2" "$3" c.yml "jobs:
  a:
    steps:
      - run: cargo build" "$4" "$5"
}
