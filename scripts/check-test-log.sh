#!/usr/bin/env bash
# axess: a cargo test run measured something, and each named suite ran.
#
# A `cargo test -- --ignored` run against live stores passes when nothing
# runs: every `test result:` line reads `0 passed`, cargo exits 0, and a
# gate that only looks at the exit status certifies a store it never
# touched. Summing `passed` across the run is not enough either, because an
# ignored test that returns early without its server counts as a pass for a
# store it never reached. So this
# reads the log and refuses, by name: a non-zero cargo status, any failed
# test, a run with no passing test at all, and for each NAME given, a run in
# which no passing test came from that store's own suite. A test is in the
# suite of NAME when NAME is a whole module of its full test name
# (`session::storage::valkey::tests::x`), or a whole word of the file its
# test binary is built from (`tests/authz_reload_valkey.rs`). NAME inside a
# longer name is another suite: a test under `valkey_cache`, in a directory
# called `valkey-runs` or named `mysqlish` is not a Valkey or a MySQL test.
#
# Usage: ./scripts/check-test-log.sh CARGO_STATUS LOG [NAME...]
#   CARGO_STATUS  the exit status of the cargo test run the log came from
#   LOG           the run's combined stdout and stderr
#   NAME          a store or suite each of which must have run a test
#                 (for instance valkey postgres mysql keycloak)

set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 CARGO_STATUS LOG [NAME...]" >&2
  exit 2
fi
status="$1"
log="$2"
shift 2
[ -r "$log" ] || { echo "ERROR: cannot read the test log $log" >&2; exit 2; }

# The log is read without its colour codes. With CARGO_TERM_COLOR=always,
# as CI sets it, cargo writes its `Running` line as an escape sequence, the
# word, another escape sequence and the source: no `Running ` at the start
# of the line, so the binary of the tests after it would go unnamed and a
# suite counted by its file (`tests/spire_live.rs`) would read as not run.
# The test harness colours `ok` the same way when told to.
plain="$(mktemp "${TMPDIR:-/tmp}/axess-test-log.XXXXXX")" || exit 2
trap 'rm -f "$plain"' EXIT
sed $'s/\x1b\\[[0-9;?]*[A-Za-z]//g' "$log" > "$plain" || {
  echo "ERROR: cannot read the test log $log" >&2
  exit 2
}
log="$plain"

passed=$(grep -E '^test result:' "$log" | awk '{p+=$4} END {print p+0}')
failed=$(grep -E '^test result:' "$log" | awk '{f+=$6} END {print f+0}')
lines=$(grep -cE '^test result:' "$log" || true)

if [ "$status" -ne 0 ] || [ "$failed" -ne 0 ]; then
  echo "ERROR: tests: $failed failed, $passed passed over $lines result lines (cargo exit $status)." >&2
  exit 1
fi
if [ "$passed" -eq 0 ]; then
  echo "ERROR: tests measured nothing: 0 passed over $lines result lines." >&2
  exit 1
fi

# Passing tests by binary: the `Running <source> (<binary>)` line names the
# source file of the binary every `test <name> ... ok` line after it
# belongs to.
missing=()
for name in "$@"; do
  count=$(awk -v name="$name" '
    function word_of(text, sep,   parts, k, n) {
      n = split(text, parts, sep)
      for (k = 1; k <= n; k++) if (parts[k] == name) return 1
      return 0
    }
    /^[[:space:]]*Running / {
      source = ($2 == "unittests") ? $3 : $2
      sub(/.*\//, "", source); sub(/\.rs$/, "", source)
      in_binary = word_of(source, "[_-]")
      next
    }
    /^[[:space:]]*Doc-tests / { in_binary = 0; next }
    /^test .* \.\.\. ok$/ { if (in_binary || word_of($2, "::")) n++ }
    END { print n + 0 }' "$log")
  if [ "$count" -eq 0 ]; then
    missing+=("$name")
  else
    echo "ok: $count passing test(s) from the $name suite."
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: no passing test ran from the suite(s): ${missing[*]} ($passed passed in all; the store's own tests did not run)." >&2
  exit 1
fi
echo "OK: tests: $passed passed, 0 failed, over $lines result lines${*:+; every suite ran: $*}."
