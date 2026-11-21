#!/usr/bin/env bash
# axess: crafted cases for scripts/check-test-log.sh.
#
# Each case writes a cargo test log, runs the check with a cargo status and
# the suite names, and asserts the exit status and a fragment of the output.
#
# Usage: ./scripts/check-test-log-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-test-log.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case NAME EXPECTED_EXIT FRAGMENT CARGO_STATUS LOG [SUITE...]
case_() {
  local name="$1" want="$2" fragment="$3" status="$4" log="$5"
  shift 5
  local file="$WORK/$passed-$failed.log"
  printf '%s\n' "$log" > "$file"
  local out rc
  out="$("$SCRIPT_DIR/check-test-log.sh" "$status" "$file" "$@" 2>"$WORK/stderr")"
  rc=$?
  judge "$name" "$want" "$fragment" "$rc" "$out"
}

NOTHING_RAN='     Running tests/valkey_live.rs (target/debug/deps/valkey_live-0123)

running 3 tests
test a ... ignored
test b ... ignored
test c ... ignored

test result: ok. 0 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.00s'
case_ "a run with no passing test is refused" 1 "tests measured nothing: 0 passed over 1 result lines" 0 "$NOTHING_RAN"

ONE_STORE='     Running tests/authz_reload_valkey.rs (target/debug/deps/authz_reload_valkey-0123)

running 2 tests
test a_reload_reaches_every_pod ... ok
test a_stale_entry_is_dropped ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s

     Running tests/returns_early.rs (target/debug/deps/returns_early-4567)

running 1 test
test passes_without_its_server ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
case_ "a store whose suite ran no test is refused" 1 "no passing test ran from the suite(s): postgres mysql" 0 "$ONE_STORE" valkey postgres mysql
case_ "the stores that ran are named" 1 "ok: 2 passing test(s) from the valkey suite." 0 "$ONE_STORE" valkey postgres
case_ "the suites given all ran" 0 "OK: tests: 3 passed, 0 failed, over 2 result lines; every suite ran: valkey" 0 "$ONE_STORE" valkey

UNIT_TESTS='     Running unittests src/lib.rs (target/debug/deps/axess_core-89ab)

running 2 tests
test session::storage::mysql::live_tests::a_row_round_trips ... ok
test device::storage::postgres::tests::reseal::a_reseal_keeps_the_owner ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s'
case_ "a suite inside the library test binary counts by test name" 0 "every suite ran: mysql postgres" 0 "$UNIT_TESTS" mysql postgres
case_ "a store with no test in the library binary is refused" 1 "no passing test ran from the suite(s): valkey" 0 "$UNIT_TESTS" valkey

FAILING='     Running tests/postgres_store.rs (target/debug/deps/postgres_store-0123)

running 2 tests
test a ... ok
test b ... FAILED

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s'
case_ "a failed test is refused" 1 "tests: 1 failed, 1 passed over 1 result lines (cargo exit 101)" 101 "$FAILING" postgres
case_ "a non-zero cargo status is refused even with passes" 1 "(cargo exit 1)" 1 "$ONE_STORE" valkey
case_ "no suite names: a run with passes is accepted" 0 "OK: tests: 3 passed, 0 failed, over 2 result lines." 0 "$ONE_STORE"

# The store's name inside a longer name is another suite.
OTHER_SUITES='     Running unittests src/lib.rs (target/valkey-runs/debug/deps/axess_core-89ab)

running 3 tests
test authz::cache::valkey_cache::tests::an_entry_round_trips ... ok
test session::storage::mysqlish::a_row_round_trips ... ok
test federation::valkey_logout::tests::a_token_is_spent ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s

     Running tests/valkey_cache_live.rs (target/debug/deps/valkey_cache_live-0123)

running 1 test
test a_cached_decision_is_dropped ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s'
case_ "a test under a module whose name holds the store's name is not the store's" 1 "no passing test ran from the suite(s): mysql" 0 "$OTHER_SUITES" mysql
case_ "a binary in a directory that holds the store's name is not the store's" 1 "no passing test ran from the suite(s): postgres" 0 "${OTHER_SUITES//valkey-runs/postgres-runs}" postgres
case_ "a binary whose file names the store as a word is the store's" 0 "ok: 1 passing test(s) from the valkey suite." 0 "$OTHER_SUITES" valkey
case_ "a unit test under a module named for the store counts" 0 "every suite ran: mysql postgres" 0 "$UNIT_TESTS" mysql postgres

# In colour, as cargo writes with CARGO_TERM_COLOR=always (CI's setting):
# the SPIRE suite counts by its file, so its `Running` line must be read
# through the escape sequences around the word.
ESC=$'\033'
SPIRE_COLOURED="${ESC}[1m${ESC}[92m     Running${ESC}[0m tests/spire_live.rs (target/debug/build/axess-core/322db374fad57eba/out/spire_live-322db374fad57eba)

running 4 tests
spire-live: delete the entry of spiffe://example.org/axess-live/withdrawn
test spire_live::a_jwt_svid_is_validated_by_the_agent_and_against_its_bundle ... ok
test spire_live::an_x509_svid_arrives_with_the_bundle_that_verifies_it ... ok
test spire_live::a_deleted_entry_is_withdrawn_while_another_identity_remains ... ok
test spire_live::a_rotation_of_the_x509_svid_is_followed ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 27.79s"
case_ "a suite counted by its file runs when cargo writes in colour" 0 "ok: 4 passing test(s) from the spire suite." 0 "$SPIRE_COLOURED" spire
case_ "in colour, a binary from another file is not the suite's" 1 "no passing test ran from the suite(s): spire" 0 \
  "${SPIRE_COLOURED//spire_live/workload_live}" spire

SPIRE_IGNORED_COLOURED="${ESC}[1m${ESC}[92m     Running${ESC}[0m tests/spire_live.rs (target/debug/deps/spire_live-0123)

running 4 tests
test spire_live::a_rotation_of_the_x509_svid_is_followed ... ignored
test spire_live::an_x509_svid_arrives_with_the_bundle_that_verifies_it ... ignored

test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 2 filtered out; finished in 0.00s

${ESC}[1m${ESC}[92m     Running${ESC}[0m tests/returns_early.rs (target/debug/deps/returns_early-4567)

running 1 test
test passes_without_its_server ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"
case_ "in colour, a suite whose tests were all ignored is refused" 1 "no passing test ran from the suite(s): spire" 0 \
  "$SPIRE_IGNORED_COLOURED" spire

HARNESS_COLOURED="     Running tests/spire_live.rs (target/debug/deps/spire_live-0123)

running 1 test
test spire_live::the_last_entry_deleted_is_refused_by_the_agent_and_withdrawn ... ${ESC}[32mok${ESC}[0m

test result: ${ESC}[32mok${ESC}[0m. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 9.01s"
case_ "a result the test harness writes in colour counts" 0 "OK: tests: 1 passed, 0 failed, over 1 result lines; every suite ran: spire" 0 \
  "$HARNESS_COLOURED" spire

echo "check-test-log tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
