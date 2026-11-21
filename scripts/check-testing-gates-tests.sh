#!/usr/bin/env bash
# axess: crafted cases for scripts/check-testing-gates.sh.
#
# Each case writes crate manifests and roots under a temporary root, runs
# the check against it with `--root`, and asserts the exit status and a
# fragment of the output.
#
# Usage: ./scripts/check-testing-gates-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-testing-gates.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-testing-gates.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case NAME EXPECTED_EXIT FRAGMENT -- FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3"
  shift 4
  local root="$WORK/$passed-$failed"
  while [ $# -gt 0 ]; do
    mkdir -p "$root/$(dirname "$1")"
    printf '%s\n' "$2" > "$root/$1"
    shift 2
  done
  local out status
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

GATED_MANIFEST='[package]
name = "axess-x"

[features]
testing = []
allow-testing-in-release = []

[dependencies]
serde = "1"'
GATE='//! A crate.
#[cfg(all(
    feature = "testing",
    not(debug_assertions),
    not(feature = "allow-testing-in-release")
))]
compile_error!("the `testing` feature of axess-x is enabled in a release build");

pub fn f() {}'
UNGATED_MANIFEST='[package]
name = "axess-y"

[features]
testing = []'

case_ "a gated crate passes" 0 "OK: every crate" -- axess-x/Cargo.toml "$GATED_MANIFEST" axess-x/src/lib.rs "$GATE"
case_ "a crate with no testing feature needs no gate" 0 "OK: every crate" -- \
  axess-z/Cargo.toml '[package]
name = "axess-z"
[features]
serde = []' axess-z/src/lib.rs 'pub fn f() {}'
case_ "a testing feature without the opt-out is refused" 1 "axess-y defines the testing feature with no allow-testing-in-release opt-out" -- \
  axess-y/Cargo.toml "$UNGATED_MANIFEST" axess-y/src/lib.rs "$GATE"
case_ "a testing feature without the gate is refused" 1 "axess-x/src/lib.rs carries no release-build gate" -- \
  axess-x/Cargo.toml "$GATED_MANIFEST" axess-x/src/lib.rs 'pub fn f() {}'
case_ "a gate missing one condition is refused" 1 "carries no release-build gate" -- \
  axess-x/Cargo.toml "$GATED_MANIFEST" axess-x/src/lib.rs '#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("x");'
case_ "the fixture crate is not held to the gate" 0 "OK: every crate" -- \
  axess-testing/Cargo.toml "$UNGATED_MANIFEST" axess-testing/src/lib.rs 'pub fn f() {}'
case_ "an example enabling the opt-out in its dependencies is refused" 1 "examples/demo enables allow-testing-in-release under [dependencies]" -- \
  examples/demo/Cargo.toml '[package]
name = "axess-example-demo"

[dependencies]
axess = { path = "../../axess", features = ["testing", "allow-testing-in-release"] }

[dev-dependencies]
serde = "1"'
case_ "an example enabling the opt-out in its dev-dependencies passes" 0 "OK: every crate" -- \
  examples/demo/Cargo.toml '[package]
name = "axess-example-demo"

[dependencies]
axess = { path = "../../axess", features = ["testing"] }

[dev-dependencies]
axess-clock = { path = "../../axess-clock", features = ["testing", "allow-testing-in-release"] }'

echo "check-testing-gates tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
