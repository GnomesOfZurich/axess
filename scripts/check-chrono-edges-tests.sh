#!/usr/bin/env bash
# axess: crafted cases for the text rule of scripts/check-chrono-edges.sh.
#
# Each case writes Rust files under a temporary root, runs the check on it
# with `--text-root`, and asserts the exit status and a fragment of the
# output. The refusals are the contract: library code names chrono only in
# the boundary file, and there in no public item. The manifest, lock and
# tree parts of the check read cargo's own answers and are run on the
# repository itself.
#
# Usage: ./scripts/check-chrono-edges-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-chrono-edges.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-chrono-edges.XXXXXX")"
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
  out="$("$CHECK" --text-root "$root" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

OK="ok: no public item names chrono"
BOUNDARY=axess-factors/src/oauth/provider.rs

case_ "library code that names no chrono passes" 0 "$OK" -- \
  axess-core/src/a.rs 'pub fn f(now: axess_clock::Timestamp) {}'
case_ "a chrono type in a public signature is refused" 1 "axess-core/src/a.rs:1: library code names chrono outside the boundary" -- \
  axess-core/src/a.rs 'pub fn f(now: chrono::DateTime<chrono::Utc>) {}'
case_ "a chrono value in private code outside the boundary is refused" 1 "axess-core/src/a.rs:2: library code names chrono outside the boundary" -- \
  axess-core/src/a.rs 'fn f() {
    let _ = chrono::Duration::seconds(1);
}'
case_ "an import of chrono outside the boundary is refused" 1 "axess-cache/src/lib.rs:1: library code names chrono" -- \
  axess-cache/src/lib.rs 'use chrono::Utc;'
case_ "chrono in a comment, a doc comment or a string passes" 0 "$OK" -- \
  axess-core/src/a.rs '/// Earlier releases held this as a chrono value.
// chrono::Utc::now() was the read.
pub fn f() -> &'"'"'static str { "chrono" }'
case_ "a name that only contains the word passes" 0 "$OK" -- \
  axess-core/src/a.rs 'pub fn synchronous() {} pub fn chronology() {}'
case_ "chrono in a test module of library code passes" 0 "$OK" -- \
  axess-core/src/a.rs 'pub fn f() {}
#[cfg(test)]
mod tests {
    fn t() { let _ = chrono::Utc; }
}'
case_ "chrono in a test file and in an integration test passes" 0 "$OK" -- \
  axess-core/src/a/tests.rs 'fn t() { let _ = chrono::Utc; }' \
  axess-clock/tests/chrono_agreement.rs 'use chrono::Utc;'
case_ "an example's own code is not this rule's" 0 "$OK" -- \
  examples/sqlite/src/main.rs 'use chrono::Utc;'
case_ "the private conversion in the boundary file passes" 0 "$OK" -- \
  "$BOUNDARY" 'fn chrono_time(at: Timestamp) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::UNIX_EPOCH
}
pub fn provider() -> u8 { 1 }'
case_ "a crate-private item in the boundary file may carry the value" 0 "$OK" -- \
  "$BOUNDARY" 'impl P {
    pub(crate) fn time_fn(
        &self,
    ) -> impl Fn() -> chrono::DateTime<chrono::Utc> + Send {
        move || chrono::DateTime::UNIX_EPOCH
    }
}'
case_ "a public function in the boundary file that returns chrono is refused" 1 "$BOUNDARY:2: a public item names chrono" -- \
  "$BOUNDARY" 'impl P {
    pub fn time_fn(
        &self,
    ) -> impl Fn() -> chrono::DateTime<chrono::Utc> + Send {
        todo()
    }
}'
case_ "a public function in the boundary file that takes chrono is refused" 1 "$BOUNDARY:1: a public item names chrono" -- \
  "$BOUNDARY" 'pub async fn at(when: chrono::DateTime<chrono::Utc>) {}'
case_ "a public field of a chrono type in the boundary file is refused" 1 "$BOUNDARY:2: a public item names chrono" -- \
  "$BOUNDARY" 'pub struct Claims {
    pub issued: chrono::DateTime<chrono::Utc>,
    private: u8,
}'
case_ "a private field of a chrono type in the boundary file passes" 0 "$OK" -- \
  "$BOUNDARY" 'pub struct Claims {
    issued: chrono::DateTime<chrono::Utc>,
}'
case_ "a public re-export of chrono in the boundary file is refused" 1 "$BOUNDARY:1: a public item names chrono" -- \
  "$BOUNDARY" 'pub use chrono::DateTime;'
case_ "a public alias of a chrono type in the boundary file is refused" 1 "$BOUNDARY:1: a public item names chrono" -- \
  "$BOUNDARY" 'pub type Stamp = chrono::DateTime<chrono::Utc>;'
case_ "a public constant of a chrono type in the boundary file is refused" 1 "$BOUNDARY:1: a public item names chrono" -- \
  "$BOUNDARY" 'pub const LATEST: chrono::DateTime<chrono::Utc> = chrono::DateTime::<chrono::Utc>::MAX_UTC;'
case_ "chrono in the body of a public function of the boundary file passes" 0 "$OK" -- \
  "$BOUNDARY" 'pub fn verify(now: Timestamp) -> bool {
    let _ = chrono::DateTime::from_timestamp(now.unix_seconds(), 0);
    true
}'

echo "check-chrono-edges tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
