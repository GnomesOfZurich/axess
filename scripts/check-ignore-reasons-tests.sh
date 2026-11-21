#!/usr/bin/env bash
# axess: crafted cases for scripts/check-ignore-reasons.sh.
#
# Each case writes Rust files under a temporary root, runs the check against
# it with `--root`, and asserts the exit status and a fragment of the output.
# The refusals are the contract: an ignore attribute without a reason is
# named by file and line, wherever in the attribute it stands, and text that
# only looks like one (a comment, a string, another attribute) is not.
#
# Usage: ./scripts/check-ignore-reasons-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-ignore-reasons.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-ignore-reasons.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case NAME EXPECTED_EXIT FRAGMENT [UNWANTED] -- FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3" unwanted=""
  shift 3
  if [ "$1" != "--" ]; then unwanted="$1"; shift; fi
  shift
  local root="$WORK/$passed-$failed"
  mkdir -p "$root"
  while [ $# -gt 0 ]; do
    mkdir -p "$root/$(dirname "$1")"
    printf '%s\n' "$2" > "$root/$1"
    shift 2
  done
  local out status
  out="$("$CHECK" --root "$root" 2>&1)"
  status=$?
  rm -rf "$root"
  if [ "$status" -eq "$want" ] && grep -qF -- "$fragment" <<<"$out" \
     && { [ -z "$unwanted" ] || ! grep -qF -- "$unwanted" <<<"$out"; }; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment'${unwanted:+ and without '$unwanted'}, got exit $status:" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

REASONED='#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a() {}'
case_ "an ignore with a reason passes" 0 "ok: 1 ignore attribute(s) in 1 file(s)" -- a/tests/t.rs "$REASONED"

# The two forms the tree held: a bare attribute, and a bare attribute with
# the reason in a comment beside it, which `cargo test` never prints.
case_ "a bare ignore is refused" 1 "a/tests/t.rs:2: #[ignore] without a reason" -- a/tests/t.rs '#[test]
#[ignore]
fn a() {}'
case_ "a reason in a comment is not a reason" 1 "a/tests/t.rs:2: #[ignore] without a reason" -- a/tests/t.rs '#[test]
#[ignore] // Requires POSTGRES_URL
fn a() {}'
case_ "the count names the bad ones among all" 1 "1 of 2 ignore attribute(s) give no reason" -- a/tests/t.rs "$REASONED
#[test]
#[ignore]
fn b() {}"
case_ "each bare ignore is named" 1 "a/src/y.rs:1: #[ignore] without a reason" -- a/src/x.rs "$REASONED" a/src/y.rs '#[ignore]
fn b() {}'

# A reason has to say something.
case_ "an empty reason is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = ""]
fn a() {}'
case_ "a reason of spaces is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = "   "]
fn a() {}'
case_ "a reason with no letter is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = "..."]
fn a() {}'
# A reason is the string, not its spelling: an escape is the character it
# stands for.
case_ "a reason of one escaped line break is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = "\n"]
fn a() {}'
case_ "a reason of escaped tabs is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = "\t\t\r\0"]
fn a() {}'
case_ "a reason of an escaped code point for a blank is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = "\u{20}\u{2e}"]
fn a() {}'
case_ "a reason of escaped bytes for punctuation is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = "\x20\x2e\\\""]
fn a() {}'
case_ "a reason that is only a line continuation is refused, at the line its literal ends on" 1 "a/tests/t.rs:2: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = "\
    "]
fn a() {}'
case_ "a reason spelled with escaped letters passes" 0 "ok: 1 ignore attribute(s)" -- a/tests/t.rs '#[ignore = "\u{6e}eeds \x61 server"]
fn a() {}'
case_ "a reason after an escaped line break passes" 0 "ok: 1 ignore attribute(s)" -- a/tests/t.rs '#[ignore = "\nrequires a server"]
fn a() {}'
case_ "a raw string is read as written" 0 "ok: 1 ignore attribute(s)" -- a/tests/t.rs '#[ignore = r"\n"]
fn a() {}'
case_ "an empty raw string is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[ignore = r#""#]
fn a() {}'
case_ "a raw string with a reason passes" 0 "ok: 1 ignore attribute(s)" -- a/tests/t.rs '#[ignore = r#"requires a "quoted" server"#]
fn a() {}'
case_ "a reason holding a bracket and a quote passes" 0 "ok: 1 ignore attribute(s)" -- a/tests/t.rs '#[ignore = "needs ] and \" in it"]
fn a() {}'

# However the attribute is written.
case_ "spacing inside the attribute is refused alike" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '# [ ignore ]
fn a() {}'
case_ "an attribute over several lines is named by its first" 1 "a/tests/t.rs:2: #[ignore] without a reason" -- a/tests/t.rs '#[test]
#[
    ignore
]
fn a() {}'
case_ "a reason on a later line of the attribute passes" 0 "ok: 1 ignore attribute(s)" -- a/tests/t.rs '#[ignore =
    "requires a running Valkey (VALKEY_URL)"]
fn a() {}'
case_ "a bare ignore sharing a line with the test attribute is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[test] #[ignore] fn a() {}'

# Under cfg_attr the ignore is the same attribute, applied on a condition.
case_ "a conditional ignore with a reason passes" 0 "ok: 1 ignore attribute(s)" -- a/tests/t.rs '#[cfg_attr(miri, ignore = "too slow to interpret")]
fn a() {}'
case_ "a bare conditional ignore is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[cfg_attr(miri, ignore)]
fn a() {}'
case_ "a bare ignore after another conditional attribute is refused" 1 "a/tests/t.rs:1: #[ignore] without a reason" -- a/tests/t.rs '#[cfg_attr(any(miri, feature = "x"), allow(unused), ignore)]
fn a() {}'
case_ "a bare ignore under a nested cfg_attr is refused" 1 "a/tests/t.rs:2: #[ignore] without a reason" -- a/tests/t.rs '#[test]
#[cfg_attr(
    miri,
    cfg_attr(feature = "x", ignore)
)]
fn a() {}'
case_ "a condition named ignore is not an ignore" 0 "ok: 0 ignore attribute(s)" -- a/tests/t.rs '#[cfg_attr(ignore, allow(unused))]
fn a() {}'

# Text that is not an attribute.
case_ "an ignore in a comment passes" 0 "ok: 0 ignore attribute(s)" -- a/src/x.rs '// These are #[ignore]d until the server is up.
/* #[ignore] */
fn a() {}'
case_ "an ignore in a doc comment passes" 0 "ok: 0 ignore attribute(s)" -- a/src/x.rs '//! The tests that use these are `#[ignore]`d.
/// ```rust,ignore
/// #[ignore]
/// ```
fn a() {}'
case_ "an ignore in a string passes" 0 "ok: 0 ignore attribute(s)" -- a/src/x.rs 'const S: &str = "#[ignore]";
const R: &str = r#"
#[ignore]
"#;'
case_ "another attribute that says ignore passes" 0 "ok: 0 ignore attribute(s)" -- a/src/x.rs '#[serde(ignore)]
#[doc = "ignore"]
#[ignored]
struct A;'
case_ "a bare ignore after a string that holds one is refused" 1 "a/src/x.rs:3: #[ignore] without a reason" -- a/src/x.rs 'const S: &str = "#[ignore = \"x\"]";
#[test]
#[ignore]
fn a() {}'

# A run that read nothing checked nothing.
case_ "a root with no Rust file is refused" 1 "no Rust file read" --

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
BARE='#[test]
#[ignore]
fn a() {}'
listed "$CHECK" "an untracked file is read" 1 "a/tests/new.rs:2: #[ignore] without a reason" "ignored.rs" \
  a/tests/t.rs "$REASONED" a/tests/new.rs "$BARE" a/tests/ignored.rs "$BARE"
listed "$CHECK" "an ignored file is not read" 0 "ok: 1 ignore attribute(s) in 1 file(s)" "ignored.rs" \
  a/tests/t.rs "$REASONED" a/tests/ignored.rs "$BARE"

echo "check-ignore-reasons tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
