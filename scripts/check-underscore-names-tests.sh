#!/usr/bin/env bash
# axess: crafted cases for scripts/check-underscore-names.sh.
#
# Each case writes Rust files under a temporary root, runs the check
# against it with `--root`, and asserts the exit status and a fragment of
# the output. The refusals are the contract: an underscore-prefixed name is
# named by file, line and name in every position a binding takes (a
# parameter, a field, a `let`, a closure parameter, a pattern, a doc
# example's code), and what only looks like one (the bare `_`, a name with
# two underscores, a number, a lifetime, a comment, a string) is not
# refused.
#
# Usage: ./scripts/check-underscore-names-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-underscore-names.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-underscore-names.XXXXXX")"
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
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out" "$unwanted"
}

CLEAN='fn a(b: u8) -> u8 { b }'
case_ "a file with no such name passes" 0 "ok: no underscore-prefixed name in 1 Rust file(s)" -- a/src/lib.rs "$CLEAN"
case_ "no Rust file is no pass" 1 "ERROR: no Rust file read" -- a/README.md "nothing"

# Every position a binding takes.
case_ "a parameter is refused" 1 "a/src/lib.rs:1: _x" -- a/src/lib.rs 'fn f(_x: u8) {}'
case_ "a trait method's parameter is refused" 1 "a/src/lib.rs:2: _state" -- a/src/lib.rs 'impl A for B {
    fn f(&self, _state: &S) {}
}'
case_ "a closure parameter is refused" 1 "a/src/lib.rs:1: _x" -- a/src/lib.rs 'fn f() { g(|_x| 1); }'
case_ "a typed closure parameter is refused" 1 "a/src/lib.rs:1: _slug" -- a/src/lib.rs 'fn f() { g(move |_slug: &str| None); }'
case_ "a held guard is refused" 1 "a/src/lib.rs:2: _g" -- a/src/lib.rs 'fn f() {
    let _g = lock();
}'
case_ "a mutable binding is refused" 1 "a/src/lib.rs:1: _g" -- a/src/lib.rs 'fn f() { let mut _g = 1; }'
case_ "a ref binding is refused" 1 "a/src/lib.rs:1: _g" -- a/src/lib.rs 'fn f() { let ref _g = 1; }'
case_ "a field is refused" 1 "a/src/lib.rs:1: _f" -- a/src/lib.rs 'struct S { _f: u8 }'
case_ "a field set in a literal is refused" 1 "a/src/lib.rs:1: _hold" -- a/src/lib.rs 'fn f(hold: H) -> W { W { _hold: hold } }'
case_ "a variant's pattern is refused" 1 "a/src/lib.rs:1: _x" -- a/src/lib.rs 'fn f(o: Option<u8>) -> bool { matches!(o, Some(_x)) }'
case_ "a parenthesised pattern is refused" 1 "a/src/lib.rs:1: _e" -- a/src/lib.rs 'fn f(r: Result<u8, E>) { if let Err(_e) = r {} }'
case_ "a tuple pattern is refused" 1 "a/src/lib.rs:1: _url" -- a/src/lib.rs 'fn f() { let (_url, ctx) = begin(); }'
case_ "a match arm binding is refused" 1 "a/src/lib.rs:1: _other" -- a/src/lib.rs 'fn f(n: u8) { match n { 1 => {} _other => {} } }'
case_ "a for binding is refused" 1 "a/src/lib.rs:1: _i" -- a/src/lib.rs 'fn f() { for _i in 0..3 {} }'
case_ "a macro metavariable is refused" 1 "a/src/lib.rs:1: _t" -- a/src/lib.rs 'macro_rules! m { ($_t:ty) => {}; }'
case_ "a raw identifier is refused" 1 "a/src/lib.rs:1: _x" -- a/src/lib.rs 'fn f() { let r#_x = 1; }'
case_ "a name in a test file is refused" 1 "a/tests/t.rs:1: _clock" -- a/tests/t.rs 'fn f() { let (s, _clock) = store(); }'
case_ "a name after a string on its line is refused" 1 "a/src/lib.rs:1: _y" -- a/src/lib.rs 'fn f() { let a = r#"_x " still"#; let _y = a; }'
case_ "a name after a block comment on its line is refused" 1 "a/src/lib.rs:1: _y" -- a/src/lib.rs 'fn f() { /* _x */ let _y = 1; }'
case_ "every name on a line is named" 1 "a/src/lib.rs:1: _b" -- a/src/lib.rs 'fn f(_a: u8, _b: u8) {}'
case_ "the count names the refused and their files" 1 "3 underscore-prefixed name(s) refused in 2 file(s)" -- a/src/x.rs 'fn f(_a: u8, _b: u8) {}' a/src/y.rs 'fn g() { let _c = 1; }'

# The code of a doc example, which rustdoc compiles.
case_ "a name in a doc example is refused" 1 "a/src/lib.rs:2: _cleanup (in a doc example)" -- a/src/lib.rs '/// ```
/// let _cleanup = spawn();
/// ```
fn a() {}'
case_ "a name on a hidden doc line is refused" 1 "a/src/lib.rs:3: _x (in a doc example)" -- a/src/lib.rs '//! Example.
//! ```no_run
//! # let _x = 1;
//! ```'
case_ "a text block in a doc comment is not code" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs '/// ```text
/// let _x = 1;
/// ```
fn a() {}'
case_ "prose in a doc comment is not code" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs '/// Not `_state`, and not `let _g = lock()`.
fn a() {}'

# What only looks like one.
case_ "the bare underscore passes" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs 'impl A for B {
    fn f(&self, _: &S) -> u8 { let _ = g(); match 1 { _ => 0 } }
}'
case_ "a name with two underscores passes" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs 'pub mod __macro_support {}
fn f() { serde::__private::g(); }'
case_ "an underscore inside a name passes" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs 'fn a_b(c_: u8) -> u8 { c_ }'
case_ "an underscore in a number passes" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs 'const A: u64 = 1_000_000; const B: u8 = 0x_f; const C: f64 = 1e_3; const D: u8 = 1_u8;'
case_ "a lifetime passes" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs "fn f<'_a>(x: &'_ str, y: &'_a str) {}"
case_ "a line comment is not code" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs '// let _g = lock();
fn a() {}'
case_ "a block comment is not code" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs '/* fn f(_x: u8) /* nested |_y| */ */
fn a() {}'
case_ "a string is not code" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs 'const A: &str = "_x: u8";'
case_ "a raw string is not code" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs 'const A: &str = r#"let _g = "lock"; "#;'
case_ "a byte string is not code" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs 'const A: &[u8] = b"_x";'
case_ "a char literal is not code" 0 "ok: no underscore-prefixed name" -- a/src/lib.rs "const A: char = '_';"
case_ "a file that is not Rust is not read" 0 "ok: no underscore-prefixed name in 1 Rust file(s)" -- a/src/lib.rs "$CLEAN" a/notes.md 'let _x = 1;'

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
listed "$CHECK" "an untracked file is read" 1 "a/src/new.rs:1: _x" "ignored.rs" \
  a/src/new.rs 'fn f(_x: u8) {}' a/src/ignored.rs 'fn g(_y: u8) {}'
listed "$CHECK" "an ignored file is not read" 0 "ok: no underscore-prefixed name in 1 Rust file(s)" "ignored.rs" \
  a/src/lib.rs "$CLEAN" a/src/ignored.rs 'fn g(_y: u8) {}'

echo "check-underscore-names tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
