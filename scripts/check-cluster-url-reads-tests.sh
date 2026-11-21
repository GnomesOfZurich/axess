#!/usr/bin/env bash
# axess: crafted cases for scripts/check-cluster-url-reads.sh.
#
# Each case writes Rust files under a temporary root, runs the check against
# it with `--root`, and asserts the exit status and a fragment of the output.
# The refusals are the contract: a read of VALKEY_CLUSTER_URL through any of
# std's readers, written out or through a `use` of std in scope, is refused
# everywhere but in `cluster_url` after its guard, and in `cluster_url` when
# the guard does not open it. What is no read passes: a mention in a comment
# or a string, the tokens of a macro invocation or definition, another
# variable, a function, module, macro or local of the tree's own under a
# reader's name, a method under a reader's name with any space or comment
# after its dot, a `use` out of scope, compiled out or shadowed, and a
# literal that is not the whole argument.
#
# Usage: ./scripts/check-cluster-url-reads-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-cluster-url-reads.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-cluster-url-reads.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case_ NAME EXPECTED_EXIT FRAGMENT [UNWANTED] -- FILE CONTENT [FILE CONTENT...]
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

OK="ok: in"
HELPER=axess-core/src/testing/valkey_cluster.rs
GUARD='    if let Some(refusal) = partition_refusal(std::thread::current().name()) {
        panic!("{refusal}");
    }'
READ='    std::env::var("VALKEY_CLUSTER_URL").unwrap_or_else(|_| "redis-cluster://127.0.0.1:7001".into())'
GUARDED="pub(crate) fn cluster_url() -> String {
$GUARD
$READ
}"
T=a/src/t.rs

# The one allowed read.
case_ "the read in cluster_url after its guard passes" 0 "(1 read(s) there)" -- "$HELPER" "$GUARDED"
case_ "cluster_url without its guard is refused" 1 "$HELPER:2: std::env::var(\"VALKEY_CLUSTER_URL\") (no cluster_url here opens with its guard)" -- \
  "$HELPER" "pub(crate) fn cluster_url() -> String {
$READ
}"
case_ "a read in cluster_url before its guard is refused" 1 "$HELPER:2: std::env::var" -- \
  "$HELPER" "pub(crate) fn cluster_url() -> String {
    let url = std::env::var(\"VALKEY_CLUSTER_URL\");
$GUARD
    url.unwrap_or_default()
}"
case_ "a guard that does not panic is no guard" 1 "(no cluster_url here opens with its guard)" -- \
  "$HELPER" "pub(crate) fn cluster_url() -> String {
    if let Some(refusal) = partition_refusal(std::thread::current().name()) {
        eprintln!(\"{refusal}\");
    }
$READ
}"
case_ "a read elsewhere in the helper's file is refused" 1 "$HELPER:8: option_env!(\"VALKEY_CLUSTER_URL\")" "$HELPER:5" -- \
  "$HELPER" "$GUARDED
#[test]
fn valkey_cluster_reads_it_itself() { let _ = option_env!(\"VALKEY_CLUSTER_URL\"); }"
case_ "a cluster_url with its guard in another file is refused" 1 "a/src/testing/valkey_cluster.rs:5" -- \
  a/src/testing/valkey_cluster.rs "$GUARDED"

# Each reader, written out.
case_ "std::env::var in a test is refused" 1 "$T:2: std::env::var(\"VALKEY_CLUSTER_URL\")" -- \
  "$T" '#[test]
fn valkey_logout_cluster() { let _ = std::env::var("VALKEY_CLUSTER_URL"); }'
case_ "var_os is refused" 1 "$T:1: std::env::var_os(" -- \
  "$T" 'fn f() { let _ = std::env::var_os("VALKEY_CLUSTER_URL"); }'
case_ "env! with a message is refused" 1 "$T:1: env!(\"VALKEY_CLUSTER_URL\"," -- \
  "$T" 'const URL: &str = env!("VALKEY_CLUSTER_URL", "set the cluster");'
case_ "option_env! and a macro under core are refused" 1 "$T:2: core::option_env!" "$OK" -- \
  "$T" 'const A: Option<&str> = option_env!("VALKEY_CLUSTER_URL");
const B: Option<&str> = core::option_env!["VALKEY_CLUSTER_URL"];'
case_ "a rooted path, a turbofish, a reference and a raw string are refused" 1 "$T:4: std::env::var(\"VALKEY_CLUSTER_URL\")" -- \
  "$T" 'fn f() {
    let _ = ::std::env::var("VALKEY_CLUSTER_URL");
    let _ = std::env::var::<&str>(&"VALKEY_CLUSTER_URL");
    let _ = std::env::var(r#"VALKEY_CLUSTER_URL"#);
}'
case_ "a read written over lines and spaces is refused" 1 "$T:2: std :: env ::" -- \
  "$T" 'fn f() {
    let _ = std :: env
        ::var(
            "VALKEY_CLUSTER_URL" );
}'
case_ "a read after an escaped quote beside a double quote is found" 1 "$T:2: std::env::var" -- \
  "$T" "const Q: [char; 2] = ['\\'','\"'];
fn f() { let _ = std::env::var(\"VALKEY_CLUSTER_URL\"); }"

# Through a `use` of std in scope.
case_ "env::var under use std::env is refused" 1 "$T:2: env::var(" -- \
  "$T" 'use std::env;
fn f() { let _ = env::var("VALKEY_CLUSTER_URL"); }'
case_ "the module under another name is refused" 1 "$T:2: e::var(" -- \
  "$T" 'use std::env as e;
fn f() { let _ = e::var("VALKEY_CLUSTER_URL"); }'
case_ "an imported function is refused" 1 "$T:2: var(" -- \
  "$T" 'use std::env::var;
fn f() { let _ = var("VALKEY_CLUSTER_URL"); }'
case_ "a function renamed in a nested use tree is refused" 1 "$T:2: vo(" -- \
  "$T" 'use std::{env::{self as e, var_os as vo}, io};
fn f() { let _ = vo("VALKEY_CLUSTER_URL"); }'
case_ "a renamed macro is refused" 1 "$T:2: oe!(" -- \
  "$T" 'use std::option_env as oe;
const A: Option<&str> = oe!("VALKEY_CLUSTER_URL");'
case_ "a test module that glob-imports its parent's import is refused" 1 "$T:5: var(" -- \
  "$T" 'use std::env::var;
#[cfg(test)]
mod tests {
    use super::*;
    fn f() { let _ = var("VALKEY_CLUSTER_URL"); }
}'
case_ "a use in the function's body is refused" 1 "$T:3: get(" -- \
  "$T" 'fn f() {
    use std::env::var as get;
    let _ = get("VALKEY_CLUSTER_URL");
}'

# What is no read passes.
SQ="'"
case_ "comments, doc comments, a reason and a string pass" 0 "$OK" -- \
  "$T" "//! Set \`VALKEY_CLUSTER_URL\`: std::env::var(\"VALKEY_CLUSTER_URL\") reads it.
/// \`\`\`
/// let url = std::env::var(\"VALKEY_CLUSTER_URL\");
/// \`\`\`
#[test]
#[ignore = \"requires a Valkey cluster (VALKEY_CLUSTER_URL)\"]
fn t() { let _ = \"std::env::var(\\\"VALKEY_CLUSTER_URL\\\")\"; /* env!(\"VALKEY_CLUSTER_URL\") */ }
const Q: [char; 2] = [${SQ}\\${SQ}${SQ},${SQ}\"${SQ}]; // std::env::var(\"VALKEY_CLUSTER_URL\")"
case_ "another variable, a write and a removal pass" 0 "$OK" -- \
  "$T" 'fn f() {
    let _ = std::env::var("VALKEY_URL");
    let _ = std::env::var("VALKEY_CLUSTER_URL_2");
    unsafe { std::env::set_var("VALKEY_CLUSTER_URL", "x") };
    unsafe { std::env::remove_var("VALKEY_CLUSTER_URL") };
}'
case_ "the tokens of a macro invocation or definition pass" 0 "$OK" -- \
  "$T" 'const A: &str = stringify!(std::env::var("VALKEY_CLUSTER_URL"));
const B: &str = stringify!(env!("VALKEY_CLUSTER_URL"));
macro_rules! url { () => { std::env::var("VALKEY_CLUSTER_URL") }; }
fn f() { let _ = !(true); other::wrap! { let _ = std::env::var("VALKEY_CLUSTER_URL"); } }'
case_ "an import in a macro's tokens binds nothing" 0 "$OK" -- \
  "$T" 'other::items!(use std::env::var;);
use crate::helpers::*;
fn f() { let _ = var("VALKEY_CLUSTER_URL"); }'
case_ "the tokens of an attribute pass" 0 "$OK" -- \
  "$T" '#[derive(Thing)]
struct S {
    #[thing(default = std::env::var("VALKEY_CLUSTER_URL"))]
    url: String,
}'
case_ "an item a macro of the tree defines beside the call shadows an imported reader" 0 "$OK" -- \
  a/src/defs.rs 'macro_rules! def { () => { fn var(_: &str) {} }; }' \
  "$T" 'use std::env::var;
fn f() {
    crate::def!();
    var("VALKEY_CLUSTER_URL");
}'
case_ "a read after a negation is refused" 1 "$T:1: std::env::var(" -- \
  "$T" 'fn f() -> bool { return !(std::env::var("VALKEY_CLUSTER_URL").is_ok()); }'
case_ "a literal that is not the whole argument passes" 0 "$OK" -- \
  "$T" 'fn f() {
    let _ = std::env::var(&"VALKEY_CLUSTER_URL"[..6]);
    let _ = std::env::var("VALKEY_CLUSTER_URL".to_lowercase());
}'
case_ "a function, a method and a module of the tree's own under a reader's name pass" 0 "$OK" -- \
  "$T" 'fn var(name: &str) -> &str { name }
mod env { pub fn var(_: &str) {} }
fn f(c: &Config) {
    let _ = var("VALKEY_CLUSTER_URL");
    env::var("VALKEY_CLUSTER_URL");
    c.var("VALKEY_CLUSTER_URL");
    Config::var("VALKEY_CLUSTER_URL");
}'
case_ "a method under an imported reader's name passes, whatever stands after the dot" 0 "$OK" -- \
  "$T" 'use std::env::var as get;
fn f(m: &Map) {
    let _ = get("HOME");
    let _ = m. get("VALKEY_CLUSTER_URL");
    let _ = m
        .
        get("VALKEY_CLUSTER_URL");
    let _ = m./* the caller'"'"'s map */get("VALKEY_CLUSTER_URL");
    let _ = m. get::<String>("VALKEY_CLUSTER_URL");
}'
case_ "a local or an inner function that shadows an imported reader passes" 0 "$OK" -- \
  "$T" 'use std::env::var;
fn f() {
    let var = |name: &str| name.len();
    let _ = var("VALKEY_CLUSTER_URL");
}' a/src/u.rs 'use std::env::var;
fn g() {
    fn var(_: &str) {}
    var("VALKEY_CLUSTER_URL");
}'
case_ "an import out of scope passes" 0 "$OK" -- \
  "$T" 'mod a { use std::env::var; }
mod b {
    use crate::helpers::*;
    fn f() { let _ = var("VALKEY_CLUSTER_URL"); }
}
fn g() { use std::env::var; }
fn h() { let _ = var("VALKEY_CLUSTER_URL"); }'
case_ "a glob import between the import and the call passes" 0 "$OK" -- \
  "$T" 'use std::env::var;
fn f() {
    use crate::helpers::*;
    let _ = var("VALKEY_CLUSTER_URL");
}'
case_ "an import an attribute may compile out passes" 0 "$OK" -- \
  "$T" '#[cfg(any())]
use std::env::var;
use crate::helpers::*;
fn f() { let _ = var("VALKEY_CLUSTER_URL"); }'
case_ "a module std of the tree's own, here or glob-imported, passes" 0 "$OK" -- \
  a/src/shadow.rs 'pub mod std { pub mod env { pub fn var(_: &str) {} } }
fn f() { std::env::var("VALKEY_CLUSTER_URL"); }' \
  a/src/user.rs 'use crate::shadow::*;
fn g() { std::env::var("VALKEY_CLUSTER_URL"); }'
case_ "a rooted path still names the crate beside a module std of the tree's own" 1 "a/src/user.rs:2: ::std::env::var(" -- \
  a/src/shadow.rs 'pub mod std {}' \
  a/src/user.rs 'use crate::shadow::*;
fn g() { let _ = ::std::env::var("VALKEY_CLUSTER_URL"); }'
case_ "a macro env of the tree's own and an import under the name pass" 0 "$OK" -- \
  a/src/m.rs 'macro_rules! env { ($e:expr) => { $e }; }
const A: &str = env!("VALKEY_CLUSTER_URL");' \
  a/src/n.rs 'use std::format as env;
fn f() { let _ = env!("VALKEY_CLUSTER_URL"); }'
case_ "a macro_use import leaves the bare macros unread" 0 "$OK" -- \
  a/src/lib.rs '#[macro_use]
extern crate other;
const A: &str = env!("VALKEY_CLUSTER_URL");'

# Nothing to read.
case_ "an empty root is refused" 1 "read no Rust file" --

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
listed "$CHECK" "an untracked file is read" 1 "a/src/new.rs:1" "ignored.rs" \
  a/src/new.rs 'fn f() { let _ = std::env::var("VALKEY_CLUSTER_URL"); }' \
  a/src/ignored.rs 'fn f() { let _ = std::env::var("VALKEY_CLUSTER_URL"); }'
listed "$CHECK" "an ignored file is not read" 0 "$OK" "ignored.rs" \
  a/src/a.rs 'fn f() {}' a/src/ignored.rs 'fn f() { let _ = std::env::var("VALKEY_CLUSTER_URL"); }'

echo "check-cluster-url-reads-tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
