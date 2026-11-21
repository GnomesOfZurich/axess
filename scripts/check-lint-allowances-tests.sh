#!/usr/bin/env bash
# axess: crafted cases for scripts/check-lint-allowances.sh.
#
# Each case writes Rust files (and, where it says so, an exemption file or a
# cargo configuration) under a temporary root, runs the check against it
# with `--root`, and asserts the exit status and a fragment of the output.
# The refusals are the contract: an `allow` or `expect` attribute is named
# by file, line and lint in every position and form it can take, an
# attribute a macro argument can fill is refused unless the caller writes
# it whole, and text that only looks like one (a comment, a doc comment, a
# string, a method call) is not refused.
#
# Usage: ./scripts/check-lint-allowances-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-lint-allowances.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-lint-allowances.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0
EMPTY='# no entries'

# case NAME EXPECTED_EXIT FRAGMENT [UNWANTED] -- FILE CONTENT [FILE CONTENT...]
# The exemption file is written empty unless a case writes its own.
case_() {
  local name="$1" want="$2" fragment="$3" unwanted=""
  shift 3
  if [ "$1" != "--" ]; then unwanted="$1"; shift; fi
  shift
  local root="$WORK/$passed-$failed"
  mkdir -p "$root/scripts"
  printf '%s\n' "$EMPTY" > "$root/scripts/lint-allowance-exemptions.txt"
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

CLEAN='fn a() -> u8 { 1 }'
case_ "a file with no allowance passes" 0 "ok: no lint allowance in 1 Rust file(s)" -- a/src/lib.rs "$CLEAN"
case_ "no Rust file is no pass" 1 "ERROR: no Rust file read" -- a/README.md "nothing"

# Every position and form an allowance takes.
case_ "an outer allow is refused" 1 "a/src/lib.rs:1: #[allow(dead_code)]" -- a/src/lib.rs '#[allow(dead_code)]
fn a() {}'
case_ "an inner allow is refused" 1 "a/src/lib.rs:2: #![allow(missing_docs)]" -- a/src/lib.rs '//! A crate.
#![allow(missing_docs)]'
case_ "an outer expect is refused" 1 "a/src/lib.rs:1: #[expect(unused)]" -- a/src/lib.rs '#[expect(unused)]
fn a() {}'
case_ "an inner expect is refused" 1 "a/src/lib.rs:1: #![expect(clippy::all)]" -- a/src/lib.rs '#![expect(clippy::all)]'
case_ "a clippy lint is refused" 1 "a/src/lib.rs:2: #[allow(clippy::cmp_owned)]" -- a/src/lib.rs '#[test]
#[allow(clippy::cmp_owned)]
fn a() {}'
case_ "a rustdoc lint is refused" 1 "a/src/lib.rs:1: #![allow(rustdoc::broken_intra_doc_links)]" -- a/src/lib.rs '#![allow(rustdoc::broken_intra_doc_links)]'
case_ "each lint of a list is named" 1 "a/src/lib.rs:1: #[allow(unused_mut)]" -- a/src/lib.rs '#[allow(dead_code, unused_mut)]
fn a() {}'
case_ "an expect with a reason is refused" 1 "a/src/lib.rs:1: #[expect(dead_code)]" -- a/src/lib.rs '#[expect(dead_code, reason = "kept for later")]
fn a() {}'
case_ "blanks inside the attribute do not hide it" 1 "a/src/lib.rs:1: #![allow(unused)]" -- a/src/lib.rs '# ! [ allow ( unused ) ]'
case_ "an attribute over several lines is named at its first" 1 "a/src/lib.rs:2: #[allow(dead_code)]" -- a/src/lib.rs 'fn a() {}
#[
    allow(
        dead_code
    )
]
fn b() {}'
case_ "an allowance on a statement is refused" 1 "a/src/lib.rs:2: #[allow(unused_variables)]" -- a/src/lib.rs 'fn a() {
    #[allow(unused_variables)]
    let x = 1;
}'
case_ "an allowance on a struct field is refused" 1 "a/src/lib.rs:3: #[allow(dead_code)]" -- a/src/lib.rs '#[derive(Debug)]
struct Holder {
    #[allow(dead_code)]
    key: u8,
}'
case_ "an allowance in a test module is refused" 1 "a/src/tests.rs:3: #[allow(clippy::clone_on_copy)]" -- a/src/tests.rs '#[test]
fn a() {
    #[allow(clippy::clone_on_copy)]
    let b = 1u8.clone();
}'
case_ "an allowance in an integration test is refused" 1 "a/tests/t.rs:1: #![allow(dead_code)]" -- a/tests/t.rs '#![allow(dead_code)]'
case_ "an allowance in a build script is refused" 1 "a/build.rs:1: #![allow(unused)]" -- a/build.rs '#![allow(unused)]
fn main() {}'
case_ "an allowance under cfg_attr is refused" 1 "a/src/lib.rs:1: #[allow(dead_code)]" -- a/src/lib.rs '#[cfg_attr(test, allow(dead_code))]
fn a() {}'
case_ "an inner allowance under cfg_attr is refused" 1 "a/src/lib.rs:1: #![allow(missing_docs)]" -- a/src/lib.rs '#![cfg_attr(feature = "x", allow(missing_docs))]'
case_ "an allowance after another attribute in cfg_attr is refused" 1 "a/src/lib.rs:1: #[expect(unused)]" -- a/src/lib.rs '#[cfg_attr(all(test, unix), derive(Debug), expect(unused))]
struct A;'
case_ "an allowance in a nested cfg_attr is refused" 1 "a/src/lib.rs:1: #[allow(dead_code)]" -- a/src/lib.rs '#[cfg_attr(test, cfg_attr(unix, allow(dead_code)))]
fn a() {}'
case_ "a raw identifier is the same attribute" 1 "a/src/lib.rs:1: #[allow(dead_code)]" -- a/src/lib.rs '#[r#allow(dead_code)]
fn a() {}'
case_ "an allowance handed to another attribute is refused" 1 "a/src/lib.rs:1: #[allow(dead_code)]" -- a/src/lib.rs '#[some_macro(allow(dead_code))]
fn a() {}'
case_ "an allowance a quote! block writes is refused" 1 "a/src/lib.rs:2: #[allow(dead_code)]" -- a/src/lib.rs 'fn a() -> T {
    quote! { #[allow(dead_code)] fn b() {} }
}'
case_ "an allowance a macro transcriber writes is refused" 1 "a/src/lib.rs:3: #[allow(unused)]" -- a/src/lib.rs 'macro_rules! m {
    ($name:ident) => {
        #[allow(unused)]
        fn $name() {}
    };
}'
case_ "an allowance a caller passes to a macro is refused at the call" 1 "a/src/lib.rs:6: #[allow(dead_code)]" -- a/src/lib.rs 'macro_rules! m {
    ($(#[$meta:meta])* $name:ident) => { $(#[$meta])* fn $name() {} };
}
m! {
    /// Documented.
    #[allow(dead_code)]
    b
}'
case_ "every file is named" 1 "a/src/y.rs:1: #[allow(dead_code)]" -- a/src/x.rs "$CLEAN" a/src/y.rs '#[allow(dead_code)]
fn a() {}'
case_ "the count names the refused" 1 "2 allowance(s) refused" -- a/src/lib.rs '#[allow(dead_code)]
fn a() {}
#[expect(unused)]
fn b() {}'

# An attribute a macro argument fills.
case_ "an attribute from a bare macro argument is refused" 1 "a/src/lib.rs:2: #[\$lint]: an attribute built from a macro argument" -- a/src/lib.rs 'macro_rules! m {
    ($lint:meta) => { #[$lint] fn b() {} };
}
m!(allow(dead_code));'
case_ "an attribute from token trees is refused" 1 "a/src/lib.rs:2: #[\$(\$t)*]" -- a/src/lib.rs 'macro_rules! m {
    ($($t:tt)*) => { #[$($t)*] fn b() {} };
}'
case_ "a metavariable inside cfg_attr is refused" 1 "a/src/lib.rs:2: #[cfg_attr(test, \$a)]" -- a/src/lib.rs 'macro_rules! m {
    ($(#[$a:meta])*) => { #[cfg_attr(test, $a)] fn b() {} };
}'
case_ "a binding of another arm does not count" 1 "a/src/lib.rs:3: #[\$a]" -- a/src/lib.rs 'macro_rules! m {
    (#[$a:meta] one) => { fn one() {} };
    ($a:meta) => { #[$a] fn two() {} };
}'
case_ "a quote! interpolation in an attribute is refused" 1 "a/src/lib.rs:2: #[#lint]" -- a/src/lib.rs 'fn a(lint: T) -> T {
    quote! { #[#lint] fn b() {} }
}'
case_ "a bound #[\$name:meta] written as #[\$name] passes" 0 "ok: no lint allowance" -- a/src/lib.rs 'macro_rules! define {
    ($(#[$meta:meta])* pub $name:ident) => {
        $(#[$meta])*
        pub struct $name;
    };
}'
case_ "\$crate in an attribute is a path" 0 "ok: no lint allowance" -- a/src/lib.rs 'macro_rules! m {
    () => { #[$crate::marker] fn b() {} };
}'

# Text that only looks like an allowance.
case_ "a line comment is not code" 0 "ok: no lint allowance" -- a/src/lib.rs '// #[allow(dead_code)]
fn a() {}'
case_ "a block comment is not code" 0 "ok: no lint allowance" -- a/src/lib.rs '/* #[allow(dead_code)] /* nested #![allow(unused)] */ */
fn a() {}'
case_ "a doc comment outside an example is not code" 0 "ok: no lint allowance" -- a/src/lib.rs '//! Write #[allow(unused)] nowhere.
/// Not even `#[allow(dead_code)]`.
fn a() {}'
case_ "a string is not code" 0 "ok: no lint allowance" -- a/src/lib.rs 'const A: &str = "#[allow(dead_code)]";
const B: &str = "#![expect(unused)]";'
case_ "a raw string is not code" 0 "ok: no lint allowance" -- a/src/lib.rs 'const A: &str = r#"#[allow(dead_code)] " still"#;'
case_ "a byte string is not code" 0 "ok: no lint allowance" -- a/src/lib.rs "const A: &[u8] = b\"#[allow(dead_code)]\";"
case_ "a string in a doc attribute is not code" 0 "ok: no lint allowance" -- a/src/lib.rs '#[doc = "write #[allow(x)] nowhere"]
fn a() {}'
case_ "a hash in a char literal opens nothing" 0 "ok: no lint allowance" -- a/src/lib.rs "fn a() { let c = '#'; let v = [allow(1)]; }
fn allow(n: u8) -> u8 { n }"
case_ "expect and allow as calls are not attributes" 0 "ok: no lint allowance" -- a/src/lib.rs 'fn a(r: Option<u8>) -> u8 {
    let v = r.expect("present");
    policy.allow(v);
    expect(v)
}'
case_ "other lint levels pass" 0 "ok: no lint allowance" -- a/src/lib.rs '#![deny(missing_docs)]
#![forbid(unsafe_code)]
#[warn(unused)]
#[should_panic(expected = "boom")]
fn a() {}'
case_ "a word that only starts like one passes" 0 "ok: no lint allowance" -- a/src/lib.rs '#[cfg(allow_x)]
#[serde(allowed = "x")]
fn a() {}'

# The exemption file.
EXEMPT='a/src/gen.rs | dead_code | written by a generator this repository does not own'
case_ "an exempted lint in its file passes" 0 "(1 exempted)" -- scripts/lint-allowance-exemptions.txt "$EXEMPT" a/src/gen.rs '#[allow(dead_code)]
fn a() {}'
case_ "an exemption covers one lint" 1 "a/src/gen.rs:1: #[allow(unused)]" -- scripts/lint-allowance-exemptions.txt "$EXEMPT" a/src/gen.rs '#[allow(dead_code, unused)]
fn a() {}'
case_ "an exemption covers one file" 1 "a/src/other.rs:1: #[allow(dead_code)]" -- scripts/lint-allowance-exemptions.txt "$EXEMPT" a/src/gen.rs '#[allow(dead_code)]
fn a() {}' a/src/other.rs '#[allow(dead_code)]
fn a() {}'
case_ "an exemption that admits nothing is refused" 1 "exempts nothing; remove the entry" -- scripts/lint-allowance-exemptions.txt "$EXEMPT" a/src/gen.rs "$CLEAN"
case_ "an exemption without a reason is refused" 1 "an entry is \`file | lint | reason\`" -- scripts/lint-allowance-exemptions.txt 'a/src/gen.rs | dead_code' a/src/gen.rs '#[allow(dead_code)]
fn a() {}'
case_ "an exemption whose reason holds no word is refused" 1 "the reason holds no word" -- scripts/lint-allowance-exemptions.txt 'a/src/gen.rs | dead_code | ...' a/src/gen.rs '#[allow(dead_code)]
fn a() {}'
case_ "an exemption never covers a macro-built attribute" 1 "an attribute built from a macro argument" -- scripts/lint-allowance-exemptions.txt 'a/src/lib.rs | $lint | a macro' a/src/lib.rs 'macro_rules! m {
    ($lint:meta) => { #[$lint] fn b() {} };
}'

# The cargo configuration.
case_ "an allow flag in the build flags is refused" 1 ".cargo/config.toml: build.rustflags: -Adead_code" -- a/src/lib.rs "$CLEAN" .cargo/config.toml '[build]
rustflags = ["-Adead_code"]'
case_ "an allow flag as two words is refused" 1 ".cargo/config.toml: target.x86_64-unknown-linux-gnu.rustflags: -A" -- a/src/lib.rs "$CLEAN" .cargo/config.toml "[target.x86_64-unknown-linux-gnu]
rustflags = \"-A unused -D warnings\""
case_ "capped lint levels are refused" 1 ".cargo/config.toml: build.rustdocflags: --cap-lints=warn" -- a/src/lib.rs "$CLEAN" .cargo/config.toml '[build]
rustdocflags = ["--cap-lints=warn"]'
case_ "an allow flag in the env table is refused" 1 ".cargo/config.toml: env.RUSTFLAGS: --allow" -- a/src/lib.rs "$CLEAN" .cargo/config.toml '[env]
RUSTFLAGS = { value = "--allow warnings", force = true }'
case_ "a crate attribute flag is refused" 1 ".cargo/config: build.rustflags: -Zcrate-attr=allow(dead_code)" -- a/src/lib.rs "$CLEAN" .cargo/config '[build]
rustflags = ["-Zcrate-attr=allow(dead_code)"]'
case_ "a deny flag passes" 0 "ok: no lint allowance" -- a/src/lib.rs "$CLEAN" .cargo/config.toml '[build]
rustflags = ["-D", "warnings"]
[registry]
global-min-publish-age = "7 days"'

# The code of a doc example, which rustdoc compiles.
case_ "an inner allow in a doc example is refused" 1 "a/src/lib.rs:2: #![allow(unused)] (in a doc example)" -- a/src/lib.rs '//! ```
//! #![allow(unused)]
//! ```'
case_ "an allow in an item's doc example is refused" 1 "a/src/lib.rs:2: #[allow(dead_code)] (in a doc example)" -- a/src/lib.rs '/// ```
/// #[allow(dead_code)]
/// fn a() {}
/// ```
fn a() {}'
case_ "an allow on a hidden line is refused" 1 "a/src/lib.rs:3: #![allow(unused)] (in a doc example)" -- a/src/lib.rs '/// Example.
/// ```
/// # #![allow(unused)]
/// let x = 1;
/// ```
fn a() {}'
case_ "an expect in a rust,no_run example is refused" 1 "a/src/lib.rs:2: #[expect(unused)] (in a doc example)" -- a/src/lib.rs '/// ```rust,no_run
/// #[expect(unused)]
/// fn b() {}
/// ```
fn a() {}'
case_ "an allow in an ignored example is refused" 1 "#[allow(dead_code)] (in a doc example)" -- a/src/lib.rs '/// ```ignore
/// #[allow(dead_code)]
/// ```
fn a() {}'
case_ "an allow in a tilde fence is refused" 1 "#[allow(dead_code)] (in a doc example)" -- a/src/lib.rs '/// ~~~
/// #[allow(dead_code)]
/// ~~~
fn a() {}'
case_ "an allow in an indented example is refused" 1 "a/src/lib.rs:3: #[allow(dead_code)] (in a doc example)" -- a/src/lib.rs '/// Example:
///
///     #[allow(dead_code)]
///     fn b() {}
fn a() {}'
case_ "an allow in an example whose fence a cfg_attr chooses is refused" 1 "a/src/lib.rs:4: #[allow(dead_code)] (in a doc example)" -- a/src/lib.rs '/// Example.
#[cfg_attr(feature = "m", doc = "```no_run")]
#[cfg_attr(not(feature = "m"), doc = "```ignore")]
/// #[allow(dead_code)]
/// ```
fn a() {}'
case_ "an allow in the string of a doc attribute's example is refused" 1 "#[allow(dead_code)] (in a doc example)" -- a/src/lib.rs '#[doc = "```\n#[allow(dead_code)]\nfn b() {}\n```"]
fn a() {}'
case_ "an allow in a block doc comment's example is refused" 1 "a/src/lib.rs:3: #[allow(dead_code)] (in a doc example)" -- a/src/lib.rs '/**
 * ```
 * #[allow(dead_code)]
 * ```
 */
fn a() {}'
case_ "an allow in an included doc file's example is refused" 1 "(in a doc example of a/README.md:3)" -- a/src/lib.rs '#![doc = include_str!("../README.md")]' a/README.md '# A crate
```rust
#[allow(dead_code)]
fn b() {}
```'
case_ "an included doc file that cannot be read is refused" 1 "an included doc file that cannot be read" -- a/src/lib.rs '#![doc = include_str!("../MISSING.md")]'
case_ "a text block in a doc comment is not code" 0 "ok: no lint allowance" -- a/src/lib.rs '/// ```text
/// #[allow(dead_code)]
/// ```
fn a() {}'
case_ "a comment in a doc example is not code" 0 "ok: no lint allowance" -- a/src/lib.rs '/// ```
/// // #[allow(dead_code)] is not written here
/// fn b() {}
/// ```
fn a() {}'

# Lint flags set for a build outside the cargo configuration.
WF='on: push
jobs:
  a:
    runs-on: ubuntu-latest'
case_ "an allow flag in a workflow's env is refused" 1 ".github/workflows/w.yml:3: -A: a flag that silences lints" -- a/src/lib.rs "$CLEAN" .github/workflows/w.yml 'on: push
env:
  RUSTFLAGS: -A dead_code -D warnings
jobs: {}'
case_ "capped lints in a job's env are refused" 1 ".github/workflows/w.yml:6: --cap-lints=allow" -- a/src/lib.rs "$CLEAN" .github/workflows/w.yml "$WF
    env:
      RUSTDOCFLAGS: --cap-lints=allow
    steps:
      - run: cargo doc"
case_ "an allow flag in a step's cargo variable is refused" 1 ".github/workflows/w.yml:7: -Awarnings" -- a/src/lib.rs "$CLEAN" .github/workflows/w.yml "$WF
    steps:
      - env:
          CARGO_BUILD_RUSTFLAGS: -Awarnings
        run: cargo build"
case_ "an allow flag in an action's input is refused" 1 ".github/workflows/w.yml:8: --allow=unused" -- a/src/lib.rs "$CLEAN" .github/workflows/w.yml "$WF
    steps:
      - uses: owner/setup@0123456789012345678901234567890123456789
        with:
          rustflags: --allow=unused"
case_ "flags from an expression are refused" 1 "RUSTFLAGS from an expression, which the check cannot read" -- a/src/lib.rs "$CLEAN" .github/workflows/w.yml "$WF
    env:
      RUSTFLAGS: \${{ matrix.flags }}
    steps:
      - run: cargo build"
case_ "deny flags in a workflow pass" 0 "ok: no lint allowance" -- a/src/lib.rs "$CLEAN" .github/workflows/w.yml "$WF
    env:
      RUSTFLAGS: -D warnings
    steps:
      - run: RUSTDOCFLAGS='-D warnings' cargo doc"
case_ "an allow flag assigned before a command is refused" 1 "s.sh:2: -A: a flag" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
RUSTFLAGS="-A unused" cargo build'
case_ "an exported cap is refused" 1 "s.sh:2: --cap-lints" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
export RUSTDOCFLAGS="--cap-lints allow"'
case_ "a flag set through env is refused" 1 "s.sh:2: -Awarnings" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Awarnings cargo build'
case_ "a flag written for later steps is refused" 1 "s.sh:2: -A" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
echo "RUSTFLAGS=-A dead_code" >> "$GITHUB_ENV"'
case_ "a flag from another variable is refused" 1 "RUSTFLAGS from \$EXTRA, which the check cannot read" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
RUSTFLAGS="$EXTRA" cargo build'
case_ "a flag added to the variable's own value passes" 0 "ok: no lint allowance" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
export RUSTFLAGS="${RUSTFLAGS:-} -D warnings"'
case_ "an allow after -- of cargo clippy is refused" 1 "s.sh:2: -A" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
cargo clippy --workspace -- -D warnings -A clippy::all'
case_ "a cap after -- of cargo rustc is refused" 1 "s.sh:2: --cap-lints" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
cargo +1.0.0 rustc -p a -- --cap-lints allow'
case_ "a variable after -- of cargo clippy is refused" 1 "cargo clippy reads \$FLAGS, which the check cannot read" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
cargo clippy -- $FLAGS'
case_ "rustc's own allow is refused" 1 "s.sh:2: -A" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
rustc -A unused x.rs'
case_ "flags in cargo's --config are refused" 1 "cargo --config sets flags that silence lints" -- a/src/lib.rs "$CLEAN" s.sh "#!/usr/bin/env bash
cargo --config 'build.rustflags=[\"-A\", \"unused\"]' build"
case_ "the words after -- of cargo test go to the tests" 0 "ok: no lint allowance" -- a/src/lib.rs "$CLEAN" s.sh '#!/usr/bin/env bash
cargo test -p a -- --nocapture "$@"'
case_ "a step's script is read" 1 ".github/workflows/w.yml:7: -A" -- a/src/lib.rs "$CLEAN" .github/workflows/w.yml "$WF
    steps:
      - run: |
          cargo clippy -- -A clippy::all"
case_ "a cargo configuration in another directory is read" 1 "fuzz/.cargo/config.toml: build.rustflags: -Adead_code" -- a/src/lib.rs "$CLEAN" fuzz/.cargo/config.toml '[build]
rustflags = ["-Adead_code"]'

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
listed "$CHECK" "an untracked file is read" 1 "a/src/new.rs:1: #[allow(dead_code)]" "ignored.rs" \
  scripts/lint-allowance-exemptions.txt "$EMPTY" a/src/new.rs '#[allow(dead_code)]
fn a() {}' a/src/ignored.rs '#[allow(dead_code)]
fn b() {}'
listed "$CHECK" "an ignored file is not read" 0 "ok: no lint allowance in 1 Rust file(s)" "ignored.rs" \
  scripts/lint-allowance-exemptions.txt "$EMPTY" a/src/lib.rs "$CLEAN" a/src/ignored.rs '#[allow(dead_code)]
fn b() {}'

echo "check-lint-allowances tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
