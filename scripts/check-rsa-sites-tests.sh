#!/usr/bin/env bash
# axess: crafted cases for scripts/check-rsa-sites.sh.
#
# Each case writes Rust files under a temporary root, runs the check against
# it with `--root`, and asserts the exit status and a fragment of the output.
# The refusals are the contract: a `#[cfg(test)]` attribute exempts the one
# item it covers (the next item, or the block it opens), and nothing after it.
# A brace in a literal of any form rustc reads (an escaped quote, a byte
# literal, a raw string, a nested comment, beside lifetimes and labels)
# moves no item's end; these cases hold the lexer in
# scripts/lib/rust_source.py that every source-rule check shares.
#
# Usage: ./scripts/check-rsa-sites-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-rsa-sites.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-rsa-sites.XXXXXX")"
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

# A cfg(test) attribute on line 1 covers the `use foo;` on line 2 and
# nothing else, so the production lines after it are refused.
EVIDENCE='#[cfg(test)]
use foo;
use rsa::RsaPrivateKey;
fn f(){ let _ = rsa::Pkcs1v15Sign::new_unprefixed(); }'
case_ "production rsa after a cfg(test) item is refused" 1 "axess-core/src/x.rs:3" -- axess-core/src/x.rs "$EVIDENCE"
case_ "every production line after the item is refused" 1 "axess-core/src/x.rs:4" -- axess-core/src/x.rs "$EVIDENCE"

# A test module in the middle of a file exempts its own block only.
MIDDLE='use foo;
#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;
    fn f() { let _ = rsa::X; }
}
fn g() { let _ = rsa::Pkcs1v15Sign::new_unprefixed(); }
#[cfg(test)] use rsa::Z;
fn h() { rsa::again(); }'
case_ "a line inside the test module is exempt" 1 "axess-core/src/y.rs:7" "axess-core/src/y.rs:4" -- axess-core/src/y.rs "$MIDDLE"
case_ "the module body is exempt but not the line after it" 1 "axess-core/src/y.rs:7" "axess-core/src/y.rs:5" -- axess-core/src/y.rs "$MIDDLE"
case_ "a single-line cfg(test) item is exempt" 1 "axess-core/src/y.rs:9" "axess-core/src/y.rs:8" -- axess-core/src/y.rs "$MIDDLE"

TRAILING='use foo;
fn g() {}
#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;
}'
case_ "a trailing test module passes" 0 "ok: rsa is named only" -- axess-core/src/z.rs "$TRAILING"
case_ "the reviewed file passes" 0 "ok: rsa is named only" -- axess-core/src/local_idp/primitives/rsa_key.rs "use rsa::RsaPrivateKey;"
case_ "the module beside it does not" 1 "axess-core/src/local_idp/primitives.rs:1" -- axess-core/src/local_idp/primitives.rs "use rsa::RsaPrivateKey;"
case_ "a test sibling passes" 0 "ok: rsa is named only" -- axess-core/src/foo/tests.rs "use rsa::RsaPrivateKey;"
case_ "a doc comment passes" 0 "ok: rsa is named only" -- axess-core/src/w.rs "/// Signing goes through rsa::Pkcs1v15Sign in the primitives.
fn g() {} // rsa::not_here"

# A brace inside a char literal, a string, a raw string or a block comment
# is text, not structure: it must not open a depth the test module never
# closes, or everything after the module would be exempt.
CHAR_LITERAL="use foo;
#[cfg(test)]
mod tests {
    const OPEN: char = '{';
    use rsa::RsaPrivateKey;
}
use rsa::RsaPrivateKey;
fn g() { let _ = rsa::X; }"
case_ "a brace in a char literal inside the test module exempts nothing after it" 1 "axess-core/src/v.rs:7" "axess-core/src/v.rs:5" -- axess-core/src/v.rs "$CHAR_LITERAL"
case_ "the item after the char literal's module is refused too" 1 "axess-core/src/v.rs:8" "axess-core/src/v.rs:4" -- axess-core/src/v.rs "$CHAR_LITERAL"
RAW_STRING='use foo;
#[cfg(test)]
mod tests {
    const OPEN: &str = r#"{"{"#;
    const ESCAPED: char = '"'"'\u{7b}'"'"';
    const QUOTE: char = '"'"'\'"'"''"'"';
    fn f<'"'"'a>(x: &'"'"'a str) -> &'"'"'a str { x }
    use rsa::RsaPrivateKey;
}
use rsa::RsaPrivateKey;'
case_ "a brace in a raw string or an escape inside the test module exempts nothing after it" 1 "axess-core/src/u.rs:10" "axess-core/src/u.rs:8" -- axess-core/src/u.rs "$RAW_STRING"
BLOCK_COMMENT='use foo;
#[cfg(test)]
mod tests {
    /* { */
    /* a comment
       over two lines { */
    use rsa::RsaPrivateKey;
}
use rsa::RsaPrivateKey;'
case_ "a brace in a block comment inside the test module exempts nothing after it" 1 "axess-core/src/t.rs:9" "axess-core/src/t.rs:7" -- axess-core/src/t.rs "$BLOCK_COMMENT"
case_ "a use inside a block comment passes" 0 "ok: rsa is named only" -- axess-core/src/s.rs 'fn g() {}
/* use rsa::RsaPrivateKey;
   rsa::again(); */
fn h() {}'

# A quote is read as rustc's lexer reads it (scripts/lib/rust_source.py),
# so no brace in a literal moves the test module's end: every escape of a
# char or byte literal, lifetimes, labels, raw strings and nested block
# comments, beside braces, as written and as rustfmt spaces them.
cat > "$WORK/forms" <<'EOF'
    const CHARS: [char; 9] = ['\'', '\\', '\n', '\u{7B}', '\x7D', '{', '"', '\t', '\0'];
    const TIGHT: [char; 4] = ['\'','{','\'','}'];
    const BYTES: [u8; 5] = [b'\'', b'{', b'}', b'\\', b'\x7b'];
    const RAW: [&str; 4] = [r#"}"#, r"{", r##"a "# }"##, "\"}'{'"];
    const RAW_BYTES: &[u8] = br#"{"#;
    const C_TEXT: [&core::ffi::CStr; 2] = [c"{", cr#"}"#];
    /* outer /* inner } */ still a comment { */
    fn labels<'a, 'b: 'a>(x: &'a str, _y: &'b str) -> &'a str {
        'outer: loop {
            'inner: for _ in 0..1 { break 'inner; }
            break 'outer x;
        }
    }
    fn open<'_a>(c: &'_a char) -> bool { *c == '{' }
    struct Holder<'r#ab>(&'r#ab str);
EOF
FORMS="$(cat "$WORK/forms")"
# quoted_module LITERAL: a test module that holds LITERAL on line 4 and a
# use on line 5, and a production use after it on line 7.
quoted_module() {
  printf 'use foo;\n#[cfg(test)]\nmod tests {\n    const QUOTES: [char; 2] = %s;\n    use rsa::RsaPrivateKey;\n}\nuse rsa::RsaPrivateKey;' "$1"
}
case_ "an escaped quote beside an opening brace leaves the test module whole" 1 "axess-core/src/p.rs:7" "axess-core/src/p.rs:5" -- \
  axess-core/src/p.rs "$(quoted_module "['\\'','{']")"
case_ "the same literal as rustfmt spaces it leaves the test module whole" 1 "axess-core/src/p.rs:7" "axess-core/src/p.rs:5" -- \
  axess-core/src/p.rs "$(quoted_module "['\\'', '{']")"
case_ "an escaped quote beside a closing brace does not end the test module" 1 "axess-core/src/p.rs:7" "axess-core/src/p.rs:5" -- \
  axess-core/src/p.rs "$(quoted_module "['\\'','}']")"
case_ "a use after every literal form inside the test module is exempt" 0 "ok: rsa is named only" -- \
  axess-core/src/p.rs "#[cfg(test)]
mod tests {
$FORMS
    use rsa::RsaPrivateKey;
}"
case_ "a use after a test module of every literal form is production code" 1 "axess-core/src/p.rs:20" -- \
  axess-core/src/p.rs "mod outer {
    #[cfg(test)]
    mod tests {
$FORMS
    }
    use rsa::RsaPrivateKey;
}"
case_ "a use after a test module whose escaped quote stands beside a brace is production code" 1 "axess-core/src/p.rs:6" -- \
  axess-core/src/p.rs "mod outer {
    #[cfg(test)]
    mod tests {
        const QUOTES: [char; 2] = ['\\'','{'];
    }
    use rsa::RsaPrivateKey;
}"

# A test item that shares a line with a production item exempts only itself,
# whatever ends it: a closing brace, a semicolon, or the end of a block
# that opened on an earlier line.
case_ "a production item after a closed test item on its line is refused" 1 "axess-core/src/r.rs:2" -- axess-core/src/r.rs 'use foo;
#[cfg(test)] fn helper() {} fn f() { let _ = rsa::Pkcs1v15Sign::new_unprefixed(); }'
case_ "a production use after a test use on its line is refused" 1 "axess-core/src/r.rs:1" -- axess-core/src/r.rs '#[cfg(test)] use foo; use rsa::RsaPrivateKey;'
case_ "a production item after the brace that closes a test module is refused" 1 "axess-core/src/r.rs:4" "axess-core/src/r.rs:3" -- axess-core/src/r.rs '#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;
} use rsa::RsaPrivateKey;'
case_ "a test item after a production item on its line exempts only itself" 1 "axess-core/src/r.rs:1" -- axess-core/src/r.rs 'use rsa::RsaPrivateKey; #[cfg(test)] use rsa::Other;'
case_ "an array type's semicolon does not end a test item" 0 "ok: rsa is named only" -- axess-core/src/r.rs '#[cfg(test)] const K: [u8; 2] = { let _ = rsa::x(); [0; 2] };'
# Attributes stacked after the test attribute belong to its item, and an
# attribute line with a production item on it is production code.
case_ "a production item on an attribute line after the test attribute is refused" 1 "axess-core/src/q.rs:2" -- axess-core/src/q.rs '#[cfg(test)]
#[derive(Debug)] struct A; use rsa::RsaPrivateKey;
fn f() {}'
case_ "the item after stacked attributes is the test item" 0 "ok: rsa is named only" -- axess-core/src/q.rs '#[cfg(test)]
#[allow(dead_code)]
#[cfg_attr(
    feature = "x",
    allow(unused)
)]
fn t() { let _ = rsa::x(); }'
case_ "a test attribute with test second in all() exempts its item" 0 "ok: rsa is named only" -- axess-core/src/q.rs '#[cfg(all(feature = "x", test))]
fn t() { let _ = rsa::x(); }'
case_ "a cfg that holds in production exempts nothing" 1 "axess-core/src/q.rs:2" -- axess-core/src/q.rs '#[cfg(any(test, feature = "x"))]
fn t() { let _ = rsa::x(); }'
# A declaration in a comment declares nothing.
case_ "a commented-out test declaration in the parent exempts nothing" 1 "axess-core/src/a/fake.rs:1" -- axess-core/src/a.rs '// #[cfg(test)] mod fake;
mod fake;' axess-core/src/a/fake.rs 'use rsa::RsaPrivateKey;'
case_ "a test declaration in the parent exempts the file" 0 "ok: rsa is named only" -- axess-core/src/a.rs '#[cfg(test)]
mod fake;' axess-core/src/a/fake.rs 'use rsa::RsaPrivateKey;'
case_ "a test declaration in a string in the parent exempts nothing" 1 "axess-core/src/a/fake.rs:1" -- axess-core/src/a.rs 'const S: &str = "#[cfg(test)] mod fake;";
mod fake;' axess-core/src/a/fake.rs 'use rsa::RsaPrivateKey;'

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
listed "$CHECK" "an untracked file is read" 1 "axess-core/src/new.rs:1" "ignored.rs" \
  axess-core/src/new.rs 'use rsa::RsaPrivateKey;' axess-core/src/ignored.rs 'use rsa::RsaPrivateKey;'
listed "$CHECK" "an ignored file is not read" 0 "ok: rsa is named only" "ignored.rs" \
  axess-core/src/a.rs 'fn f() {}' axess-core/src/ignored.rs 'use rsa::RsaPrivateKey;'

echo "check-rsa-sites tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
