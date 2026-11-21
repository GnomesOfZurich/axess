#!/usr/bin/env bash
# axess: crafted cases for scripts/check-jwt-provider-sites.sh.
#
# Each case writes files under a temporary root, runs the check against it
# with `--root`, and asserts the exit status and a fragment of the output.
# The refusals are the contract: every path and import that reaches a
# jsonwebtoken operation taking the crypto provider is refused wherever it
# stands, test code included, and the boundary file, the provider installs,
# `decode_header`, comments and strings pass.
#
# Usage: ./scripts/check-jwt-provider-sites-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-jwt-provider-sites.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-jwt-provider-sites.XXXXXX")"
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

# Paths to the operations, in production code and in tests alike.
case_ "a path to encode is refused" 1 "src/a.rs:1: jsonwebtoken::encode" -- \
  src/a.rs 'fn f() { let _ = jsonwebtoken::encode(&h, &c, &k); }'
case_ "a path to decode in a test file is refused" 1 "tests/b.rs:2: jsonwebtoken::decode" -- \
  tests/b.rs '#[test]
fn t() { let _ = jsonwebtoken::decode::<V>(t, &k, &v); }'
case_ "a path written over lines and spaces is refused" 1 "src/c.rs:1: jsonwebtoken ::" -- \
  src/c.rs 'fn f() { jsonwebtoken ::
    crypto::sign(m, &k, a); }'
case_ "crypto::verify is refused" 1 "src/d.rs:1: jsonwebtoken::crypto::verify" -- \
  src/d.rs 'fn f() { let _ = jsonwebtoken::crypto::verify(s, m, &k, a); }'
case_ "anything in jws is refused" 1 "src/e.rs:1: jsonwebtoken::jws" -- \
  src/e.rs 'fn f() { let _ = jsonwebtoken::jws::encode(&h, None, &k); }'
case_ "decode_header passes" 0 "$OK" -- \
  src/f.rs 'fn f() { let _ = jsonwebtoken::decode_header(t); }'
case_ "a provider install passes" 0 "$OK" -- \
  src/g.rs 'fn f() { let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default(); }'
case_ "the boundary's own calls pass" 0 "$OK" -- \
  axess-factors/src/jwt.rs 'pub fn encode() { jsonwebtoken::encode(h, c, k) }'
case_ "a file beside the boundary does not" 1 "axess-factors/src/jwt/x.rs:1" -- \
  axess-factors/src/jwt/x.rs 'fn f() { jsonwebtoken::encode(h, c, k); }'
case_ "the boundary's functions pass" 0 "$OK" -- \
  src/h.rs 'fn f() { crate::jwt::encode(h, c, k); axess::jwt::decode::<V>(t, k, v); }'

# Imports.
case_ "importing encode is refused" 1 "src/i.rs:1: use jsonwebtoken::{Algorithm, EncodingKey, Header, encode}" -- \
  src/i.rs 'use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};'
case_ "a use over lines names the line of the import" 1 "src/j.rs:3: use jsonwebtoken::{" -- \
  src/j.rs 'use jsonwebtoken::{
    Algorithm, DecodingKey,
    Validation, decode,
};'
case_ "importing decode_header and the key types passes" 0 "$OK" -- \
  src/k.rs 'use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation, decode_header};
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::signature::{Signer, Verifier};'
case_ "importing the crypto module is refused" 1 "src/l.rs:1" -- \
  src/l.rs 'use jsonwebtoken::crypto;'
case_ "importing crypto as self is refused" 1 "src/m.rs:1" -- \
  src/m.rs 'use jsonwebtoken::crypto::{self, aws_lc};'
case_ "importing crypto under another name is refused" 1 "src/n.rs:1" -- \
  src/n.rs 'use jsonwebtoken::crypto as c;'
case_ "importing sign and verify is refused" 1 "src/o.rs:1" -- \
  src/o.rs 'use jsonwebtoken::crypto::{sign, verify};'
case_ "importing a backend's provider passes" 0 "$OK" -- \
  src/p.rs 'use jsonwebtoken::crypto::aws_lc;
use jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER;'
case_ "a glob is refused" 1 "src/q.rs:1" -- \
  src/q.rs 'use jsonwebtoken::*;'
case_ "the crate under another name is refused" 1 "src/r.rs:1" -- \
  src/r.rs 'use jsonwebtoken as jwt;'
case_ "extern crate under another name is refused" 1 "src/s.rs:1: extern crate jsonwebtoken" -- \
  src/s.rs 'extern crate jsonwebtoken as jwt;'
case_ "a type under another name passes" 0 "$OK" -- \
  src/t.rs 'use jsonwebtoken::Algorithm as J;'
case_ "a public re-export of an operation is refused" 1 "src/u.rs:1" -- \
  src/u.rs 'pub use ::jsonwebtoken::encode;'

# The JWK operations the boundary does not cover, and a renamed dependency.
case_ "Jwk::from_encoding_key is refused" 1 "src/v.rs:1: from_encoding_key" -- \
  src/v.rs 'fn f() { let _ = Jwk::from_encoding_key(&k, a); }'
case_ "a thumbprint by ThumbprintHash is refused" 1 "src/w.rs:1: ThumbprintHash" -- \
  src/w.rs 'fn f() { let _ = jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256); }'
case_ "a manifest that renames the crate is refused" 1 "x/Cargo.toml:2: jsonwebtoken under another name" -- \
  x/Cargo.toml '[dependencies]
jwt = { package = "jsonwebtoken", version = "11.1.0" }'
case_ "a manifest that names the crate passes" 0 "$OK" -- \
  x/Cargo.toml '[dependencies]
jsonwebtoken = { version = "11.1.0", default-features = false }  # package = "jsonwebtoken"'

# Comments and strings are not code.
case_ "a comment and a string pass" 0 "$OK" -- \
  src/y.rs '// jsonwebtoken::encode(h, c, k) would panic here.
/// `use jsonwebtoken::{encode};` in a doc comment.
fn f() { let _ = "jsonwebtoken::decode::<V>(t, k, v)"; }'

# Nothing to read.
case_ "an empty root is refused" 1 "read no Rust file or manifest" --

echo "check-jwt-provider-sites-tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
