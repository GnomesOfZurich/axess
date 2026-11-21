#!/usr/bin/env bash
# axess: build locally every feature set CI builds, before CI does.
#
# Every other gate here runs `--all-features`, which turns on every `cfg`
# and so can never see a reference to a feature-gated item that is itself
# ungated: an ungated test that names `crate::middleware::request_id::RequestId`
# compiles under `--all-features` and fails CI's `--features
# postgres,testing` job with E0433. Without this script the first report of
# such a reference comes from CI after a push.
#
# The sets below mirror `.github/workflows/ci.yml` and are not invented
# here. Two shapes, because CI runs two:
#
#   - the `features` matrix, over the profiles of axess-core and the
#     facade: `cargo check --lib`, then every target (`--all-targets`: the
#     unit tests, where `#[cfg(test)]` widens a gate, the integration
#     tests, examples and benches). `--lib` stays beside it because a test
#     target pulls the dev-dependencies, whose features can mask the
#     absence of one in the library; every target, because a test gated on
#     a store alone that reaches a fixture of `testing`, or a dependency
#     only a target under one profile does not use, shows nowhere else.
#   - every target once more with `postgres,testing`, the set the test
#     job's integration tests are written for.
#
# Beside them, the `factor_isolation` job checks axess-factors with each
# factor feature alone, and for the client assertion's three sets (the
# pure-Rust backend with and without `client-assertion-rsa`, and the aws-lc
# backend) runs its unit tests too, because the workspace's test run has
# both backends on and so never runs the refusal of an RSA signer. With both
# backends and without `client-assertion-rsa`, the test binary that installs
# RustCrypto's provider before axess installs aws-lc runs here as well, and
# so does the local IdP's refusal of RSA in a build without `local-idp-rsa`:
# the workspace's test run has every feature on, so it runs neither.
#
# Keep them in step. A profile added to ci.yml and not to this list is a
# profile that goes back to being checked only after a push.
#
# A warning in first-party code fails a profile as an error does (CI sets
# `RUSTFLAGS=-D warnings` on these jobs): an item gated wider than its users
# is dead code in the profiles between the two gates, and only these
# profiles compile it.
#
# Each profile and each factor set runs its crates' doctests too
# (`cargo test --doc`), and scripts/doctest-crates.sh the other library
# crates' under each of their features: a doc example is compiled only by a
# test run, and the workspace's test run has every feature on.
#
# Usage: ./scripts/check-feature-matrix.sh [profile ...]
#   With profile names (e.g. `delegated-only`), only those lib profiles
#   run, every target and the doctests of each included, and the factor
#   sets, the other crates and the postgres,testing targets are skipped.
set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1

# name | flags, mirroring the `features` matrix in ci.yml
LIB_SETS=(
  "no-default-features|--no-default-features"
  "default-features|"
  "memory-only|--no-default-features --features memory"
  "sqlite-only|--no-default-features --features sqlite"
  # The system's SQLite library in place of the bundled source: the only
  # profile that compiles the stores without `sqlite` on (dev-dependencies
  # and `--all-features` both switch the bundled source on).
  "sqlite-unbundled-only|--no-default-features --features sqlite-unbundled"
  "postgres-only|--no-default-features --features postgres"
  "mysql-only|--no-default-features --features mysql"
  "valkey-only|--no-default-features --features valkey"
  # `delegated` without a store: session crypto compiles for the encrypted
  # credential store alone, without the bound formats the stores use.
  "delegated-only|--no-default-features --features delegated,jwt-rust-crypto"
  # `spire` alone: the Workload API client with neither rustls nor a JOSE
  # library beside it. What it hands to each is gated on that feature too
  # (`outbound-mtls`, `jwt`), and only this profile compiles it without them.
  "spire-only|--no-default-features --features spire"
  # Device keys alone, with the crypto backend every JWT user names: the
  # enforcement in the session layer and the key service without a store
  # backend, a factor or OAuth beside them.
  "device-keys-only|--no-default-features --features device-keys,jwt-rust-crypto"
  # The local IdP without its RSA keys, which is how `local-idp` builds:
  # nothing outside the `local-idp-rsa` module may name an RSA constructor
  # or the `rsa` crate.
  "local-idp-only|--no-default-features --features local-idp,jwt-aws-lc"
  # The W3C Trace Context layer alone: the audit context reads the trace id
  # from it under this feature, and from nothing without it.
  "trace-context-only|--no-default-features --features trace-context"
)

# axess-factors with one factor or protocol feature alone. Each feature names
# the dependencies its module uses (`totp` does not build without
# `axess-clock` when only `hotp` pulls it in); the default set hides that. The
# `jwt` family needs a crypto backend beside it. Keep in step with the
# `factor_isolation` job in ci.yml.
FACTOR_SETS=(
  "totp"
  "hotp"
  "password"
  "email_otp"
  "recovery_code"
  "fido2"
  "ldap"
  "mtls"
  "http-body"
  "social"
  "jwt,jwt-rust-crypto"
  "oidc,jwt-rust-crypto"
  "bearer,jwt-rust-crypto"
  "oauth,jwt-rust-crypto"
  "outbound-oauth,jwt-rust-crypto"
  "key-proof,jwt-rust-crypto"
  # The client assertion signs with an RSA key only where a build chose it:
  # with `client-assertion-rsa` on the pure-Rust backend, and on the aws-lc
  # backend without it.
  "outbound-oauth,jwt-rust-crypto,client-assertion-rsa"
  "outbound-oauth,jwt-aws-lc"
)

# Sets a user can name for one crate that the profiles above do not hold,
# each of which failed once: every target of the crate under them, with a
# first-party warning failing the set. `testing` without `authz` (a test of
# the Cedar bridge, a macro test's import), axess-identity without `serde`
# (a round trip in its unit tests), `delegated-exchange` without a store (a
# constant only the stored grant's tests read), `sqlx` alone (the id
# derives need the dependency), OAuth with `testing` but without `device`
# (an import only the device tests use), and LDAP with `testing` but without
# `fido2` (imports only the FIDO2 withdrawal test uses). Keep in step with the
# `crate_feature_sets` job in ci.yml.
CRATE_SETS=(
  "axess-identity|--no-default-features"
  "axess-identity|--no-default-features --features testing"
  "axess-core|--no-default-features --features testing"
  "axess-core|--no-default-features --features oauth,testing,jwt-rust-crypto"
  "axess-core|--no-default-features --features delegated-exchange,jwt-rust-crypto"
  "axess-core|--no-default-features --features sqlx"
  "axess-core|--no-default-features --features ldap,testing"
  "axess|--no-default-features --features testing"
)

# The client assertion with both backends compiled, where the provider in
# place decides: the test binary that installs one before axess does, with
# and without `client-assertion-rsa`.
PROVIDER_SETS=(
  "outbound-oauth,jwt-aws-lc,jwt-rust-crypto"
  "outbound-oauth,jwt-aws-lc,jwt-rust-crypto,client-assertion-rsa"
)

failed=0

# Profiles named on the command line, or every profile.
wanted() {
  local name="$1"
  [ "${#PICK[@]}" -eq 0 ] && return 0
  local p
  for p in "${PICK[@]}"; do [ "$p" = "$name" ] && return 0; done
  return 1
}
PICK=("$@")

run() {
  local label="$1"; shift
  printf '  %-38s ' "$label"
  local status=0
  out=$("$@" --message-format=short 2>&1) || status=1
  # A first-party warning in short format: `path.rs:line:col: warning: ...`
  # (dependencies' lints are capped by cargo and never print).
  if [ "$status" -eq 0 ] && ! grep -qE '^[^ ]+\.rs:[0-9]+:[0-9]+: warning' <<<"$out"; then
    echo "ok"
  else
    echo "FAILED"
    printf '%s\n' "$out" | grep -E "^[a-z].*(error|warning)|^error" | grep -v 'generated [0-9]* warning' | sed 's/^/      /' | sed -n 1,10p
    failed=1
  fi
}

for entry in "${LIB_SETS[@]}"; do
  name="${entry%%|*}"
  flags="${entry#*|}"
  wanted "$name" || continue
  # shellcheck disable=SC2086
  for pkg in axess-core axess; do
    run "$pkg --lib ($name)" cargo check -p "$pkg" --lib $flags
    run "$pkg --all-targets ($name)" cargo check -p "$pkg" --all-targets $flags
    run "$pkg doctests ($name)" cargo test -p "$pkg" --doc $flags
  done
done

# Each factor feature alone. Run with no profile names only: they are not
# core profiles.
if [ "${#PICK[@]}" -eq 0 ]; then
  for features in "${FACTOR_SETS[@]}"; do
    run "axess-factors --lib ($features alone)" \
      cargo check -p axess-factors --lib --no-default-features --features "$features"
    run "axess-factors --all-targets ($features alone)" \
      cargo check -p axess-factors --all-targets --no-default-features --features "$features"
    run "axess-factors doctests ($features alone)" \
      cargo test -p axess-factors --doc --no-default-features --features "$features"
  done
  # The doctests of the other library crates, under each of their features.
  run "doctests of the other library crates" ./scripts/doctest-crates.sh
  for entry in "${CRATE_SETS[@]}"; do
    crate="${entry%%|*}"
    flags="${entry#*|}"
    # shellcheck disable=SC2086
    run "$crate --all-targets ($flags)" cargo check -p "$crate" --all-targets $flags
  done
fi

# The client assertion's tests under each of the three: the workspace's test
# run has both backends on, so the refusal of an RSA signer on the pure-Rust
# backend, and each backend's RSA signature, run only here and in CI's
# factor_isolation job.
if [ "${#PICK[@]}" -eq 0 ]; then
  for features in "${FACTOR_SETS[@]}"; do
    case "$features" in outbound-oauth*) ;; *) continue ;; esac
    run "axess-factors client_assertion tests ($features)" \
      cargo test -p axess-factors --lib --no-default-features --features "$features" client_assertion
  done
  for features in "${PROVIDER_SETS[@]}"; do
    run "axess-factors installed provider ($features)" \
      cargo test -p axess-factors --no-default-features --features "$features" \
        --test client_assertion_installed_provider
  done
  # The local IdP without `local-idp-rsa` refuses every RSA algorithm.
  run "axess-core local IdP RSA refused (local-idp)" \
    cargo test -p axess-core --lib --no-default-features --features local-idp,jwt-aws-lc \
      testing::local_idp::rsa_refused
fi

# Every target with the set the test job's integration tests are written
# for. `check` rather than `test --no-run`: same errors, no codegen or
# linking.
if [ "${#PICK[@]}" -eq 0 ]; then
  run "axess-core --all-targets (postgres,testing)" \
    cargo check -p axess-core --all-targets --features postgres,testing
fi

if [ "$failed" -ne 0 ]; then
  echo
  echo "ERROR: a feature set CI builds does not compile here."
  echo "       Usually an item behind a \`#[cfg(feature = ..)]\` named from"
  echo "       code that is not itself gated. Gate the use, or move it."
  exit 1
fi

if [ "${#PICK[@]}" -eq 0 ]; then
  echo "check-feature-matrix: ${#LIB_SETS[@]} lib profiles and ${#FACTOR_SETS[@]} factor sets, every target and the doctests of each, the doctests of the other library crates, and every target under ${#CRATE_SETS[@]} crate sets, all green."
else
  echo "check-feature-matrix: ${PICK[*]}: lib, every target and the doctests green."
fi
