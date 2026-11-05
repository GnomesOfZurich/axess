#!/usr/bin/env bash
# axess: build locally every feature set CI builds, before CI does.
#
# Every other gate here runs `--all-features`, which turns on every `cfg`
# and so can never see a reference to a feature-gated item that is itself
# ungated. That is not hypothetical: 0.7.0 put
# `crate::middleware::request_id::RequestId` into an ungated test, and
# `--all-features` compiled it happily while CI's `--features
# postgres,testing` job failed with E0433. No local gate covered it, so
# the first report came from CI after the release was tagged.
#
# The sets below mirror `.github/workflows/ci.yml` and are not invented
# here. Two shapes, because CI runs two:
#
#   - the `features` matrix, `cargo check --lib` over eight profiles, and
#     the same profiles once more for axess-core's unit tests
#     (`--lib --profile test`), where `#[cfg(test)]` widens a gate: an item
#     compiled "in tests or with a store" that calls one compiled "with a
#     store" breaks only there (0.14.0's delegated-only build did).
#     `--lib` is deliberate there: an integration-test target pulls extra
#     dependencies and can mask the absence of a feature.
#   - the postgres job, which is the only one that compiles test targets,
#     and so the only one that sees a `#[cfg]` mistake inside `#[cfg(test)]`.
#
# Keep them in step. A profile added to ci.yml and not to this list is a
# profile that goes back to being checked only after a push.
#
# A warning in first-party code fails a profile as an error does (CI sets
# `RUSTFLAGS=-D warnings` on these jobs): an item gated wider than its users
# is dead code in the profiles between the two gates, and only these
# profiles compile it.
#
# Usage: ./scripts/check-feature-matrix.sh [profile ...]
#   With profile names (e.g. `delegated-only`), only those lib profiles and
#   their unit tests run, and the test-compiling job is skipped.
set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# name | flags, mirroring the `features` matrix in ci.yml
LIB_SETS=(
  "no-default-features|--no-default-features"
  "default-features|"
  "memory-only|--no-default-features --features memory"
  "sqlite-only|--no-default-features --features sqlite"
  "postgres-only|--no-default-features --features postgres"
  "mysql-only|--no-default-features --features mysql"
  "valkey-only|--no-default-features --features valkey"
  # `delegated` without a store: session crypto compiles for the encrypted
  # credential store alone, without the bound formats the stores use.
  "delegated-only|--no-default-features --features delegated,jwt-rust-crypto"
)

# axess-factors with one factor or protocol feature alone. Each feature names
# the dependencies its module uses (`totp` once failed to build without
# `chrono`, which only `hotp` pulled in); the default set hides that. The
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
  if [ "$status" -eq 0 ] && ! printf '%s\n' "$out" | grep -qE '^[^ ]+\.rs:[0-9]+:[0-9]+: warning'; then
    echo "ok"
  else
    echo "FAILED"
    printf '%s\n' "$out" | grep -E "^[a-z].*(error|warning)|^error" | grep -v 'generated [0-9]* warning' | sed 's/^/      /' | head -10
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
  done
done

# Each factor feature alone. Run with no profile names only: they are not
# core profiles.
if [ "${#PICK[@]}" -eq 0 ]; then
  for features in "${FACTOR_SETS[@]}"; do
    run "axess-factors --lib ($features alone)" \
      cargo check -p axess-factors --lib --no-default-features --features "$features"
  done
fi

# axess-core's unit tests under every profile: `#[cfg(test)]` code and the
# gates it widens. The facade has no unit tests: its src holds re-exports.
for entry in "${LIB_SETS[@]}"; do
  name="${entry%%|*}"
  flags="${entry#*|}"
  wanted "$name" || continue
  # shellcheck disable=SC2086
  run "axess-core --lib unit tests ($name)" cargo check -p axess-core --lib --profile test $flags
done

# The one CI job that compiles test targets. `--tests` rather than
# `test --no-run`: same errors, no codegen or linking.
if [ "${#PICK[@]}" -eq 0 ]; then
  run "axess-core --tests (postgres,testing)" \
    cargo check -p axess-core --tests --features postgres,testing
fi

if [ "$failed" -ne 0 ]; then
  echo
  echo "ERROR: a feature set CI builds does not compile here."
  echo "       Usually an item behind a \`#[cfg(feature = ..)]\` named from"
  echo "       code that is not itself gated. Gate the use, or move it."
  exit 1
fi

if [ "${#PICK[@]}" -eq 0 ]; then
  echo "check-feature-matrix: ${#LIB_SETS[@]} lib profiles, their core unit tests and the test-compiling job, all green."
else
  echo "check-feature-matrix: ${PICK[*]}: lib and core unit tests green."
fi
