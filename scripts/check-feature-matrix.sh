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
#   - the `features` matrix, `cargo check --lib` over seven profiles.
#     `--lib` is deliberate there: an integration-test target pulls extra
#     dependencies and can mask the absence of a feature.
#   - the postgres job, which is the only one that compiles test targets,
#     and so the only one that sees a `#[cfg]` mistake inside `#[cfg(test)]`.
#
# Keep them in step. A profile added to ci.yml and not to this list is a
# profile that goes back to being checked only after a push.
#
# Usage: ./scripts/check-feature-matrix.sh
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
)

failed=0

run() {
  local label="$1"; shift
  printf '  %-38s ' "$label"
  if out=$("$@" --message-format=short 2>&1); then
    echo "ok"
  else
    echo "FAILED"
    printf '%s\n' "$out" | grep -E "^[a-z].*error|^error" | sed 's/^/      /' | head -10
    failed=1
  fi
}

for entry in "${LIB_SETS[@]}"; do
  name="${entry%%|*}"
  flags="${entry#*|}"
  # shellcheck disable=SC2086
  for pkg in axess-core axess; do
    run "$pkg --lib ($name)" cargo check -p "$pkg" --lib $flags
  done
done

# The one CI job that compiles test targets. `--tests` rather than
# `test --no-run`: same errors, no codegen or linking.
run "axess-core --tests (postgres,testing)" \
  cargo check -p axess-core --tests --features postgres,testing

if [ "$failed" -ne 0 ]; then
  echo
  echo "ERROR: a feature set CI builds does not compile here."
  echo "       Usually an item behind a \`#[cfg(feature = ..)]\` named from"
  echo "       code that is not itself gated. Gate the use, or move it."
  exit 1
fi

echo "check-feature-matrix: ${#LIB_SETS[@]} lib profiles plus the test-compiling job, all green."
