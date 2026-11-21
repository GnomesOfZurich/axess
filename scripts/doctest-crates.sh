#!/usr/bin/env bash
# axess: the doctests of the library crates outside the feature matrix's
# profiles, under each of their features.
#
# A doc example is compiled only by a test run, and the workspace's test run
# has every feature on, so an example that names an item of a feature it is
# not gated on breaks only in a build without that feature. This runs the
# doctests of each crate below without its default features, with them, and
# with each feature alone. axess-core and the facade run theirs under each
# profile of scripts/check-feature-matrix.sh, and axess-factors under each
# factor set; the matrix runs this script too, and CI runs it in one row of
# its feature isolation job.
#
# Usage: ./scripts/doctest-crates.sh [cargo argument ...]
#   Each argument is passed to every cargo test (the matrix passes
#   --message-format=short). Exits 1 if any run fails, after running all.

set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1

# crate|features, each feature run alone.
CRATES=(
  "axess-cache|"
  "axess-clock|testing serde"
  "axess-events|serde rkyv full"
  "axess-identity|serde rkyv testing sqlx full"
  "axess-macros|authz"
  "axess-rng|testing numeric"
  "axess-strings|serde rkyv full"
  "axess-testing|"
  "axess-factors|"
)

failed=0
runs=0
for entry in "${CRATES[@]}"; do
  pkg="${entry%%|*}"
  read -r -a features <<<"${entry#*|}"
  echo "== $pkg: no default features"
  runs=$((runs + 1))
  cargo test -p "$pkg" --doc --no-default-features "$@" || { echo "FAILED: $pkg doctests without default features"; failed=1; }
  echo "== $pkg: default features"
  runs=$((runs + 1))
  cargo test -p "$pkg" --doc "$@" || { echo "FAILED: $pkg doctests with default features"; failed=1; }
  for feature in ${features[@]+"${features[@]}"}; do
    echo "== $pkg: $feature alone"
    runs=$((runs + 1))
    cargo test -p "$pkg" --doc --no-default-features --features "$feature" "$@" \
      || { echo "FAILED: $pkg doctests with $feature alone"; failed=1; }
  done
done

if [ "$failed" -ne 0 ]; then
  echo "ERROR: a doc example does not compile, or fails, in a build without a feature it needs."
  echo "       Gate the example on that feature (a cfg_attr on the doc line that opens it), or"
  echo "       write it to need none."
  exit 1
fi
echo "doctest-crates: $runs doctest runs of ${#CRATES[@]} crates, all green."
