#!/usr/bin/env bash
# axess: a release build of the workspace carries no testing feature, and a
# mock example refuses one.
#
# Every crate with a `testing` feature refuses a release build that enables
# it unless `allow-testing-in-release` is named (scripts/check-testing-gates.sh
# holds the gates to one pattern). This checks the gate from the other side,
# on the build CI ships:
#
#   1. the workspace apart from the examples built on mock stores
#      (scripts/lib/mock_examples.sh) checks in release, so no member turns
#      the feature on for the others by unification;
#   2. the resolved feature graph of that selection holds no `testing` node
#      (`cargo tree -e features,normal`, which leaves dev edges out);
#   3. every mock example refuses a release build, and the error names the
#      feature, so the gate is known to fire in each of them: each example
#      enables `testing` on its own crates, and a gate that fires for one
#      says nothing of another's manifest.
#
# Usage: ./scripts/check-release-build.sh

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"
# shellcheck source=lib/mock_examples.sh
. "$AXESS_DIR/scripts/lib/mock_examples.sh"

exclude=()
for ex in "${EXAMPLES_WITH_MOCKS[@]}"; do exclude+=(--exclude "$ex"); done

echo "--- release check of the workspace without ${EXAMPLES_WITH_MOCKS[*]} ---"
cargo check --release --workspace "${exclude[@]}"

echo "--- no testing feature in that selection's normal graph ---"
if hits=$(cargo tree --workspace "${exclude[@]}" -e features,normal --prefix none \
    | grep -E '^axess[a-z-]* feature "(testing|allow-testing-in-release)"' | sort -u); [ -n "$hits" ]; then
  echo "REFUSED: the release build of the workspace enables a testing feature:" >&2
  echo "$hits" >&2
  exit 1
fi

for probe in "${EXAMPLES_WITH_MOCKS[@]}"; do
  echo "--- $probe refuses a release build by name ---"
  if out=$(cargo check --release -p "$probe" 2>&1); then
    echo "REFUSED: $probe compiled in release with the testing feature on; the release-build gate did not fire." >&2
    exit 1
  fi
  if ! grep -qE 'the `testing` feature of axess[a-z-]* is enabled in a release build' <<<"$out"; then
    echo "REFUSED: $probe failed to build in release, but not on the release-build gate:" >&2
    tail -20 <<<"$out" >&2
    exit 1
  fi
done
echo "OK: the workspace checks in release with no testing feature, and ${EXAMPLES_WITH_MOCKS[*]} each refuse a release build by name."
