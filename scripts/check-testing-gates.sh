#!/usr/bin/env bash
# axess: every crate with a `testing` feature refuses a release build the same way.
#
# The `testing` feature compiles test doubles: deterministic clocks and
# random sources, mock stores, label-driven ids, constructors that skip key
# checks. A release build that links them ships them in a production binary,
# and cargo feature unification lets any one dependent switch the feature on
# for the whole build. So every crate that defines `testing` carries the one
# gate, in its crate root:
#
#   #[cfg(all(feature = "testing", not(debug_assertions),
#             not(feature = "allow-testing-in-release")))]
#   compile_error!(...)
#
# with `allow-testing-in-release` as the named opt-out in its features. A
# crate that defined the feature without the gate was the hole: a build with
# its `testing` on and debug assertions off compiled, and the crates beneath
# it that do carry the gate never saw the feature.
#
# The opt-out is for a build that means it (a benchmark, a release-mode test
# run), so an example enables it under `[dev-dependencies]` only: in
# `[dependencies]` it reaches the whole workspace's release build by
# unification and switches every gate off.
#
# Usage: ./scripts/check-testing-gates.sh [--root DIR]
#   --root DIR  check the crates under DIR (scripts/check-testing-gates-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$AXESS_DIR"
if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  ROOT="$2"
fi
cd "$ROOT"

errors=0
refuse() { echo "REFUSED: $1" >&2; errors=$((errors + 1)); }

# section <manifest> <name>: the lines of one [section] of a manifest.
section() { awk -v want="[$2]" '/^\[/ { in_section = ($0 == want); next } in_section' "$1"; }

for manifest in */Cargo.toml; do
  [ -e "$manifest" ] || continue
  crate="${manifest%/Cargo.toml}"
  # The fixture crate is the test doubles; it has no production build.
  [ "$crate" = "axess-testing" ] && continue
  features="$(section "$manifest" features)"
  grep -qE '^testing[[:space:]]*=' <<<"$features" || continue
  if ! grep -qE '^allow-testing-in-release[[:space:]]*=' <<<"$features"; then
    refuse "$crate defines the testing feature with no allow-testing-in-release opt-out in $manifest"
  fi
  root="$crate/src/lib.rs"
  if [ ! -f "$root" ]; then
    refuse "$crate defines the testing feature and has no $root to carry the gate"
    continue
  fi
  # The gate: one cfg(all(...)) attribute naming the three conditions,
  # followed by compile_error!.
  if ! grep -qE '#\[cfg\(all\([^]]*feature = "testing"[^]]*not\(debug_assertions\)[^]]*not\(feature = "allow-testing-in-release"\)[^]]*\)\)\][[:space:]]*compile_error!' <<<"$(tr '\n' ' ' < "$root")"; then
    refuse "$crate defines the testing feature and $root carries no release-build gate (cfg(all(feature = \"testing\", not(debug_assertions), not(feature = \"allow-testing-in-release\"))) compile_error!)"
  fi
done

for manifest in examples/*/Cargo.toml; do
  [ -e "$manifest" ] || continue
  if grep -q 'allow-testing-in-release' <<<"$(section "$manifest" dependencies)"; then
    refuse "${manifest%/Cargo.toml} enables allow-testing-in-release under [dependencies]; an example may enable it under [dev-dependencies] only"
  fi
done

if [ "$errors" -ne 0 ]; then
  echo "$errors testing-gate problem(s)." >&2
  exit 1
fi
echo "OK: every crate with a testing feature carries the release-build gate and its named opt-out, and no example enables the opt-out in its dependencies."
