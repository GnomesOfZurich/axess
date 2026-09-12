#!/usr/bin/env bash
# axess: verify the crate really builds and tests on its declared MSRV.
#
# `rust-version` in the workspace Cargo.toml is a promise to adopters: depend
# on axess with that compiler and it will work. Nothing enforces it locally.
# The development toolchain is pinned well above it (rust-toolchain.toml), so
# a call to anything stabilised after the MSRV compiles cleanly here and breaks
# only for the adopter who took the promise at face value.
#
# Mirrors the `msrv` job in .github/workflows/ci.yml, which is the
# specification: build the workspace with all features, then run the lib tests.
#
# The MSRV is read from Cargo.toml rather than written here twice, so raising
# `rust-version` moves this check with it.
#
# Usage: ./scripts/check-msrv.sh

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

MSRV="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml \
  | grep -m1 '^rust-version' | sed 's/.*"\(.*\)".*/\1/')"

if [ -z "$MSRV" ]; then
  echo "ERROR: could not read [workspace.package] rust-version from Cargo.toml" >&2
  exit 1
fi

echo "Declared MSRV: ${MSRV}"

# The workspace root must be the only place the floor is written. Nine members
# (the examples and the fuzz crate) once hardcoded their own `rust-version`,
# and because cargo resolves against the *minimum* across members, correcting
# only the root left the dependency resolver still pinned to the stale floor.
stray="$(git ls-files '*Cargo.toml' \
  | grep -v '^Cargo.toml$' \
  | xargs grep -ln '^rust-version[[:space:]]*=[[:space:]]*"' 2>/dev/null || true)"
if [ -n "$stray" ]; then
  echo "ERROR: these manifests hardcode rust-version instead of inheriting it" >&2
  echo "       with \`rust-version.workspace = true\`:" >&2
  printf '  %s\n' $stray >&2
  echo "       cargo resolves against the minimum across members, so a stale" >&2
  echo "       copy here silently overrides the workspace floor." >&2
  exit 1
fi

if ! rustup toolchain list | grep -q "^${MSRV}-"; then
  echo "ERROR: the ${MSRV} toolchain is not installed, so the MSRV promise" >&2
  echo "       cannot be checked. Install it and re-run:" >&2
  echo "" >&2
  echo "         rustup toolchain install ${MSRV} --profile minimal" >&2
  echo "" >&2
  echo "       This deliberately fails rather than skipping: a check that" >&2
  echo "       quietly does nothing is worse than no check, because it" >&2
  echo "       reports green." >&2
  exit 1
fi

# `rust-toolchain.toml` pins the development compiler, and RUSTUP_TOOLCHAIN is
# what overrides it (the same mechanism dtolnay/rust-toolchain uses in CI).
# Confirm the override actually took effect, if the pin won instead, every
# command below would test the wrong compiler and still pass.
export RUSTUP_TOOLCHAIN="$MSRV"
ACTUAL="$(rustc --version | awk '{print $2}')"
if [ "$ACTUAL" != "$MSRV" ]; then
  echo "ERROR: asked for ${MSRV} but rustc reports ${ACTUAL}. The toolchain" >&2
  echo "       override did not take effect; this run would prove nothing." >&2
  exit 1
fi
echo "Building with rustc ${ACTUAL}"

# Its own target dir: MSRV artifacts share no fingerprints with the pinned
# toolchain's, so pointing both at one directory makes each run rebuild the
# other's work.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AXESS_DIR/target}/msrv"

if ! cargo build --workspace --all-features; then
  echo "" >&2
  echo "ERROR: the workspace does not build on its declared MSRV ${MSRV}." >&2
  echo "       Either avoid the newer API, or raise rust-version in" >&2
  echo "       Cargo.toml to the version that does support it." >&2
  exit 1
fi

if ! cargo test --workspace --all-features --lib; then
  echo "" >&2
  echo "ERROR: lib tests fail on the declared MSRV ${MSRV}." >&2
  exit 1
fi

echo "OK: the workspace builds and its lib tests pass on ${MSRV}."
