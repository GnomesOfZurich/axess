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
cd "$AXESS_DIR" || exit 1

MSRV="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml \
  | grep '^rust-version' | sed -n 1p | sed 's/.*"\(.*\)".*/\1/')"

if [ -z "$MSRV" ]; then
  echo "ERROR: could not read [workspace.package] rust-version from Cargo.toml" >&2
  exit 1
fi

echo "Declared MSRV: ${MSRV}"

# The workspace root must be the only place the floor is written. A member
# (an example, the fuzz crate) that writes its own `rust-version` holds the
# dependency resolver to that floor, because cargo resolves against the
# *minimum* across members, so correcting only the root changes nothing.
# Tracked manifests and untracked ones git does not ignore, so a manifest
# not yet added is checked as well.
stray="$(git ls-files --cached --others --exclude-standard --deduplicate '*Cargo.toml' \
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

if ! grep -q -- "^${MSRV}-" <<<"$(rustup toolchain list)"; then
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

# Every source Cargo.lock names is fetched by the pinned toolchain's cargo
# first, `--locked` so nothing is resolved anew: the cargo of the MSRV then
# builds from what is on disk and downloads and unpacks nothing itself, so
# what it builds is what the pinned cargo fetched under the registry rules
# of .cargo/config.toml.
echo "Fetching Cargo.lock's sources with the pinned toolchain: $(cargo --version)"
if ! cargo fetch --locked; then
  echo "ERROR: cargo fetch --locked failed with the pinned toolchain, so the" >&2
  echo "       MSRV build would fetch with the MSRV's cargo instead." >&2
  exit 1
fi

# `rust-toolchain.toml` pins the development compiler. rustup takes that file
# over its default toolchain and takes RUSTUP_TOOLCHAIN over the file, so the
# variable is what selects the MSRV here; in CI the msrv job's toolchain step
# installs that release and this line selects it the same way.
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
