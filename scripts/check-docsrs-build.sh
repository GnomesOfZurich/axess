#!/usr/bin/env bash
# axess: every published crate's documentation builds as docs.rs builds it.
#
# docs.rs documents a crate on a nightly compiler, with the features its
# `[package.metadata.docs.rs]` names and `--cfg docsrs` handed to rustdoc.
# A crate that marks items with `#[cfg_attr(docsrs, doc(cfg(..)))]` must
# switch the nightly feature on in its root with
# `#![cfg_attr(docsrs, feature(doc_cfg))]`; without it every build here
# passes and the documentation fails on docs.rs alone, after the release.
# scripts/check-doc-links.sh documents the workspace on the stable pin,
# without `--cfg docsrs`, so it cannot see that; this does.
#
# For each published crate, as scripts/lib/docsrs_build.py reads its table
# from cargo's metadata:
#
#   cargo +NIGHTLY doc --locked -p CRATE --lib --no-deps FEATURES
#
# with RUSTDOCFLAGS set to `--cfg docsrs`, which docs.rs always hands
# rustdoc and every crate's table names. NIGHTLY is the dated nightly
# nightly-toolchain.toml names, which must be installed. A key of the table
# the gate does not apply, or another rustdoc argument, is refused by name
# (the helper says which), and every crate is built even when one fails, so
# one failure does not hide another. `cargo doc` prints nothing and exits 0
# when the docs are fresh, so each crate must also have a rendered page.
#
# What it cannot see: docs.rs builds on its own nightly, not this pin, and
# for x86_64-unknown-linux-gnu, not the host; a crate that needs a system
# library docs.rs's image lacks fails there alone
# (scripts/check-docsrs-features.sh keeps such a feature out of the list).
#
# Builds go to $CARGO_TARGET_DIR/docsrs (default target/docsrs), a folder of
# their own, so this can run beside the stable builds.
#
# Usage: ./scripts/check-docsrs-build.sh

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR" || exit 1
LIB="$AXESS_DIR/scripts/lib"
[ $# -eq 0 ] || { echo "usage: $0" >&2; exit 2; }

nightly="$(sed -n 's/^channel *= *"\(nightly-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\)" *$/\1/p' nightly-toolchain.toml)"
if [ -z "$nightly" ]; then
  echo "ERROR: nightly-toolchain.toml names no dated nightly." >&2
  exit 1
fi
if ! grep -q "^$nightly" <<<"$(rustup toolchain list)"; then
  echo "ERROR: $nightly, the nightly nightly-toolchain.toml names, is not installed. Run: rustup toolchain install $nightly --profile minimal" >&2
  exit 1
fi

TARGET_BASE="${CARGO_TARGET_DIR:-$AXESS_DIR/target}"
export CARGO_TARGET_DIR="$TARGET_BASE/docsrs"
DOC_ROOT="$CARGO_TARGET_DIR/doc"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-docsrs-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if ! cargo metadata --no-deps --format-version 1 >"$WORK/metadata.json"; then
  echo "ERROR: cargo metadata failed, so the crates to document are not known." >&2
  exit 1
fi
python3 -I -B "$LIB/docsrs_build.py" "$WORK/metadata.json" >"$WORK/plan" || exit 1

failed=()
count=0
while IFS='|' read -r crate features; do
  count=$((count + 1))
  read -r -a feature_args <<<"$features"
  echo "== $crate: cargo +$nightly doc -p $crate --lib --no-deps $features"
  if ! RUSTDOCFLAGS="--cfg docsrs" cargo +"$nightly" doc --locked -p "$crate" --lib --no-deps \
      ${feature_args[@]+"${feature_args[@]}"}; then
    failed+=("$crate")
  elif [ ! -f "$DOC_ROOT/${crate//-/_}/index.html" ]; then
    echo "ERROR: $crate: cargo doc passed and rendered no page at $DOC_ROOT/${crate//-/_}/index.html" >&2
    failed+=("$crate")
  fi
done <"$WORK/plan"

if [ "${#failed[@]}" -gt 0 ]; then
  echo "FAILED: the documentation of ${#failed[@]} of $count published crates does not build as docs.rs builds it: ${failed[*]}" >&2
  exit 1
fi
echo "OK: the documentation of all $count published crates builds as docs.rs builds it ($nightly, --cfg docsrs)."
