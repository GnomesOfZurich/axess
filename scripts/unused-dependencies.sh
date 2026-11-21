#!/usr/bin/env bash
# axess: unused dev-dependencies as cargo-udeps finds them, for a local run.
#
# Normal and build dependencies are cargo's own lint's: `unused_dependencies`
# is denied in Cargo.toml's [workspace.lints.cargo], so every all-targets
# clippy and check refuses one no target uses
# (scripts/check-unused-dependency-lint.sh proves it fires). The lint never
# reads dev-dependencies; this does. cargo-udeps builds the workspace on a
# nightly toolchain and reads what the compiler used, so it does not report
# a dependency that is used only through a macro, and it takes a full build
# to say so. It reports normal and build dependencies too; the lint has
# already refused those.
#
# It stands in a script of its own, which no workflow runs: a job runs only
# the cargo subcommands it installs (scripts/check-workflow-pins.sh), and
# the jobs that run the supply-chain gate install no nightly toolchain and
# no cargo-udeps.
#
# Needs cargo-udeps on the path (cargo install --locked cargo-udeps) and the
# dated nightly nightly-toolchain.toml names (rustup toolchain install it).
#
# Usage: scripts/unused-dependencies.sh

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
nightly="$(sed -n 's/^channel *= *"\(nightly-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\)" *$/\1/p' nightly-toolchain.toml)"
if [ -z "$nightly" ]; then
  echo "ERROR: nightly-toolchain.toml names no dated nightly (channel = \"nightly-YYYY-MM-DD\")." >&2
  exit 1
fi
exec cargo +"$nightly" udeps --workspace --all-targets --all-features
