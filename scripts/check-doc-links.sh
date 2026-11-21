#!/usr/bin/env bash
# axess: fail on a broken intra-doc link anywhere in the workspace.
#
# `[`Foo`]` that does not resolve is not an error at compile time and not a
# test failure; rustdoc emits a warning and docs.rs renders the text
# verbatim, brackets and backticks included. A warning nothing reads
# accumulates: a link to a type that was renamed, or a dependency bump that
# updates a re-export and leaves the prose above it naming the old item. A
# published library's docs are part of its surface, so this runs with
# `-D warnings`.
#
# Three failure shapes this catches:
#   - a path written relative (`workload::WorkloadResolver`), which resolves
#     in the module that wrote it but not where the doc comment travels with
#     a re-export. `crate::`-absolute resolves in both.
#   - a link into a dev-dependency's feature (`axess_clock::testing::MockClock`),
#     which no documentation build can see. Name it in backticks instead.
#   - a link to an item that was renamed or never existed.
#
# It also rejects a link that is *needlessly* explicit: rustdoc's
# `redundant_explicit_links` lint fires when `[`Foo`](path::Foo)` would have
# resolved as plain `[`Foo`]`, which is how the module-level qualification
# above is kept from spreading into item docs where the type is in scope.
#
# Every member is documented and every error is reported with its crate:
# `--keep-going` documents the members after one that fails (a member's
# rustdoc reads the metadata of the members it uses, not their docs), so an
# error in one crate does not hide the errors of those that depend on it.
# Where rustdoc gives no file or line (a redundant link target in the docs
# of a module written both on its `mod` line and in its own file), the
# report names the links it can come from. scripts/lib/doc_links.py reads
# cargo's messages; scripts/check-doc-links-tests.sh holds its cases.
#
# Usage: ./scripts/check-doc-links.sh
#   DOC_LINKS_SENTINEL_CRATE=name  add `name` to the list of crates whose
#                                  rendered docs must exist. Setting it to a
#                                  crate that is not in the workspace must
#                                  fail the run: that is this script's own
#                                  self-test for the non-vacuity guard.

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR" || exit 1

MANIFEST="$AXESS_DIR/Cargo.toml"
LIB="$AXESS_DIR/scripts/lib"

# Isolate the rustdoc artifacts from `cargo test`/`clippy` so this can run
# beside them without fighting for the target-dir lock. An ambient
# CARGO_TARGET_DIR is respected (agents point it at a scratch volume), and
# the subdirectory is added under whichever base applies.
TARGET_BASE="${CARGO_TARGET_DIR:-$AXESS_DIR/target}"
export CARGO_TARGET_DIR="$TARGET_BASE/rustdoc"
DOC_ROOT="$CARGO_TARGET_DIR/doc"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-doc-links.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if ! cargo metadata --manifest-path "$MANIFEST" --no-deps --format-version 1 >"$WORK/metadata.json"; then
  echo "ERROR: cargo metadata failed, so the members to document are not known." >&2
  exit 1
fi

echo "Documenting the workspace with -D warnings (target: $CARGO_TARGET_DIR)"

# Non-vacuity. `cargo doc` prints nothing and exits 0 when every crate is
# already fresh, so a green exit is not by itself evidence that anything was
# documented: the same failure mode `test-all.sh` had when a step that ran
# zero tests reported PASS. The report requires a rendered page for every
# workspace member that reported nothing, with the member list read from
# cargo so that adding a crate cannot quietly fall outside the check.
RUSTDOCFLAGS="-D warnings" cargo doc \
  --manifest-path "$MANIFEST" --workspace --all-features --no-deps \
  --keep-going --message-format=json >"$WORK/messages.json"
status=$?

python3 -I -B "$LIB/doc_links.py" "$WORK/messages.json" "$WORK/metadata.json" "$DOC_ROOT" "$status" \
  "${DOC_LINKS_SENTINEL_CRATE:-}"
