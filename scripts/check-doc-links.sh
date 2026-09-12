#!/usr/bin/env bash
# axess: fail on a broken intra-doc link anywhere in the workspace.
#
# `[`Foo`]` that does not resolve is not an error at compile time and not a
# test failure; rustdoc emits a warning and docs.rs renders the text
# verbatim, brackets and backticks included. Nothing in `test-all.sh` ran
# rustdoc, so the warnings accumulated unread: at 0.5.0 the workspace
# carried 29 of them, and two named items that do not exist at all
# (`IdTokenClaims`, where the type is `OAuthClaims`; and `TOTP`, which
# `totp-rs` 6.0 renamed to `Totp`: the 0.4.0 dependency bump updated the
# re-export and left the prose above it). A published library's docs are
# part of its surface, so this runs with `-D warnings`.
#
# Three failure shapes this catches, all seen in that sweep:
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
# Usage: ./scripts/check-doc-links.sh
#   DOC_LINKS_SENTINEL_CRATE=name  add `name` to the list of crates whose
#                                  rendered docs must exist. Setting it to a
#                                  crate that is not in the workspace must
#                                  fail the run: that is this script's own
#                                  self-test for the non-vacuity guard below.

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

MANIFEST="$AXESS_DIR/Cargo.toml"

# Isolate the rustdoc artifacts from `cargo test`/`clippy` so this can run
# beside them without fighting for the target-dir lock. An ambient
# CARGO_TARGET_DIR is respected (agents point it at a scratch volume), and
# the subdirectory is added under whichever base applies.
TARGET_BASE="${CARGO_TARGET_DIR:-$AXESS_DIR/target}"
export CARGO_TARGET_DIR="$TARGET_BASE/rustdoc"
DOC_ROOT="$CARGO_TARGET_DIR/doc"

echo "Documenting the workspace with -D warnings (target: $CARGO_TARGET_DIR)"

if ! RUSTDOCFLAGS="-D warnings" cargo doc \
      --manifest-path "$MANIFEST" --workspace --all-features --no-deps; then
  echo "" >&2
  echo "ERROR: rustdoc reported a documentation warning (fatal under -D warnings)." >&2
  echo "       An unresolved link renders as literal text on docs.rs. Qualify it" >&2
  echo "       with a \`crate::\`-absolute path, or drop the link and keep the" >&2
  echo "       backticks if the target is not reachable from a docs build." >&2
  exit 1
fi

# Non-vacuity. `cargo doc` prints nothing and exits 0 when every crate is
# already fresh, so a green exit is not by itself evidence that anything was
# documented: the same failure mode `test-all.sh` had when a step that ran
# zero tests reported PASS. Require rendered output for every workspace
# member, with the member list read from cargo so that adding a crate cannot
# quietly fall outside the check.
MEMBERS="$(cargo metadata --manifest-path "$MANIFEST" --no-deps --format-version 1 \
  | python3 -c 'import json,sys; [print(p["name"]) for p in json.load(sys.stdin)["packages"]]')"

if [ -z "$MEMBERS" ]; then
  echo "ERROR: cargo metadata listed no workspace members: the member query is" >&2
  echo "       broken, not the tree." >&2
  exit 1
fi

if [ -n "${DOC_LINKS_SENTINEL_CRATE:-}" ]; then
  MEMBERS="$MEMBERS
$DOC_LINKS_SENTINEL_CRATE"
fi

missing=0
count=0
while IFS= read -r member; do
  [ -n "$member" ] || continue
  count=$((count + 1))
  # rustdoc renders `axess-core` into `doc/axess_core/`.
  page="$DOC_ROOT/${member//-/_}/index.html"
  if [ ! -f "$page" ]; then
    echo "ERROR: no rendered docs for workspace member '$member' ($page)" >&2
    missing=$((missing + 1))
  fi
done <<< "$MEMBERS"

if [ "$missing" -gt 0 ]; then
  echo "ERROR: rustdoc exited 0 but $missing of $count workspace members have no" >&2
  echo "       rendered page. The invocation documented less than the workspace." >&2
  exit 1
fi

echo "OK: $count workspace members documented, no link warnings."
