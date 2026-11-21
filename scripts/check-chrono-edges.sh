#!/usr/bin/env bash
# axess: chrono is named where an upstream crate hands it, and nowhere else.
#
# The time types of the workspace are axess-clock's (`Timestamp`,
# `SignedDuration`, `Until`, `UtcDate`), on the standard library alone. chrono
# and chrono-tz are declared unmaintained (RUSTSEC-2026-0543,
# RUSTSEC-2026-0555), so no crate here builds on them, and no adopter is
# handed a chrono type. This holds that, in four parts.
#
# 1. Direct edges. A manifest of the workspace, an example's or the fuzz
#    crate's included, depends on chrono only as listed in ADMITTED:
#
#      axess-factors  an optional normal dependency that the feature `oauth`
#                     alone names: openidconnect's ID-token verifier reads the
#                     time through a closure that returns a chrono value, so
#                     the reading is converted where it crosses. A feature
#                     reaches it through `oauth` or not at all.
#      axess-clock    a dev-dependency: the oracle of
#                     `tests/chrono_agreement.rs`, which holds the time types
#                     to the values and texts earlier releases computed with
#                     chrono, and the other library of
#                     `tests/other_time_library.rs`, the conversions at an
#                     adopter's boundary. No library code of the crate names
#                     it.
#
#    Any other edge, of any kind, is refused: a normal or build edge in
#    another crate, a dev edge outside axess-clock, the axess-factors edge
#    made unconditional or named by a second feature, a renamed edge
#    (`package = "chrono"`).
#
# 2. chrono-tz. No manifest names it and neither lock file holds it.
#
# 3. Public items. In the library code of the workspace's crates (each
#    crate's `src/` less its test code, with comments and literals taken
#    out) the name `chrono` stands only in the files of BOUNDARY, the private
#    conversion beside the upstream crate, and there in no public item: not
#    in the signature of a `pub fn`, the header of a `pub` type, a `pub`
#    field, a `pub const` or `static`, or a `pub use`. An item of restricted
#    visibility (`pub(crate)`, `pub(super)`) is not an adopter's to name and
#    may carry the value inside the crate. This is a text rule: it sees the
#    name, not a type that hides one behind an alias, which is why every
#    other file may not spell the name at all.
#
# 4. The tree an adopter gets with no feature chosen. For each published
#    crate, `cargo tree -e normal --no-default-features` holds no chrono,
#    with one named exception, written in VIA_UPSTREAM: the facade `axess`.
#    It always enables authorization (its manifest asks axess-core for
#    `authz` whatever features an adopter chooses, the surface the facade
#    has always offered), authorization is Cedar, and Cedar's core,
#    `cedar-policy-core`, depends on chrono for its own datetime
#    extension. No axess signature names chrono there: the request context
#    hands Cedar the time as text. No other crate may join the exception.
#    chrono may reach a build through three upstream crates,
#    `cedar-policy-core`, `oauth2` and `openidconnect`, and through nothing
#    else: with those three pruned, no tree of any published crate holds
#    chrono, and a crate not in VIA_UPSTREAM holds none even through them.
#
# The rules are in scripts/lib/chrono_edges.py.
#
# Usage: ./scripts/check-chrono-edges.sh [--text-root DIR]
#   --text-root DIR  run part 3 alone on the Rust files under DIR
#                    (scripts/check-chrono-edges-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

TEXT_ROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --text-root) TEXT_ROOT="${2:-}"; shift 2 ;;
    *) echo "usage: $0 [--text-root DIR]" >&2; exit 2 ;;
  esac
done

if [ -n "$TEXT_ROOT" ]; then
  [ -d "$TEXT_ROOT" ] || { echo "usage: $0 [--text-root DIR]" >&2; exit 2; }
  cd "$TEXT_ROOT"
  files() { find . -name '*.rs' -type f | sed 's|^\./||' | sort; }
else
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not yet
  # added is checked as well.
  files() { git ls-files --cached --others --exclude-standard --deduplicate '*.rs'; }
fi

status=0

# ── Part 3: no public item names chrono ──────────────────────────────────────
listed="$(files)"
python3 -I -B -c "
import sys

sys.path.insert(0, sys.argv[1])
import chrono_edges

sys.exit(chrono_edges.text_rule(sys.stdin.read().split()))
" "$LIB" <<<"$listed" || status=1

if [ -n "$TEXT_ROOT" ]; then
  exit "$status"
fi

# ── Parts 1 and 2: the manifests and the lock files ──────────────────────────
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-chrono-edges.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
cargo metadata --format-version 1 --no-deps --locked > "$WORK/workspace.json" 2>"$WORK/stderr" || {
  echo "ERROR: cargo metadata could not read the workspace:" >&2; cat "$WORK/stderr" >&2; exit 1; }
cargo metadata --format-version 1 --no-deps --locked --manifest-path fuzz/Cargo.toml > "$WORK/fuzz.json" 2>"$WORK/stderr" || {
  echo "ERROR: cargo metadata could not read fuzz/Cargo.toml:" >&2; cat "$WORK/stderr" >&2; exit 1; }

# The rule prints the published crates, one a line, for part 4.
if published="$(python3 -I -B -c "
import sys

sys.path.insert(0, sys.argv[1])
import chrono_edges

sys.exit(chrono_edges.manifest_rule(sys.argv[2], sys.argv[3], [\"Cargo.lock\", \"fuzz/Cargo.lock\"]))
" "$LIB" "$WORK/workspace.json" "$WORK/fuzz.json")"; then
  echo "ok: chrono is a direct dependency of axess-factors (optional, feature oauth) and of axess-clock (dev) alone; no chrono-tz"
else
  status=1
fi

# ── Part 4: the tree with no feature chosen ──────────────────────────────────
UPSTREAM=(cedar-policy-core oauth2 openidconnect)
# VIA_UPSTREAM: the upstream crate a published crate's tree holds chrono
# through with no feature chosen; nothing for a crate that holds none. One
# entry, `axess`, which always enables authorization (part 4 of the header).
via_upstream() {
  case "$1" in
    axess) echo cedar-policy-core ;;
  esac
}

tree_of() { cargo tree -p "$1" -e normal --no-default-features --prefix none --locked "${@:2}" 2>&1; }
holds() { grep -qE "^$1 v"; }

for crate in $published; do
  tree="$(tree_of "$crate")" || { echo "ERROR: cargo tree failed for $crate: $tree" >&2; status=1; continue; }
  # cargo refuses to prune a crate the tree does not hold, so each tree is
  # pruned of the upstream crates it has.
  prune=()
  for upstream in "${UPSTREAM[@]}"; do
    if holds "$upstream" <<<"$tree"; then
      prune+=(--prune "$upstream")
    fi
  done
  pruned="$tree"
  if [ "${#prune[@]}" -gt 0 ]; then
    pruned="$(tree_of "$crate" "${prune[@]}")" || { echo "ERROR: cargo tree failed for $crate: $pruned" >&2; status=1; continue; }
  fi
  if holds chrono <<<"$pruned"; then
    echo "REFUSED: $crate with no feature chosen holds chrono, and not through ${UPSTREAM[*]}:" >&2
    cargo tree -p "$crate" -e normal --no-default-features --locked -i chrono ${prune[@]+"${prune[@]}"} >&2 || true
    status=1
    continue
  fi
  through="$(via_upstream "$crate")"
  if holds chrono <<<"$tree"; then
    if [ -z "$through" ]; then
      echo "REFUSED: $crate with no feature chosen holds chrono through an upstream crate; only a crate of VIA_UPSTREAM may:" >&2
      cargo tree -p "$crate" -e normal --no-default-features --locked -i chrono >&2 || true
      status=1
    elif ! holds "$through" <<<"$tree"; then
      echo "REFUSED: $crate holds chrono, and its tree does not hold $through, the crate VIA_UPSTREAM names for it." >&2
      status=1
    fi
  elif [ -n "$through" ]; then
    echo "REFUSED: $crate no longer holds chrono with no feature chosen; take it out of VIA_UPSTREAM." >&2
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "ok: with no feature chosen no published crate holds chrono, but axess through cedar-policy-core"
fi
exit "$status"
