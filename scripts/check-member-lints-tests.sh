#!/usr/bin/env bash
# axess: crafted cases for scripts/check-member-lints.sh.
#
# Each case writes a workspace (its manifest and its members' manifests)
# under a temporary root, runs the check against it with `--root`, and
# asserts the exit status and a fragment of the output. The refusals are the
# contract: a member that does not take the workspace lint table, or holds
# one of its own, is named by its manifest, wherever the workspace finds it;
# the workspace table denies unused dependencies and allows no lint.
#
# Usage: ./scripts/check-member-lints-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-member-lints.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-member-lints.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case NAME EXPECTED_EXIT FRAGMENT [UNWANTED] -- FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3" unwanted=""
  shift 3
  if [ "$1" != "--" ]; then unwanted="$1"; shift; fi
  shift
  local root="$WORK/$passed-$failed"
  mkdir -p "$root"
  while [ $# -gt 0 ]; do
    mkdir -p "$root/$(dirname "$1")"
    printf '%s\n' "$2" > "$root/$1"
    shift 2
  done
  local out status
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out" "$unwanted"
}

TABLE='[workspace.lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(loom)"] }

[workspace.lints.cargo]
unused_dependencies = "deny"'
WS="[workspace]
members = [\"lib\", \"examples/*\"]
$TABLE"
TAKES='[package]
name = "m"

[lints]
workspace = true'
BARE='[package]
name = "m"'

case_ "every member taking the table passes" 0 "ok: 2 member(s) take the workspace lint table" -- \
  Cargo.toml "$WS" lib/Cargo.toml "$TAKES" examples/a/Cargo.toml "$TAKES"

# A member without the opt-in, wherever the workspace finds it.
case_ "a member without workspace = true is refused" 1 "lib/Cargo.toml: no [lints] workspace = true" -- \
  Cargo.toml "$WS" lib/Cargo.toml "$BARE" examples/a/Cargo.toml "$TAKES"
case_ "a new example without it is refused" 1 "examples/b/Cargo.toml: no [lints] workspace = true" -- \
  Cargo.toml "$WS" lib/Cargo.toml "$TAKES" examples/a/Cargo.toml "$TAKES" examples/b/Cargo.toml "$BARE"
case_ "workspace = false is refused" 1 "lib/Cargo.toml: [lints] is not workspace = true" -- \
  Cargo.toml "$WS" lib/Cargo.toml '[package]
name = "m"
[lints]
workspace = false' examples/a/Cargo.toml "$TAKES"
case_ "an empty [lints] is refused" 1 "lib/Cargo.toml: [lints] is not workspace = true" -- \
  Cargo.toml "$WS" lib/Cargo.toml '[package]
name = "m"
[lints]' examples/a/Cargo.toml "$TAKES"
case_ "the root package is a member" 1 "Cargo.toml: no [lints] workspace = true" "lib/Cargo.toml" -- \
  Cargo.toml "[package]
name = \"root\"
$WS" lib/Cargo.toml "$TAKES" examples/a/Cargo.toml "$TAKES"

# A member's own table, alone or beside the opt-in.
case_ "a member's own lints table is refused" 1 "lib/Cargo.toml: a [lints.rust] table of its own" -- \
  Cargo.toml "$WS" lib/Cargo.toml '[package]
name = "m"
[lints.rust]
unexpected_cfgs = "warn"' examples/a/Cargo.toml "$TAKES"
case_ "an own table beside workspace = true is refused" 1 "examples/a/Cargo.toml: a [lints.clippy] table of its own" -- \
  Cargo.toml "$WS" lib/Cargo.toml "$TAKES" examples/a/Cargo.toml "$TAKES
[lints.clippy]
all = \"deny\""

# Which paths are members.
case_ "an excluded path is not a member" 0 "ok: 2 member(s)" -- \
  Cargo.toml "[workspace]
members = [\"lib\", \"examples/*\"]
exclude = [\"examples/old\"]
$TABLE" lib/Cargo.toml "$TAKES" examples/a/Cargo.toml "$TAKES" examples/old/Cargo.toml "$BARE"
case_ "a path outside the members is not read" 0 "ok: 2 member(s)" -- \
  Cargo.toml "$WS" lib/Cargo.toml "$TAKES" examples/a/Cargo.toml "$TAKES" fuzz/Cargo.toml "$BARE"
case_ "a member path with no manifest is refused" 1 "examples/c: a workspace member (members entry examples/*) with no Cargo.toml" -- \
  Cargo.toml "$WS" lib/Cargo.toml "$TAKES" examples/a/Cargo.toml "$TAKES" examples/c/README.md "x"
case_ "a named member with no manifest is refused" 1 "lib: a workspace member (members entry lib) with no Cargo.toml" -- \
  Cargo.toml "$WS" lib/README.md "x" examples/a/Cargo.toml "$TAKES"
case_ "a workspace with no member is no pass" 1 "ERROR: the workspace names no member" -- \
  Cargo.toml "[workspace]
members = []
$TABLE"
case_ "a manifest with no workspace is no pass" 1 "ERROR: Cargo.toml declares no [workspace]" -- \
  Cargo.toml "$BARE"
case_ "a manifest that is not TOML is refused" 1 "lib/Cargo.toml: cannot be read as TOML" -- \
  Cargo.toml "$WS" lib/Cargo.toml "[package" examples/a/Cargo.toml "$TAKES"

# The workspace's table.
case_ "a workspace without the table is refused" 1 "Cargo.toml: no [workspace.lints] table" -- \
  Cargo.toml '[workspace]
members = ["lib"]' lib/Cargo.toml "$TAKES"
case_ "unused dependencies at warn are refused" 1 "unused_dependencies is warn, not deny" -- \
  Cargo.toml '[workspace]
members = ["lib"]
[workspace.lints.cargo]
unused_dependencies = "warn"' lib/Cargo.toml "$TAKES"
case_ "unused dependencies denied in table form pass" 0 "ok: 1 member(s)" -- \
  Cargo.toml '[workspace]
members = ["lib"]
[workspace.lints.cargo]
unused_dependencies = { level = "deny", priority = 1 }' lib/Cargo.toml "$TAKES"
case_ "a lint allowed in the table is refused" 1 "[workspace.lints.clippy] cmp_owned is set to allow" -- \
  Cargo.toml "$WS
[workspace.lints.clippy]
cmp_owned = \"allow\"" lib/Cargo.toml "$TAKES" examples/a/Cargo.toml "$TAKES"
case_ "a lint expected in table form is refused" 1 "[workspace.lints.rust] dead_code is set to expect" -- \
  Cargo.toml '[workspace]
members = ["lib"]
[workspace.lints.rust]
dead_code = { level = "expect", priority = -1 }
[workspace.lints.cargo]
unused_dependencies = "deny"' lib/Cargo.toml "$TAKES"

echo "check-member-lints tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
