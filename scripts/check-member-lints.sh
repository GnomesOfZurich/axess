#!/usr/bin/env bash
# axess: every workspace member takes the workspace's lint table, and the
# table allows no lint away.
#
# One lint table in the workspace manifest (`[workspace.lints.*]`) holds
# for every member only when each member opts in with `[lints] workspace =
# true`; a member without it builds with the compiler's defaults, and cargo
# says nothing. So this refuses, by manifest:
#
#   - a member whose `[lints]` is missing, is not exactly `workspace =
#     true`, or holds a table of its own (`[lints.rust]`, `[lints.clippy]`,
#     ...; cargo 1.100 refuses one beside `workspace = true` as well);
#   - a workspace manifest without `[workspace.lints]`, or whose
#     `[workspace.lints.cargo]` does not deny `unused_dependencies`;
#   - a lint set to `allow` or `expect` in the workspace's table (the rule
#     scripts/check-lint-allowances.sh holds for attributes).
#
# The members are read from the workspace manifest as cargo reads them
# (`members` with its globs, less `exclude`, and the root package if there
# is one), not from a list here, so a new example is held the day it is
# added. A path a member glob matches that holds no Cargo.toml is refused,
# as cargo refuses it. Needs python3 3.11 or newer (tomllib).
#
# Usage: ./scripts/check-member-lints.sh [--root DIR]
#   --root DIR  check the workspace whose manifest is DIR/Cargo.toml
#               (scripts/check-member-lints-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$2"
else
  [ $# -eq 0 ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$AXESS_DIR"
fi

python3 -I -B -c '
import glob, os, sys

try:
    import tomllib
except ImportError:
    print("ERROR: python3 has no tomllib (3.11 or newer); the manifests cannot be read.", file=sys.stderr)
    sys.exit(1)

refused = []


def load(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as err:
        refused.append(f"{path}: cannot be read as TOML ({err})")
        return None


def level(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("level")
    return None


root = load("Cargo.toml")
workspace = root.get("workspace") if root else None
if not isinstance(workspace, dict):
    print("ERROR: Cargo.toml declares no [workspace]; nothing was checked.", file=sys.stderr)
    sys.exit(1)

lints = workspace.get("lints")
if not isinstance(lints, dict) or not lints:
    refused.append("Cargo.toml: no [workspace.lints] table for the members to take")
    lints = {}
cargo = lints.get("cargo") if isinstance(lints.get("cargo"), dict) else {}
unused = level(cargo.get("unused_dependencies")) or "not set"
if unused != "deny":
    refused.append(f"Cargo.toml: [workspace.lints.cargo] unused_dependencies is {unused}, not deny")
for tool, table in lints.items():
    if not isinstance(table, dict):
        continue
    for lint, value in table.items():
        if level(value) in ("allow", "expect"):
            refused.append(f"Cargo.toml: [workspace.lints.{tool}] {lint} is set to {level(value)}; fix what it reports")

excluded = {os.path.normpath(p) for p in workspace.get("exclude", [])}
members = []
if isinstance(root.get("package"), dict):
    members.append(".")
for pattern in workspace.get("members", []):
    matches = sorted(glob.glob(pattern)) if glob.has_magic(pattern) else [pattern]
    for path in matches:
        path = os.path.normpath(path)
        if path in excluded or (glob.has_magic(pattern) and not os.path.isdir(path)):
            continue
        if not os.path.isfile(os.path.join(path, "Cargo.toml")):
            refused.append(f"{path}: a workspace member (members entry {pattern}) with no Cargo.toml")
            continue
        if path not in members:
            members.append(path)
if not members:
    print("ERROR: the workspace names no member; nothing was checked.", file=sys.stderr)
    sys.exit(1)

for path in members:
    manifest = os.path.normpath(os.path.join(path, "Cargo.toml"))
    doc = load(manifest)
    if doc is None:
        continue
    own = doc.get("lints")
    if own is None:
        refused.append(f"{manifest}: no [lints] workspace = true; the member builds without the workspace lint table")
        continue
    if not isinstance(own, dict) or own.get("workspace") is not True:
        refused.append(f"{manifest}: [lints] is not workspace = true")
    for key in own if isinstance(own, dict) else []:
        if key != "workspace":
            refused.append(f"{manifest}: a [lints.{key}] table of its own; a member takes the workspace table only")

for line in refused:
    print(line, file=sys.stderr)
if refused:
    print(f"{len(refused)} refusal(s); see the header of scripts/check-member-lints.sh.", file=sys.stderr)
    sys.exit(1)
print(f"ok: {len(members)} member(s) take the workspace lint table, which denies unused dependencies and allows no lint")
'
