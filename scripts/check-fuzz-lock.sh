#!/usr/bin/env bash
# axess: the fuzz crate's lock file agrees with the workspace's.
#
# `fuzz/` is a workspace of its own, so it has a lock file of its own. With
# none committed, each fuzz build resolved the newest version of every
# dependency: two builds of one commit could differ, and the targets ran
# against other code than the workspace ships (a newer `generic-array`
# deprecated a call that the workspace's lock never showed). With one
# committed and nothing holding it, it can name a version of `axess-core`
# the workspace has left.
#
# So the lock file is committed and held to the workspace's: this fails when
# a package that both lock files name is held by the fuzz lock at a version
# the workspace's lock does not hold. A package only the fuzz crate depends
# on (`libfuzzer-sys`, `arbitrary`) is the fuzz lock's own business.
#
# And the lock file is current: it is what cargo itself writes for the fuzz
# manifest. `cargo metadata --locked` (the Lockfile Drift job runs it) only
# asks whether the lock covers the manifests, and a lock that holds more
# than they ask for covers them: an edge to a package a manifest no longer
# names (the fuzz lock once kept one from axess-factors to axum) passed it.
# So this runs `cargo update --workspace --offline` on a copy of the lock,
# beside a copy of the fuzz manifest whose path dependencies reach this
# repository's crates, and refuses a lock the update would change, naming
# each package whose edges differ. The update moves no version (it updates
# the fuzz crate's own package only); it writes the lock again from the
# manifests. It reads the registry index from cargo's local cache, which a
# `cargo metadata` on the fuzz manifest fills. With the cache cold it cannot
# run, and the check then fails with the reason (exit 3); it never passes
# on a lock it could not read again.
#
# To bring it back in step after the workspace's lock changes, with the
# cargo rust-toolchain.toml pins:
#
#   cp Cargo.lock fuzz/Cargo.lock
#   (cd fuzz && cargo metadata --format-version 1 > /dev/null)
#   (cd fuzz && cargo update --workspace --offline)
#   ./scripts/check-lock-age.sh
#
# The copy holds every package both crates use at the workspace's version.
# The packages only the fuzz crate uses (`libfuzzer-sys`, `arbitrary` and
# theirs) are not in it, so cargo resolves them afresh, and under the same
# publish-age rule as the workspace's lock: cargo 1.100 and later read
# `registry.global-min-publish-age` from .cargo/config.toml, which applies
# inside fuzz/ too (an older cargo prints that it ignores the key, and such
# a run is not this recipe). The lock-age check then reads both lock files
# and refuses, by name, a version younger than the rule in either.
#
# Usage: ./scripts/check-fuzz-lock.sh [--locks WORKSPACE_LOCK FUZZ_LOCK | --current ROOT]
#   --locks A B     compare the versions of those two files only
#   --current ROOT  check only that ROOT/fuzz/Cargo.lock is current for
#                   ROOT/fuzz/Cargo.toml, ROOT standing for this repository
#   (both for scripts/check-fuzz-lock-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECIPE='Bring it back in step, with the cargo rust-toolchain.toml pins:
  cp Cargo.lock fuzz/Cargo.lock
  (cd fuzz && cargo metadata --format-version 1 > /dev/null)
  (cd fuzz && cargo update --workspace --offline)
  ./scripts/check-lock-age.sh'
mirror=""
trap '[ -z "$mirror" ] || rm -rf "$mirror"' EXIT

# same_versions WORKSPACE_LOCK FUZZ_LOCK: every package both name is held by
# the fuzz lock at a version the workspace's holds.
same_versions() {
  local lock
  for lock in "$1" "$2"; do
    if [ ! -f "$lock" ]; then
      echo "ERROR: no lock file at $lock" >&2
      return 1
    fi
  done
  python3 - "$1" "$2" "$RECIPE" <<'PY'
import re
import sys


def packages(path):
    """name -> set of versions, from the [[package]] tables of a lock file."""
    held = {}
    text = open(path, encoding="utf-8").read()
    for table in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"$', table, re.M)
        version = re.search(r'^version = "([^"]+)"$', table, re.M)
        if name and version:
            held.setdefault(name.group(1), set()).add(version.group(1))
    return held


workspace, fuzz = packages(sys.argv[1]), packages(sys.argv[2])
if not fuzz:
    sys.exit(f"ERROR: {sys.argv[2]} names no package")
differing = [
    (name, version, sorted(workspace[name]))
    for name, versions in sorted(fuzz.items())
    if name in workspace
    for version in sorted(versions - workspace[name])
]
if differing:
    print("ERROR: the fuzz lock file holds packages at versions the workspace's does not:\n")
    for name, version, held in differing:
        print(f"  {name} {version} (the workspace holds {', '.join(held)})")
    print("\n" + sys.argv[3])
    sys.exit(1)
shared = sum(1 for name in fuzz if name in workspace)
print(f"OK: the fuzz lock file holds {shared} shared packages at the workspace's versions.")
PY
}

# mirror_of ROOT: a directory that stands for ROOT, every entry a link to
# ROOT's own but fuzz/, whose manifest and lock file are copies (cargo
# writes the copy, never the file it was made from) and whose other entries
# are links. Its path is left in `mirror`.
mirror_of() {
  local root="$1" entry name
  mirror="$(mktemp -d "${TMPDIR:-/tmp}/axess-fuzz-current.XXXXXX")"
  for entry in "$root"/* "$root"/.[!.]*; do
    [ -e "$entry" ] || continue
    name="${entry##*/}"
    case "$name" in .git | fuzz | target) continue ;; esac
    ln -s "$entry" "$mirror/$name"
  done
  mkdir "$mirror/fuzz"
  for entry in "$root"/fuzz/* "$root"/fuzz/.[!.]*; do
    [ -e "$entry" ] || continue
    name="${entry##*/}"
    case "$name" in
      Cargo.toml | Cargo.lock) cp "$entry" "$mirror/fuzz/$name" ;;
      target | corpus | artifacts | coverage) ;;
      *) ln -s "$entry" "$mirror/fuzz/$name" ;;
    esac
  done
}

# current ROOT: ROOT/fuzz/Cargo.lock is what `cargo update --workspace
# --offline` writes for ROOT/fuzz/Cargo.toml.
current() {
  local root="$1" before after file
  for file in "$root/fuzz/Cargo.toml" "$root/fuzz/Cargo.lock"; do
    if [ ! -f "$file" ]; then
      echo "ERROR: no file at $file" >&2
      return 1
    fi
  done
  before="$(cksum < "$root/fuzz/Cargo.lock")"
  mirror_of "$root"
  if ! (cd "$mirror/fuzz" && cargo update --workspace --offline) > "$mirror/update.log" 2>&1; then
    echo "ERROR: not checked, and so not passed: cargo update --workspace --offline could not run on a copy of the fuzz lock file:" >&2
    sed 's/^/    /' "$mirror/update.log" >&2
    echo "With a cold registry cache the offline update has no index to read: fill the cache (cargo metadata --format-version 1 --manifest-path fuzz/Cargo.toml > /dev/null) and run this again." >&2
    return 3
  fi
  after="$(cksum < "$root/fuzz/Cargo.lock")"
  if [ "$before" != "$after" ]; then
    echo "ERROR: $root/fuzz/Cargo.lock changed while its copy was updated; the check wrote the file it reads." >&2
    return 1
  fi
  python3 - "$root/fuzz/Cargo.lock" "$mirror/fuzz/Cargo.lock" "$RECIPE" <<'PY'
import difflib
import sys

try:
    import tomllib
except ImportError:
    sys.exit("ERROR: python3 has no tomllib (3.11 or newer); the lock files cannot be read.")

committed_path, updated_path, recipe = sys.argv[1:4]
committed_text = open(committed_path, encoding="utf-8").read()
updated_text = open(updated_path, encoding="utf-8").read()
if committed_text == updated_text:
    count = len(tomllib.loads(committed_text).get("package", []))
    print(f"OK: the fuzz lock file is what cargo writes for its manifest ({count} packages).")
    sys.exit(0)


def edges(text):
    """(name, version) -> the set of its dependency entries, from a lock file."""
    return {
        (p["name"], p["version"]): set(p.get("dependencies", []))
        for p in tomllib.loads(text).get("package", [])
    }


committed, updated = edges(committed_text), edges(updated_text)
lines = []
for key in sorted(committed.keys() | updated.keys()):
    label = f"{key[0]} {key[1]}"
    if key not in updated:
        lines.append(f"  {label}: in the lock file, and reached by no manifest")
    elif key not in committed:
        lines.append(f"  {label}: reached by the manifests, and missing from the lock file")
    else:
        for dep in sorted(committed[key] - updated[key]):
            lines.append(f"  {label}: an edge to {dep} that its manifest does not make")
        for dep in sorted(updated[key] - committed[key]):
            lines.append(f"  {label}: an edge to {dep} that the lock file lacks")
print("ERROR: the fuzz lock file is not what cargo writes for its manifest; cargo update --workspace --offline changes it:\n")
if lines:
    print("\n".join(lines))
else:
    diff = difflib.unified_diff(
        committed_text.splitlines(), updated_text.splitlines(), "fuzz/Cargo.lock", "updated", lineterm=""
    )
    print("  no package's edges differ; the text does:")
    print("\n".join("    " + line for line in list(diff)[:40]))
print("\n" + recipe)
sys.exit(1)
PY
}

if [ $# -eq 0 ]; then
  same_versions "$AXESS_DIR/Cargo.lock" "$AXESS_DIR/fuzz/Cargo.lock"
  current "$AXESS_DIR"
elif [ $# -eq 3 ] && [ "$1" = "--locks" ]; then
  same_versions "$2" "$3"
elif [ $# -eq 2 ] && [ "$1" = "--current" ]; then
  current "$2"
else
  echo "usage: $0 [--locks WORKSPACE_LOCK FUZZ_LOCK | --current ROOT]" >&2
  exit 2
fi
