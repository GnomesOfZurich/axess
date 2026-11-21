#!/usr/bin/env bash
# axess: crafted cases for scripts/check-fuzz-lock.sh.
#
# Each case writes a workspace lock file and a fuzz lock file under a
# temporary root, runs the check on the pair, and asserts the exit status
# and a fragment of the output. The refusal is the contract: a package both
# files name, held by the fuzz lock at a version the workspace's lacks.
#
# The cases of the current check (`--current`) write a small repository of
# path crates with a fuzz/ workspace of its own, so cargo resolves it with no
# registry: a lock file cargo would write again passes, one with an edge no
# manifest makes is refused naming the package, and an update that cannot
# run on a cold registry cache fails with its reason.
#
# Usage: ./scripts/check-fuzz-lock-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-fuzz-lock.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-fuzz-lock.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

passed=0
failed=0

# lock NAME VERSION [NAME VERSION...]: a lock file's text
lock() {
  printf 'version = 4\n'
  while [ $# -gt 0 ]; do
    printf '\n[[package]]\nname = "%s"\nversion = "%s"\n' "$1" "$2"
    shift 2
  done
}

# case NAME EXPECTED_EXIT FRAGMENT WORKSPACE_LOCK_TEXT FUZZ_LOCK_TEXT
case_() {
  local name="$1" want="$2" fragment="$3"
  printf '%s' "$4" > "$WORK/workspace.lock"
  printf '%s' "$5" > "$WORK/fuzz.lock"
  local out status
  out="$("$CHECK" --locks "$WORK/workspace.lock" "$WORK/fuzz.lock" 2>&1)"
  status=$?
  if [ "$status" -eq "$want" ] && grep -qF -- "$fragment" <<<"$out"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment', got exit $status:" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

WORKSPACE="$(lock axess-core 0.20.0 generic-array 0.14.7 syn 1.0.109 syn 2.0.100 tokio 1.54.1)"

case_ "a subset of the workspace's packages passes" 0 "2 shared packages" \
  "$WORKSPACE" "$(lock axess-core 0.20.0 generic-array 0.14.7)"
case_ "a package only the fuzz crate depends on is its own business" 0 "1 shared packages" \
  "$WORKSPACE" "$(lock generic-array 0.14.7 libfuzzer-sys 0.4.13 axess-fuzz 0.20.0)"
case_ "either of two versions the workspace holds passes" 0 "OK" \
  "$WORKSPACE" "$(lock syn 1.0.109 syn 2.0.100)"
case_ "a newer version of a shared package is refused by name" 1 "generic-array 0.14.9 (the workspace holds 0.14.7)" \
  "$WORKSPACE" "$(lock axess-core 0.20.0 generic-array 0.14.9)"
case_ "a workspace crate at a version the workspace left is refused" 1 "axess-core 0.0.16 (the workspace holds 0.20.0)" \
  "$WORKSPACE" "$(lock axess-core 0.0.16)"
case_ "one of two versions that the workspace lacks is refused" 1 "syn 3.0.0 (the workspace holds 1.0.109, 2.0.100)" \
  "$WORKSPACE" "$(lock syn 2.0.100 syn 3.0.0)"
case_ "the refusal says how to bring the file back in step" 1 "cp Cargo.lock fuzz/Cargo.lock" \
  "$WORKSPACE" "$(lock tokio 1.0.0)"
case_ "the refusal ends the recipe with the lock-age check" 1 "./scripts/check-lock-age.sh" \
  "$WORKSPACE" "$(lock tokio 1.0.0)"
case_ "the refusal names the toolchain the recipe needs" 1 "with the cargo rust-toolchain.toml pins" \
  "$WORKSPACE" "$(lock tokio 1.0.0)"
case_ "a fuzz lock file that names no package is refused" 1 "names no package" \
  "$WORKSPACE" "version = 4"

# A missing file is refused before anything is compared.
out="$("$CHECK" --locks "$WORK/workspace.lock" "$WORK/absent.lock" 2>&1)"
status=$?
if [ "$status" -eq 1 ] && grep -qF "no lock file at" <<<"$out"; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: a missing lock file: wanted exit 1, got exit $status: $out" >&2
fi

# repo DIR FUZZ_LOCK_TEXT [FUZZ_DEPENDENCY_LINE]: a repository of path crates
# `a` and `b` (neither depending on anything) whose fuzz/ crate `f` depends
# on both, with the pinned toolchain of this repository.
repo() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir/a" "$dir/b" "$dir/fuzz"
  ln -s "$SCRIPT_DIR/../rust-toolchain.toml" "$dir/rust-toolchain.toml"
  for crate in a b; do
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\npath = "lib.rs"\n' "$crate" > "$dir/$crate/Cargo.toml"
    : > "$dir/$crate/lib.rs"
  done
  printf '[package]\nname = "f"\nversion = "0.1.0"\nedition = "2021"\n\n[workspace]\n\n[lib]\npath = "lib.rs"\n\n[dependencies]\na = { path = "../a" }\nb = { path = "../b" }\n%s\n' "${3:-}" > "$dir/fuzz/Cargo.toml"
  : > "$dir/fuzz/lib.rs"
  printf '%s' "$2" > "$dir/fuzz/Cargo.lock"
}

# current NAME EXPECTED_EXIT FRAGMENT DIR: run the current check on DIR.
current() {
  local name="$1" want="$2" fragment="$3" dir="$4"
  local out status
  out="$("$CHECK" --current "$dir" 2>&1)"
  status=$?
  if [ "$status" -eq "$want" ] && grep -qF -- "$fragment" <<<"$out"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment', got exit $status:" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

HEADER='# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4
'
CURRENT="$HEADER
[[package]]
name = \"a\"
version = \"0.1.0\"

[[package]]
name = \"b\"
version = \"0.1.0\"

[[package]]
name = \"f\"
version = \"0.1.0\"
dependencies = [
 \"a\",
 \"b\",
]
"
STALE="$HEADER
[[package]]
name = \"a\"
version = \"0.1.0\"
dependencies = [
 \"b\",
]

[[package]]
name = \"b\"
version = \"0.1.0\"

[[package]]
name = \"f\"
version = \"0.1.0\"
dependencies = [
 \"a\",
 \"b\",
]
"

repo "$WORK/current" "$CURRENT"
current "a lock file cargo writes again passes" 0 "is what cargo writes for its manifest (3 packages)" "$WORK/current"
repo "$WORK/stale" "$STALE"
current "an edge no manifest makes is refused by package" 1 "a 0.1.0: an edge to b that its manifest does not make" "$WORK/stale"
current "the refusal of a stale edge says how to bring the file back" 1 "(cd fuzz && cargo update --workspace --offline)" "$WORK/stale"
printf '%s' "$STALE" > "$WORK/stale.lock"
if cmp -s "$WORK/stale/fuzz/Cargo.lock" "$WORK/stale.lock"; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: the check wrote the lock file it reads" >&2
fi
repo "$WORK/gone" "$CURRENT
[[package]]
name = \"g\"
version = \"0.1.0\"
"
current "a package no manifest reaches is refused by name" 1 "g 0.1.0: in the lock file, and reached by no manifest" "$WORK/gone"
repo "$WORK/missing" "$HEADER
[[package]]
name = \"a\"
version = \"0.1.0\"

[[package]]
name = \"f\"
version = \"0.1.0\"
dependencies = [
 \"a\",
]
"
current "a package the manifests reach and the lock lacks is refused" 1 "b 0.1.0: reached by the manifests, and missing from the lock file" "$WORK/missing"
# A registry dependency the local index cache cannot hold (no crate of that
# name is published) stands for a cold cache: the offline update has no
# index entry to read, as it has none for any crate on a fresh runner.
repo "$WORK/cold" "$CURRENT" 'axess-fuzz-lock-case-unpublished = "1"'
current "an update that cannot run on a cold cache is no pass" 3 "not checked, and so not passed" "$WORK/cold"
current "the cold cache is named as the reason" 3 "fill the cache" "$WORK/cold"
current "a root with no fuzz lock is refused" 1 "no file at" "$WORK/absent"

echo "check-fuzz-lock crafted cases: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
