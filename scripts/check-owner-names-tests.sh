#!/usr/bin/env bash
# axess: crafted cases for scripts/check-owner-names.sh.
#
# Each case builds a git work tree of its own that holds a copy of the
# check, an exemption list and the files the case names, runs the check
# there as it runs on the repository, and asserts the exit status and a
# fragment of the output. The refusals are the contract: the owner's name
# in a Rust test, a README, an HTML page, a file of any extension, a path,
# an untracked file and in any case of letters is refused, by file and
# line; an exemption covers its pattern on its paths and nothing else; an
# exemption with no reason, or one that exempts nothing, is refused. Then
# the repository's own list is held to the lines it exists for: those lines
# pass under it, and each entry taken away alone makes the check refuse.
#
# The name is read from the list, so this file spells none.
#
# Usage: ./scripts/check-owner-names-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CHECK="$SCRIPT_DIR/check-owner-names.sh"
REAL_LIST="$SCRIPT_DIR/owner-name-exemptions.txt"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-owner-names.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

name="$(awk -F'\t' '$1 == "name" { print $2 }' "$REAL_LIST")"
[ -n "$name" ] && [ "$(printf '%s\n' "$name" | wc -l | tr -d ' ')" = 1 ] \
  || { echo "ERROR: $REAL_LIST holds no single name line" >&2; exit 1; }
Name="$(awk -v s="$name" 'BEGIN { print toupper(substr(s, 1, 1)) substr(s, 2) }')"
NAME="$(awk -v s="$name" 'BEGIN { print toupper(s) }')"
TAB="$(printf '\t')"

# A list with the name and no exemption.
BARE="name${TAB}${name}"

# tree DIR LIST [FILE CONTENT...]: a git work tree with the check, LIST as
# its exemption list and the FILEs. A FILE written `+path` is written after
# the index is filled, so it is untracked; a .gitignore ignores `ignored.*`.
tree() {
  local dir="$1" list="$2"
  shift 2
  mkdir -p "$dir/scripts"
  cp "$CHECK" "$dir/scripts/check-owner-names.sh"
  printf '%s\n' "$list" > "$dir/scripts/owner-name-exemptions.txt"
  printf 'ignored.*\n' > "$dir/.gitignore"
  git -C "$dir" -c init.defaultBranch=main init -q
  local late=()
  while [ $# -gt 0 ]; do
    case "$1" in
      +*) late+=("${1#+}" "$2") ;;
      *) mkdir -p "$(dirname "$dir/$1")"; printf '%s\n' "$2" > "$dir/$1" ;;
    esac
    shift 2
  done
  git -C "$dir" add -A
  set -- ${late[@]+"${late[@]}"}
  while [ $# -gt 0 ]; do
    mkdir -p "$(dirname "$dir/$1")"
    printf '%s\n' "$2" > "$dir/$1"
    shift 2
  done
}

# case_ NAME EXPECTED_EXIT FRAGMENT [UNWANTED] -- LIST [FILE CONTENT...]
case_() {
  local cname="$1" want="$2" fragment="$3" unwanted=""
  shift 3
  if [ "$1" != "--" ]; then unwanted="$1"; shift; fi
  shift
  local dir="$WORK/tree-$passed-$failed"
  tree "$dir" "$@"
  local out status
  out="$("$dir/scripts/check-owner-names.sh" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$dir"
  judge "$cname" "$want" "$fragment" "$status" "$out" "$unwanted"
}

CLEAN='const TENANT: &str = "acme";'

case_ "a clean tree passes and says how many files it read" 0 \
  "ok: no owner name outside the exemption list in 3 text file(s) read" -- "$BARE" \
  a/src/lib.rs "$CLEAN"
case_ "a tree whose every file is binary by attribute reads no text" 1 "ERROR: no text file read" -- "$BARE" \
  .gitattributes '* binary'

# A hit, wherever it stands.
case_ "a hit in a Rust test is refused" 1 "a/tests/t.rs:2: let tenant = \"$name\";" -- "$BARE" \
  a/tests/t.rs "#[test]
let tenant = \"$name\";"
case_ "the trust domain put back in a workload test is refused" 1 \
  "axess-identity/src/workload/tests.rs:1:" -- "$BARE" \
  axess-identity/src/workload/tests.rs "    let trust = TrustDomain::new(\"$name.local\").unwrap();"
case_ "a hit in a README is refused" 1 "README.md:3:" -- "$BARE" \
  README.md "# Example

Sign in as alice with \`${Name}2+\`."
case_ "a hit in HTML is refused" 1 "examples/x/static/index.html:1:" -- "$BARE" \
  examples/x/static/index.html "<input name=\"tenant\" value=\"$Name\" />"
case_ "a hit in a file of no known extension is refused" 1 "notes.unknownext:1:" -- "$BARE" \
  notes.unknownext "$name"
case_ "a hit in capitals is refused" 1 "a/src/lib.rs:1:" -- "$BARE" \
  a/src/lib.rs "// SPIFFE://$NAME.LOCAL/x"
case_ "a hit inside a word is refused" 1 "a/src/lib.rs:1:" -- "$BARE" \
  a/src/lib.rs "const A: &str = \"https://api.${name}corp/x\";"
case_ "every hit is named and counted" 1 "2 line(s) refused in 2 file(s)" -- "$BARE" \
  a/x.rs "$name" b/y.md "$Name"
case_ "a path that names the owner is refused" 1 "docs/$name-notes.md: the path names the owner" -- "$BARE" \
  "docs/$name-notes.md" "nothing here"
case_ "an untracked file is read" 1 "a/new.rs:1:" -- "$BARE" \
  a/src/lib.rs "$CLEAN" +a/new.rs "$name"
case_ "an ignored file is not read" 0 "ok: no owner name" -- "$BARE" \
  a/src/lib.rs "$CLEAN" +a/ignored.rs "$name"
case_ "a file binary by attribute is not read" 0 "ok: no owner name" -- "$BARE" \
  .gitattributes '*.bin binary' a/blob.bin "$name"

# Exemptions.
CONTACT="name${TAB}${name}
# The published contact.
allow${TAB}SECURITY.md${TAB}\\bsecurity@${name}\\.ch\\b"
case_ "an exemption passes its pattern on its path" 0 "ok: no owner name" -- "$CONTACT" \
  SECURITY.md "Write to security@$name.ch."
case_ "an exemption for one file does not cover another" 1 "README.md:1:" "SECURITY.md:1" -- "$CONTACT" \
  SECURITY.md "Write to security@$name.ch." README.md "Write to security@$name.ch."
case_ "an exemption cuts its pattern and no more of the line" 1 "SECURITY.md:1:" -- "$CONTACT" \
  SECURITY.md "Write to security@$name.ch from spiffe://$name.local/x."
GLOB="name${TAB}${name}
# The copyright holder of every licence file.
allow${TAB}*/LICENSE-MIT${TAB}^Copyright \\(c\\) 2025 ${Name}\$"
case_ "a glob exemption covers each path it matches" 0 "ok: no owner name" -- "$GLOB" \
  a/LICENSE-MIT "Copyright (c) 2025 $Name" b/c/LICENSE-MIT "Copyright (c) 2025 $Name"
case_ "a glob exemption does not cover a path it does not match" 1 "LICENSE-MIT.txt:1:" -- "$GLOB" \
  a/LICENSE-MIT "Copyright (c) 2025 $Name" a/LICENSE-MIT.txt "Copyright (c) 2025 $Name"
case_ "an exemption with no reason above it is refused" 2 "an exemption with no comment above it" -- \
  "name${TAB}${name}
allow${TAB}SECURITY.md${TAB}security@" \
  SECURITY.md "security@$name.ch"
case_ "an exemption that exempts nothing is refused" 1 "an exemption that exempts nothing (README.md: stale)" -- \
  "$CONTACT
# Outlived its line.
allow${TAB}README.md${TAB}stale" \
  SECURITY.md "Write to security@$name.ch."
case_ "a pattern that does not compile is refused" 2 "the pattern does not compile" -- \
  "name${TAB}${name}
# Broken.
allow${TAB}*${TAB}(" \
  a/src/lib.rs "$CLEAN"
case_ "a line of no known form is refused" 2 "a line is a comment" -- \
  "name${TAB}${name}
allow SECURITY.md security@" \
  a/src/lib.rs "$CLEAN"
case_ "a list with no name is refused" 2 "no \`name\` line" -- \
  "# Nothing to search for." \
  a/src/lib.rs "$CLEAN"

# The repository's own list, against the lines it exists for: every line of
# the repository that holds the name, each written to the same path.
real_lines() {
  local dir="$1"
  (cd "$AXESS_DIR" && git grep -z -I -n -i -F -e "$name" -- . ':!scripts/owner-name-exemptions.txt') \
    > "$WORK/hits"
  python3 -I -B -c '
import os, sys
out = {}
for rec in open(sys.argv[2], "rb").read().decode("utf-8", "surrogateescape").split("\n"):
    if rec:
        path, _, line = rec.split("\0", 2)
        out.setdefault(path, []).append(line)
for path, lines in out.items():
    full = os.path.join(sys.argv[1], path)
    os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
    with open(full, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(lines) + "\n")
' "$dir" "$WORK/hits"
}

list_case() {
  local cname="$1" want="$2" fragment="$3" list="$4"
  local dir="$WORK/real-$passed-$failed"
  tree "$dir" "$list"
  real_lines "$dir"
  local out status
  out="$("$dir/scripts/check-owner-names.sh" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$dir"
  judge "$cname" "$want" "$fragment" "$status" "$out"
}

real="$(cat "$REAL_LIST")"
list_case "the repository's exempted lines pass under its list" 0 "ok: no owner name" "$real"
entries="$(grep -c "^allow${TAB}" "$REAL_LIST")"
for i in $(seq 1 "$entries"); do
  without="$(awk -F'\t' -v n="$i" '$1 == "allow" && ++k == n { next } { print }' "$REAL_LIST")"
  entry="$(awk -F'\t' -v n="$i" '$1 == "allow" && ++k == n { print $2 " " $3 }' "$REAL_LIST")"
  list_case "without the entry for $entry the check refuses" 1 "line(s) refused" "$without"
done

echo "check-owner-names tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
