#!/usr/bin/env bash
# axess: compile the book's code blocks against the crates they import.
#
# Builds `axess` with every feature and the minimal example (the
# getting-started chapter includes `examples/minimal/src/main.rs` region by
# region, so that crate compiling is that chapter's code compiling), then
# runs `mdbook test docs` with the directory of every library that build
# made on the crate search path.
#
# The directories are read from cargo's own account of what it built
# (`--message-format=json`, the `filenames` of each artifact), not from a
# folder written here: from Cargo 1.100 the libraries of a build lie under
# <profile>/build/<crate>/<hash>/ in place of the one <profile>/deps/, so a
# fixed folder can leave `mdbook test` nothing to link. Naming
# the directories of this build alone also leaves out a stale copy of a
# crate from an earlier build, which would be a second candidate for one
# `extern crate`.
#
# The CI "Book" job, the Docs workflow and the release preflight run this,
# so the three compile the book the same way.
#
# Usage: ./scripts/book-test.sh [BOOK]   (BOOK defaults to docs; mdbook on
# the path; CARGO_TARGET_DIR is cargo's, as for any build)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
book="$(cd "${1:-$AXESS_DIR/docs}" && pwd)"
cd "$AXESS_DIR"

messages="$(mktemp "${TMPDIR:-/tmp}/book-build.XXXXXX")"
trap 'rm -f -- "$messages"' EXIT

cargo build --quiet -p axess --all-features -p axess-example-minimal --message-format=json > "$messages"

# One directory per line: every directory that holds a library (.rlib,
# .rmeta, or a procedural macro's shared object) cargo names.
dirs="$(python3 -I -B -c '
import json, os, sys
seen = []
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("reason") != "compiler-artifact":
        continue
    for name in msg.get("filenames") or []:
        if name.endswith((".rlib", ".rmeta", ".so", ".dylib", ".dll")):
            d = os.path.dirname(name)
            if d not in seen:
                seen.append(d)
print("\n".join(seen))
' "$messages")"

if [ -z "$dirs" ]; then
  echo "ERROR: cargo named no library it built, so mdbook test would link nothing." >&2
  exit 1
fi
# `mdbook test -L` takes a comma-separated list; a directory whose name holds
# a comma would be read as two.
if grep -q ',' <<<"$dirs"; then
  echo "ERROR: a library directory holds a comma, which mdbook test -L cannot take:" >&2
  grep ',' <<<"$dirs" >&2
  exit 1
fi
count="$(wc -l <<<"$dirs" | tr -d ' ')"
echo "Crate search path: $count director(ies) cargo named for this build."

mdbook test "$book" -L "$(paste -sd, - <<<"$dirs")"

# The count says how many blocks `mdbook test` was given to compile, so a
# pass over none of them cannot read as coverage.
testable=$(find "$book" -name '*.md' -exec grep -hE '^[[:space:]]*```rust' {} + | grep -vc ignore || true)
echo "OK: examples/minimal builds; mdbook test compiled $testable block(s) not marked ignore."
