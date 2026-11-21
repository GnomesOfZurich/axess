#!/usr/bin/env bash
# axess: no name in Rust code starts with an underscore.
#
# The repository's rule (AGENTS.md, "No lint suppressions") is that an
# unused name is not hidden from the compiler behind a `_` prefix. A
# parameter a trait fixes and the implementation does not read is taken as
# a bare `_`; a guard held for its Drop is a plain name, dropped where what
# it guards must end; anything else unused is removed. In a trait's own
# declaration a parameter keeps its plain name, and a default body that
# reads none of them says so in one line (`let _ = (a, b);`).
#
# The construction: comments are dropped and string, raw string and char
# literals blanked first (scripts/lib/rust_source.py), so text there is not
# code. In what remains, every identifier that starts with one underscore
# followed by a letter or a digit is refused, by file, line and name, in
# whatever position it stands: a parameter, a field, a `let` (with `mut` or
# `ref` or none), a closure parameter, a pattern of a tuple, a struct, a
# variant or a match arm, a `for` binding, a macro's metavariable. A name is
# an identifier wherever it stands, so the rule holds for every form the
# language gives a binding, not a list of the forms seen so far. What is
# not refused: the bare `_`, an identifier that starts with two
# underscores (a macro's support items, `__private`), an underscore inside
# a number (`1_000`), a lifetime (`'_`, `'_a`), and text in a comment or a
# string.
#
# The Rust code of a doc example is code: rustdoc compiles it, and an
# adopter copies it. Its lines are read the same way, by the file line they
# stand on (scripts/lib/lint_allowances.py finds the examples). Prose in a
# doc comment is not read.
#
# There is no allowlist. It refuses to report clean when it read no Rust
# file.
#
# Usage: ./scripts/check-underscore-names.sh [--root DIR]
#   --root DIR  check the files under DIR instead of the files git lists in
#               this repository (scripts/check-underscore-names-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$2"
  files() { find . -type f -name '*.rs' | sed 's|^\./||' | sort; }
else
  [ $# -eq 0 ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not
  # yet added is checked as well.
  files() { git ls-files --cached --others --exclude-standard --deduplicate -- '*.rs'; }
fi

listed="$(files)"
python3 -I -B -c '
import os, re, sys

sys.path.insert(0, sys.argv[1])
from rust_source import blanked_lines
from lint_allowances import doc_code, doc_runs

# One underscore, then a letter or a digit, at the start of an identifier:
# not after an identifier character (`a_b`, `1_000`, `__x`) and not after a
# quote (a lifetime such as `\x27_a`).
NAME = re.compile(r"(?<![A-Za-z0-9_\x27])_[A-Za-z0-9][A-Za-z0-9_]*")


def names(lines):
    """(line, name) for each underscore-prefixed name in (line, code) pairs."""
    out = []
    for no, code in lines:
        out.extend((no, m.group(0)) for m in NAME.finditer(code))
    return out


def file_names(text):
    found = names(enumerate(blanked_lines(text), 1))
    for run in doc_runs(text):
        code = doc_code(run)
        if not code:
            continue
        numbers = [no for no, _ in code]
        blanked = blanked_lines("\n".join(c for _, c in code))
        found.extend((no, name + " (in a doc example)") for no, name in names(zip(numbers, blanked)))
    return sorted(set(found))


refused = []
files = 0
paths = [p for p in sys.stdin.read().split("\n") if p.endswith(".rs") and os.path.isfile(p)]
for path in paths:
    files += 1
    with open(path, encoding="utf-8") as f:
        text = f.read()
    refused.extend(f"{path}:{no}: {name}" for no, name in file_names(text))
if files == 0:
    print("ERROR: no Rust file read; nothing was checked.", file=sys.stderr)
    sys.exit(1)
if refused:
    for line in refused:
        print(line, file=sys.stderr)
    named = len({r.split(":", 1)[0] for r in refused})
    print(
        f"{len(refused)} underscore-prefixed name(s) refused in {named} file(s): a parameter a trait "
        "fixes is `_`, a held guard is a plain name dropped where it must end, anything else unused "
        "is removed; see the header of scripts/check-underscore-names.sh.",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"ok: no underscore-prefixed name in {files} Rust file(s) and their doc examples")
' "$LIB" <<<"$listed"
