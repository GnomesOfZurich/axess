#!/usr/bin/env bash
# axess: every `#[ignore]` says why the test is ignored.
#
# A test marked `#[ignore]` is left out of `cargo test` and run only by
# `cargo test -- --ignored`, which scripts/check-live-stores.sh does for the
# whole workspace against every live server. The reason is what a reader has
# when the test is listed as `ignored`: which server it needs
# (`requires a running Postgres (POSTGRES_URL)`), or why it is run by hand.
# A bare `#[ignore]` says neither, and a test nobody can place is a test
# nobody starts a server for.
#
# This fails on an ignore attribute without a reason in any Rust file git
# lists (tracked, or untracked and not ignored): `#[ignore]`, a reason that
# is empty or holds no letter, and the same inside
# `#[cfg_attr(..., ignore)]`. A reason is judged as the string it
# is, not as it is written: an escape (`\n`, `\x20`, `\u{2e}`) counts as
# the character it stands for, so a reason made of escapes for blanks and
# punctuation holds no letter. A raw string is taken as written. Comments, doc comments (a fenced
# ```rust,ignore example is not an attribute) and string literals are not
# code (scripts/lib/rust_source.py). It refuses to report clean when it read
# no file.
#
# Usage: ./scripts/check-ignore-reasons.sh [--root DIR]
#   --root DIR  check the Rust files under DIR instead of this repository's
#               files (scripts/check-ignore-reasons-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$2"
  files() { find . -name '*.rs' -type f | sed 's|^\./||' | sort; }
else
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not
  # yet added is checked as well.
  files() { git ls-files --cached --others --exclude-standard --deduplicate '*.rs'; }
fi

listed="$(files)"
python3 -I -B -c '
import re, sys

sys.path.insert(0, sys.argv[1])
from rust_source import blanked_lines

# What stands for a string literal once the code is read: REASON for one
# with a letter in it, EMPTY for one without.
REASON, EMPTY = "\"reason\"", "\"\""


# An escape in a string literal: a byte, a code point, a line continuation
# (the line break and the blanks after it), or one character.
ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f_]{1,8})\}|(\r?\n\s*)|(.))", re.S)
NAMED = {"n": "\n", "r": "\r", "t": "\t", "0": "\0"}


def value(body):
    """The string a literal with this body is: each escape as what it stands for."""

    def stands_for(m):
        if m.group(1):
            return chr(int(m.group(1), 16))
        if m.group(2):
            try:
                return chr(int(m.group(2).replace("_", ""), 16))
            except (ValueError, OverflowError):
                return ""
        if m.group(3):
            return ""
        return NAMED.get(m.group(4), m.group(4))

    return ESCAPE.sub(stands_for, body)


def literal(text):
    opening = text.index("\"")
    body = text[opening + 1 : text.rindex("\"")]
    if "r" not in text[:opening]:
        body = value(body)
    return REASON if re.search(r"[^\W\d_]", body) else EMPTY


def attributes(code):
    """(offset, body) of each attribute in `code`, the body without `#[` and `]`."""
    for m in re.finditer(r"#\s*!?\s*\[", code):
        depth = 0
        for j in range(m.end() - 1, len(code)):
            if code[j] == "[":
                depth += 1
            elif code[j] == "]":
                depth -= 1
                if depth == 0:
                    yield m.start(), code[m.end() : j]
                    break


def parts(body):
    """The comma-separated parts of `body` at its own depth."""
    out, depth, part = [], 0, ""
    for ch in body + ",":
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(part.strip())
            part = ""
        else:
            part += ch
    return [p for p in out if p]


def ignores(body):
    """Each ignore in an attribute body: True with a reason, False without."""
    body = body.strip()
    m = re.fullmatch(r"cfg_attr\s*\((.*)\)", body, re.S)
    if m:
        for inner in parts(m.group(1))[1:]:
            yield from ignores(inner)
    elif re.match(r"ignore\b", body):
        yield re.sub(r"\s+", "", body) == "ignore=" + REASON


files = bad = found = 0
for path in sys.stdin.read().split():
    files += 1
    with open(path, encoding="utf-8") as f:
        code = "\n".join(blanked_lines(f.read(), literal))
    for offset, body in attributes(code):
        for reasoned in ignores(body):
            found += 1
            if not reasoned:
                bad += 1
                line = code.count("\n", 0, offset) + 1
                print(f"{path}:{line}: #[ignore] without a reason", file=sys.stderr)
if files == 0:
    print("ERROR: no Rust file read; nothing was checked.", file=sys.stderr)
    sys.exit(1)
if bad:
    print(
        f"{bad} of {found} ignore attribute(s) give no reason. Write the reason the others "
        "use, for instance #[ignore = \"requires a running Postgres (POSTGRES_URL)\"]; "
        "see the header of scripts/check-ignore-reasons.sh.",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"ok: {found} ignore attribute(s) in {files} file(s), each with a reason")
' "$LIB" <<<"$listed"
