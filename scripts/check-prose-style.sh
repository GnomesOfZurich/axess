#!/usr/bin/env bash
# axess: keep the conventions of the repository's prose and comments.
#
# A convention with no enforcement does not stay held, so each one the
# house style keeps is a rule here.
#
# Em dashes. The house style elaborates with a colon and joins clauses with
# a semicolon, both of which survive `grep`, terminal rendering, and a
# reader copying a line into a commit message. An em dash also renders
# inconsistently in the places this prose actually travels. Checked on
# every line.
#
# Comments say what holds. A regression marker (the word, then a colon)
# tells the history of a change, which belongs to the commit that made it,
# and a citation of a source line by its number (a Rust, shell or Python
# file's name, then a colon or `#L` and the line) is wrong as soon as a
# line above it moves: name the function or the module instead. Checked in comments only (scripts/lib/comment_text.py): in the
# comments of Rust, shell and Python files, the Python a shell script hands
# to `python3` included, and on every line of the Markdown, TOML and YAML.
# A string literal is data, and the crafted cases of a gate hold such text
# as the output they expect.
#
# Read: the files git lists, tracked or untracked and not ignored, so a file
# not yet added is checked as well. Em dashes in Rust, Markdown, TOML,
# shell and YAML; the comment rules in those and in Python. Exempt:
# `docs/book/` (generated), and `*/migrations/*`: an applied migration's
# bytes are its checksum, so its prose is frozen whatever it says.
#
# Usage: ./scripts/check-prose-style.sh
#   scripts/check-prose-style-tests.sh holds the crafted cases.

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR" || exit 1

python3 -I - "$AXESS_DIR" <<'PY'
import os, re, subprocess, sys

os.chdir(sys.argv[1])
sys.path.insert(0, os.path.join(sys.argv[1], "scripts", "lib"))
import comment_text

listed = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--deduplicate", "-z"],
    capture_output=True, text=True, check=True,
).stdout.split("\0")

EXTS = (".rs", ".md", ".toml", ".sh", ".yml", ".yaml")
COMMENT_EXTS = EXTS + (".py",)

def exempt(path):
    return path.startswith("docs/book/") or "/migrations/" in path

# Built with `chr` rather than written out, because this file is itself
# scanned and a gate that contains the thing it bans fails on itself.
#
# Em dashes only. En dashes are left alone: the repository uses them for
# numeric ranges (`43-128 chars`, `6-24h`), which is what they are for, and
# banning those would be a different, worse convention.
BANNED = {
    chr(0x2014): ("em dash", "a colon to elaborate, a semicolon to join clauses"),
}

# Any case, any spacing before the colon: the marker is the word as a label.
# A line citation is a source file's name, a colon or `#L`, and a number.
COMMENT_RULES = (
    (re.compile(r"\bregression\s*:", re.IGNORECASE),
     "regression marker", "a sentence saying what the code does and why"),
    (re.compile(r"\.(?:rs|sh|py)(?::|#L)[0-9]"),
     "line-number citation", "the function or the module by name"),
)

hits = []
read = 0
for path in listed:
    if not path or exempt(path) or not path.endswith(COMMENT_EXTS):
        continue
    try:
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    read += 1
    if path.endswith(EXTS):
        for n, line in enumerate(text.split("\n"), 1):
            for ch, (name, fix) in BANNED.items():
                if ch in line:
                    hits.append((path, n, name, fix, line.strip()[:96]))
    for n, comment in comment_text.comments(path, text):
        for pattern, name, fix in COMMENT_RULES:
            if pattern.search(comment):
                hits.append((path, n, name, fix, comment.strip()[:96]))

if read == 0:
    print("ERROR: no file read; the listing came back empty.", file=sys.stderr)
    sys.exit(1)

if hits:
    print(f"ERROR: {len(hits)} line(s) break the prose rules:\n", file=sys.stderr)
    for path, n, name, fix, text in hits[:40]:
        print(f"  {path}:{n}  ({name}; use {fix})", file=sys.stderr)
        print(f"      {text}", file=sys.stderr)
    if len(hits) > 40:
        print(f"  ... and {len(hits) - 40} more", file=sys.stderr)
    sys.exit(1)

print(f"OK: no banned punctuation in the prose and no regression marker or line-number citation in the comments of {read} files git lists.")
PY
