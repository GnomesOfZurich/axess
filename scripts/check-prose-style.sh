#!/usr/bin/env bash
# axess: keep the typographic conventions the 0.6.0 language pass established.
#
# That pass removed every em dash from the repository. Nothing then preserved
# the result: the rule lived in a commit message and in nobody's memory, and a
# later documentation sweep reintroduced 101 of them across nineteen files
# without a single gate noticing. A convention with no enforcement is a
# convention with a half-life.
#
# Why em dashes specifically: the house style elaborates with a colon and
# joins clauses with a semicolon, both of which survive `grep`, terminal
# rendering, and a reader copying a line into a commit message. An em dash
# also renders inconsistently in the places this prose actually travels.
#
# Checked in tracked text: Rust, Markdown, TOML, shell, YAML.
# Exempt: `docs/book/` (generated), and `*/migrations/*`: an applied
# migration's bytes are its checksum, so its prose is frozen whatever it says.
#
# Usage: ./scripts/check-prose-style.sh

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

python3 - "$AXESS_DIR" <<'PY'
import os, subprocess, sys

os.chdir(sys.argv[1])

tracked = subprocess.run(
    ["git", "ls-files", "-z"], capture_output=True, text=True, check=True
).stdout.split("\0")

EXTS = (".rs", ".md", ".toml", ".sh", ".yml", ".yaml")

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

hits = []
for path in tracked:
    if not path or exempt(path) or not path.endswith(EXTS):
        continue
    try:
        lines = open(path, encoding="utf-8").read().split("\n")
    except (OSError, UnicodeDecodeError):
        continue
    for n, line in enumerate(lines, 1):
        for ch, (name, fix) in BANNED.items():
            if ch in line:
                hits.append((path, n, name, fix, line.strip()[:96]))

if hits:
    print(f"ERROR: {len(hits)} line(s) use punctuation the house style drops:\n",
          file=sys.stderr)
    for path, n, name, fix, text in hits[:40]:
        print(f"  {path}:{n}  ({name}; use {fix})", file=sys.stderr)
        print(f"      {text}", file=sys.stderr)
    if len(hits) > 40:
        print(f"  ... and {len(hits) - 40} more", file=sys.stderr)
    sys.exit(1)

print("OK: no banned punctuation in tracked prose.")
PY
