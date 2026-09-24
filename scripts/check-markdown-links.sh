#!/usr/bin/env bash
# axess: resolve the links the Markdown writes against the tree they point at.
#
# `check-doc-links.sh` runs rustdoc and covers intra-doc links in Rust source.
# Nothing covered Markdown, and Markdown is what an adopter reads first: the
# crates.io front page is a README, and every crate README links into the book.
#
# The gap this closes was live. `axess-events/README.md` linked to
# `docs/audit-pipeline.md` through an absolute github.com/blob/main URL. The
# chapter had moved to `docs/production/audit-pipeline.md`, so the link on
# crates.io 404'd, and no gate noticed for the obvious reason: a relative-path
# checker skips absolute URLs, and a link checker that fetches URLs is a
# network dependency nobody wants in CI. The trick is that a github.com link
# into *this* repository is a repository path wearing a URL, so it can be
# resolved offline against the working tree like any other.
#
# Checked:
#   - relative links to repo files, with any `#fragment` stripped
#   - absolute https://github.com/GnomesOfZurich/axess/{blob,tree}/<ref>/<path>
#
# Not checked: links to other hosts, and `mailto:`. Fetching them would make
# this gate fail on a flaky network, which is how link checkers get disabled.
#
# Usage: ./scripts/check-markdown-links.sh

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

python3 - "$AXESS_DIR" <<'PY'
import os, re, subprocess, sys

root = sys.argv[1]
os.chdir(root)

# Tracked files only: `docs/book/` is generated output, and a packaged copy
# under target/ would contribute phantom hits.
tracked = subprocess.run(
    ["git", "ls-files", "-z", "*.md"],
    capture_output=True, text=True, check=True,
).stdout.split("\0")
files = [f for f in tracked if f and not f.startswith("docs/book/")]

LINK = re.compile(r"\[[^\]]*\]\(\s*<?([^)\s>]+)>?\s*(?:\"[^\"]*\")?\)")
SELF = re.compile(
    r"^https://github\.com/GnomesOfZurich/axess/(?:blob|tree)/[^/]+/(.+)$"
)
SKIP = ("http://", "https://", "mailto:", "#")

broken = []
for path in files:
    base = os.path.dirname(path)
    try:
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    # Strip fenced code blocks: a link inside an example is illustrative.
    text = re.sub(r"^```.*?^```", "", text, flags=re.S | re.M)

    for target in LINK.findall(text):
        m = SELF.match(target)
        if m:
            # A link into this repository, resolved against the tree.
            candidate, kind = m.group(1).split("#", 1)[0], "repo URL"
        elif target.startswith(SKIP):
            continue
        else:
            candidate, kind = os.path.normpath(
                os.path.join(base, target.split("#", 1)[0])
            ), "relative link"
        if not candidate:
            continue
        if not os.path.exists(candidate):
            broken.append((path, target, candidate, kind))

if broken:
    print(
        f"ERROR: {len(broken)} Markdown link(s) point at files that do not exist:\n",
        file=sys.stderr,
    )
    for path, target, candidate, kind in broken:
        print(f"  {path}", file=sys.stderr)
        print(f"      {kind}: {target}", file=sys.stderr)
        print(f"      resolves to: {candidate}", file=sys.stderr)
    print(
        "\nEither the path is wrong (fix the link) or the file moved and the "
        "link did not follow it. A crates.io README is the first thing an "
        "adopter reads; a 404 there is the first thing they learn.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"OK: {len(files)} Markdown files, all repo links resolve.")
PY
