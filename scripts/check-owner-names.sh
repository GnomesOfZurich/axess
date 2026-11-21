#!/usr/bin/env bash
# axess: no name of the publishing company in the repository's text.
#
# This is a public repository. Its tests, examples, doc examples, book,
# scripts and workflows use neutral sample data (the RFC 2606 domains
# example.org, example.com and example.net, a tenant called `acme`, a client
# called `example-api`): a company's name in a fixture reads as the company's
# own deployment, and an adopter who copies a doc example copies it too. The
# publisher is named only where the text names the publisher: the
# repository's address, the published book's address, the crates' `authors`,
# the licences' copyright holder, the published security and conduct
# contacts, and the user agent crates.io asks of the release workflow.
#
# The construction: every text file git lists (tracked, and untracked but
# not ignored, so a file not yet added is read) is read whatever its
# extension; a binary file is skipped by git's own judgement (`git grep -I`,
# which honours the `binary` attribute of .gitattributes), never by a list
# of extensions. Each name of scripts/owner-name-exemptions.txt is searched
# for without regard to case, as a substring, so it is found inside a
# domain, a path, a slug or a password. On a line that holds one, the
# patterns of every exemption whose path matches the file are cut out of
# the line first; a name that is still there is refused, by file and line.
# An exemption therefore covers only the text its pattern spells, on the
# paths its glob names: a second, unexempted use on the same line is still
# refused. A path that holds a name is refused as well.
#
# The exemption list is explicit: each entry is a path glob and a pattern,
# under a comment that gives its reason. An entry with no reason above it,
# and an entry that exempts nothing, are refused, so the list says why each
# entry exists and holds no entry that outlived its line. The list itself
# is the one file not read: it spells the names it searches for. This
# script spells none.
#
# It refuses to report clean when it read no text file.
#
# Usage: ./scripts/check-owner-names.sh
#
# Exit 0 with one ok line; exit 1 with every refusal on stdout; exit 2 when
# the exemption list cannot be read as written.

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIST=scripts/owner-name-exemptions.txt
cd "$AXESS_DIR"
[ $# -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
[ -f "$LIST" ] || { echo "ERROR: $LIST is missing" >&2; exit 2; }

work="$(mktemp -d "${TMPDIR:-/tmp}/axess-owner-names.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# Every listed path, and the text files among them (a file that matches the
# empty pattern has a line to read; an empty file has nothing to hold).
git ls-files -z --cached --others --exclude-standard --deduplicate > "$work/paths"
git grep -z -I -l --untracked -e '' > "$work/text" || true

python3 -I -B - "$LIST" "$work" <<'PY'
import fnmatch
import os
import re
import subprocess
import sys

list_path, work = sys.argv[1], sys.argv[2]


def fail_list(no, why):
    print(f"ERROR: {list_path}:{no}: {why}", file=sys.stderr)
    sys.exit(2)


names = []
exemptions = []  # [line, glob, pattern, used]
reason = False
with open(list_path, encoding="utf-8") as f:
    for no, raw in enumerate(f, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            reason = False
            continue
        if line.startswith("#"):
            reason = True
            continue
        fields = line.split("\t")
        if fields[0] == "name" and len(fields) == 2 and fields[1]:
            names.append(fields[1].lower())
        elif fields[0] == "allow" and len(fields) == 3 and fields[1] and fields[2]:
            if not reason:
                fail_list(no, "an exemption with no comment above it that gives its reason")
            try:
                pattern = re.compile(fields[2])
            except re.error as e:
                fail_list(no, f"the pattern does not compile: {e}")
            exemptions.append([no, fields[1], pattern, False])
        else:
            fail_list(no, "a line is a comment, `name<TAB>NAME` or `allow<TAB>GLOB<TAB>PATTERN`")
if not names:
    fail_list(0, "no `name` line: nothing to search for")


def read0(path):
    with open(path, "rb") as f:
        return [p.decode("utf-8", "surrogateescape") for p in f.read().split(b"\0") if p]


paths = read0(os.path.join(work, "paths"))
text = [p for p in read0(os.path.join(work, "text")) if p != list_path]
if not text:
    print("ERROR: no text file read", file=sys.stderr)
    sys.exit(1)

refused = []
for p in paths:
    if any(n in p.lower() for n in names):
        refused.append(f"{p}: the path names the owner")

grep = ["git", "grep", "-z", "-I", "-n", "-i", "--untracked", "-F"]
for n in names:
    grep += ["-e", n]
out = subprocess.run(grep, capture_output=True, check=False)
if out.returncode not in (0, 1):
    sys.stderr.write(out.stderr.decode("utf-8", "replace"))
    sys.exit(1)

for record in out.stdout.decode("utf-8", "surrogateescape").split("\n"):
    if not record:
        continue
    path, no, line = record.split("\0", 2)
    if path == list_path:
        continue
    rest = line
    for entry in exemptions:
        if fnmatch.fnmatchcase(path, entry[1]):
            cut = entry[2].sub("", rest)
            if cut != rest:
                entry[3] = True
                rest = cut
    if any(n in rest.lower() for n in names):
        shown = line.strip()
        if len(shown) > 160:
            shown = shown[:160] + "..."
        refused.append(f"{path}:{no}: {shown}")

for no, glob, pattern, used in exemptions:
    if not used:
        refused.append(f"{list_path}:{no}: an exemption that exempts nothing ({glob}: {pattern.pattern})")

if refused:
    for r in refused:
        print(r)
    files = {r.split(":", 1)[0] for r in refused}
    print(f"{len(refused)} line(s) refused in {len(files)} file(s): the owner's name outside {list_path}")
    sys.exit(1)
print(f"ok: no owner name outside the exemption list in {len(text)} text file(s) read")
PY
