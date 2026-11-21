#!/usr/bin/env bash
# axess: the changelog keeps its form, from the 0.20.0 section on.
#
# An adopter reads CHANGELOG.md before an upgrade, entry by entry. The
# sections up to 0.19.0 grew entries of several sentences, the same heading
# twice in one release, and paragraphs between entries; the 0.20.0 section
# was folded to one sentence an entry, and nothing kept it so. This check
# does. A section it holds is `## [Unreleased]` and every `## [X.Y.Z]` at or
# above HELD_FROM; the sections below are history and are left as written.
#
# In a held section:
#   - a `### ` heading is one of HEADINGS, and stands once;
#   - every other line that is not blank is one entry: it starts with `- `,
#     stands under a heading, and is whole on its line, so a wrapped entry, a
#     nested list and a paragraph are refused;
#   - an entry is one sentence: it ends with a full stop, and outside its
#     code spans no `.`, `!` or `?` is followed by a space and then a capital
#     letter or a code span (`e.g.` and `i.e.` end no sentence and are passed
#     over; any other abbreviation is written out);
#   - an entry is MAX_CHARS characters at most, the `- ` not counted;
#   - an entry stands once in its section;
#   - an entry names no tracker row, seat or person. A tracker row is two to
#     four capitals, a hyphen and two to four digits, unless the capitals are
#     in STANDARDS (`SHA-256`, `RFC-9449`). A seat, package or ruling label
#     is a capital and one or two digits, read outside code spans. A person
#     is an author this repository records: each name in the `authors` of
#     Cargo.toml's [workspace.package] and each author name of a commit, as a
#     whole name. The names are read from there, so this file holds none.
#
# What it does not see: a name no commit or manifest records, an id of
# another shape, and whether an entry is true. A clone that holds one commit
# gives one author; the manifest's names are read whatever the clone holds.
#
# Usage: ./scripts/check-changelog.sh [--root DIR]
#   --root DIR  check DIR/CHANGELOG.md, with DIR/Cargo.toml and the commits
#               of DIR when it is a git work tree (the crafted cases,
#               scripts/check-changelog-tests.sh, use it)
#
# Exit 0 with one OK line, or exit 1 with every refusal on stderr.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --root)
      [ $# -ge 2 ] || { echo "ERROR: --root needs a value" >&2; exit 2; }
      ROOT="$2"; shift 2 ;;
    -h|--help) sed -n -- '/^# Usage:/,/^#  *scripts\/check-changelog-tests/p' "$0"; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ ! -f "$ROOT/CHANGELOG.md" ]; then
  echo "ERROR: $ROOT/CHANGELOG.md not found" >&2
  exit 1
fi

# The commit authors, one a line; nothing when ROOT is not a work tree of
# its own. `--show-toplevel` is compared so that a crafted root inside this
# checkout does not read this checkout's history.
authors=""
top="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null || true)"
if [ -n "$top" ] && [ "$(cd "$top" && pwd -P)" = "$(cd "$ROOT" && pwd -P)" ]; then
  authors="$(git -C "$ROOT" log --format=%an 2>/dev/null | sort -u || true)"
fi

AUTHORS="$authors" python3 - "$ROOT" <<'PY'
import os, re, sys

ROOT = sys.argv[1]
HELD_FROM = (0, 20, 0)
MAX_CHARS = 300
HEADINGS = ("Upgrade", "Security", "Changed (breaking)", "Removed", "Added", "Fixed", "Changed", "Dependencies")
# Names of standards and algorithms that are written with a hyphen and a number.
STANDARDS = ("AES", "CVE", "CWE", "FIPS", "GHSA", "ISO", "RFC", "RSA", "SHA", "UTF")

CODE_SPAN = re.compile(r"`[^`]*`")
SENTENCE_END = re.compile(r"[.!?][)\]\"']*\s+(?=[A-Z`])")
NO_SENTENCE_END = re.compile(r"\b(e\.g|i\.e)\.")
TRACKER_ROW = re.compile(r"\b([A-Z]{2,4})-[0-9]{2,4}\b")
LABEL = re.compile(r"\b[A-Z][0-9]{1,2}\b")


def recorded_names():
    """The authors the repository records: the manifest's and the commits'."""
    names = set()
    try:
        manifest = open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8").read()
    except OSError:
        manifest = ""
    package = re.search(r"^\[workspace\.package\]$(.*?)(?=^\[|\Z)", manifest, re.M | re.S)
    listed = re.search(r"^authors\s*=\s*\[(.*?)\]", package.group(1), re.M | re.S) if package else None
    if listed:
        for name in re.findall(r'"([^"]*)"', listed.group(1)):
            names.add(re.sub(r"\s*<[^>]*>", "", name).strip())
    for name in os.environ.get("AUTHORS", "").split("\n"):
        names.add(name.strip())
    # A bot's name is not a person's, and a name with no letter names nobody.
    return sorted(n for n in names if re.search(r"[A-Za-z]", n) and "[bot]" not in n)


def held(heading):
    """Whether a `## [...]` heading opens a section this check holds."""
    name = re.match(r"^## \[([^\]]+)\]", heading)
    if not name:
        return False
    if name.group(1) == "Unreleased":
        return True
    version = re.match(r"^(\d+)\.(\d+)\.(\d+)", name.group(1))
    return bool(version) and tuple(int(part) for part in version.groups()) >= HELD_FROM


def entry_faults(text, names):
    """Every way one entry (the text after `- `) leaves the form."""
    faults = []
    if text.count("`") % 2:
        faults.append("a code span is not closed, so the entry cannot be read")
        return faults
    prose = CODE_SPAN.sub("`", text)
    if len(text) > MAX_CHARS:
        faults.append(f"{len(text)} characters, more than {MAX_CHARS}: split it, one change an entry")
    if not prose.rstrip().endswith("."):
        faults.append("does not end with a full stop")
    if SENTENCE_END.search(NO_SENTENCE_END.sub(r"\1", prose)):
        faults.append("more than one sentence: one sentence an entry (write an abbreviation out)")
    for row in TRACKER_ROW.finditer(text):
        if row.group(1) not in STANDARDS:
            faults.append(f"names a tracker row, '{row.group(0)}'")
    for label in LABEL.finditer(CODE_SPAN.sub(" ", text)):
        faults.append(f"names a seat, package or ruling, '{label.group(0)}'")
    for name in names:
        if re.search(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])", text, re.I):
            faults.append(f"names an author this repository records, '{name}'")
    return faults


def check(lines, names):
    """The refusals of a changelog, as (line number, text), and what was held."""
    refusals, sections, entries = [], 0, 0
    holding, heading, seen_headings, seen_entries, fence = False, None, set(), set(), False
    for number, line in enumerate(lines, 1):
        if line.startswith("```"):
            fence = not fence
        if not fence and line.startswith("## "):
            holding = held(line)
            sections += holding
            heading, seen_headings, seen_entries = None, set(), set()
            continue
        if not holding or not line.strip():
            continue
        if line.startswith("### "):
            heading = line[4:].strip()
            if heading not in HEADINGS:
                refusals.append((number, f"the heading '{heading}' is not one of: {', '.join(HEADINGS)}"))
            if heading in seen_headings:
                refusals.append((number, f"the heading '{heading}' stands twice in its section"))
            seen_headings.add(heading)
            continue
        if not line.startswith("- "):
            refusals.append((number, "not an entry: every line of a section is a heading or one whole entry that starts with '- '"))
            continue
        entries += 1
        text = line[2:]
        if heading is None:
            refusals.append((number, "an entry stands under no '### ' heading"))
        if text in seen_entries:
            refusals.append((number, "the entry stands twice in its section"))
        seen_entries.add(text)
        refusals.extend((number, fault) for fault in entry_faults(text, names))
    return refusals, sections, entries


def main():
    try:
        lines = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read().split("\n")
    except (OSError, UnicodeDecodeError) as error:
        print(f"ERROR: CHANGELOG.md was not read: {error}", file=sys.stderr)
        return 1
    refusals, sections, entries = check(lines, recorded_names())
    for number, fault in refusals:
        print(f"REFUSED: CHANGELOG.md line {number}: {fault}", file=sys.stderr)
    if refusals:
        print(f"ERROR: the changelog check failed with {len(refusals)} refusal(s).", file=sys.stderr)
        return 1
    floor = ".".join(str(part) for part in HELD_FROM)
    print(f"OK: {entries} entries in {sections} changelog section(s) from {floor} on, each in form.")
    return 0


sys.exit(main())
PY
