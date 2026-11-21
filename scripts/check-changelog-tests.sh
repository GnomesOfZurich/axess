#!/usr/bin/env bash
# axess: crafted cases for scripts/check-changelog.sh.
#
# Each case writes a CHANGELOG.md (and, where it names a person, a Cargo.toml
# or a commit) under a temporary root, runs the check with `--root`, and
# asserts the exit status and a fragment of the output.
#
# Usage: ./scripts/check-changelog-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-changelog.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-changelog.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# A manifest whose one author is a neutral name no case's prose holds by
# accident.
MANIFEST='[workspace.package]
version = "1.1.0"
authors = ["Pat Example <pat@example.org>"]

[workspace.dependencies]'

# case_ NAME EXPECTED_EXIT FRAGMENT CHANGELOG_CONTENT: run the check on a
# root that holds the changelog and MANIFEST.
case_() {
  local name="$1" want="$2" fragment="$3" changelog="$4"
  local root="$WORK/case-$passed-$failed"
  mkdir -p "$root"
  printf '%s\n' "$changelog" > "$root/CHANGELOG.md"
  printf '%s\n' "$MANIFEST" > "$root/Cargo.toml"
  local out status
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  judge "$name" "$want" "$fragment" "$status" "$out"
}

# entry_ NAME EXPECTED_EXIT FRAGMENT ENTRY: one entry under `### Added` of a
# held section.
entry_() {
  case_ "$1" "$2" "$3" "# Changelog

## [1.1.0] - 2030-01-02

### Added

- $4"
}

WHOLE='# Changelog

## [Unreleased]

## [1.1.0] - unreleased

### Security

- A session is stored under a digest of its id (`SessionKey`), so a read of the table yields no cookie value.

### Changed (breaking)

- `Store::load` takes a key.

### Removed

- `Store::migrate` is removed.

### Added

- `Store::count` counts rows.

### Fixed

- A rotation keeps its row.

### Changed

- The check reads every script.

### Dependencies

- `sha2` 0.11.0 -> 0.11.1 in the workspace.'

case_ "a section in form passes, every heading once" 0 "OK: 7 entries in 2 changelog section(s)" "$WHOLE"

# --- one sentence an entry ---

entry_ "two sentences are refused" 1 "line 7: more than one sentence" \
  'A store keeps its rows. Another store drops them.'
entry_ "a sentence that begins with a code span is a second sentence" 1 "more than one sentence" \
  'A store keeps its rows. `Store::drop` removes them.'
entry_ "a question and an exclamation end a sentence too" 1 "more than one sentence" \
  'Does a store keep its rows? It does.'
entry_ "a sentence that ends inside a bracket is seen" 1 "more than one sentence" \
  'A store keeps its rows (all of them.) Another drops them.'
entry_ "a full stop inside a code span ends nothing" 0 "OK: 1 entries" \
  'A reader takes `a. B` and `x? Y` as written.'
entry_ "a version and a decimal end nothing" 0 "OK: 1 entries" \
  'The lock moves from 1.2.3 to 1.2.4 and the bound from 0.5 s to 1.5 s.'
entry_ "e.g. and i.e. end nothing" 0 "OK: 1 entries" \
  'A reader takes a tag, e.g. `Reject`, and a bound, i.e. One hour.'
entry_ "an entry without its full stop is refused" 1 "does not end with a full stop" \
  'A store keeps its rows'
entry_ "an unclosed code span is refused" 1 "a code span is not closed" \
  'A store keeps `its rows.'

# --- length ---

exact="$(printf 'a%.0s' $(seq 1 299))."
entry_ "an entry of 300 characters passes" 0 "OK: 1 entries" "$exact"
entry_ "an entry of 301 characters is refused" 1 "301 characters, more than 300" "a$exact"

# --- tracker rows, labels, names ---

entry_ "a tracker row is refused" 1 "names a tracker row, 'AB-123'" \
  'A store keeps its rows, as AB-123 asked.'
entry_ "a tracker row inside a code span is refused" 1 "names a tracker row, 'ABCD-42'" \
  'A store keeps its rows (`ABCD-42`).'
entry_ "standards and advisories are no tracker rows" 0 "OK: 1 entries" \
  'A key is a SHA-256 digest on P-256 under RFC-9449, AES-256 and UTF-8 (RUSTSEC-2026-0459, CVE-2026-1234).'
entry_ "a seat label is refused" 1 "names a seat, package or ruling, 'Z9'" \
  'A store keeps its rows, as Z9 ruled.'
entry_ "a package label of two digits is refused" 1 "names a seat, package or ruling, 'K12'" \
  'A store keeps its rows since K12.'
entry_ "a label inside a code span, and a longer name, pass" 0 "OK: 1 entries" \
  'A pair `Store<T1, T2>` keeps ES256, X25519, E0308 and HTTP/2 apart.'
entry_ "an author of the manifest is refused" 1 "names an author this repository records, 'Pat Example'" \
  'A store keeps its rows, thanks to Pat Example.'
entry_ "an author is refused in any case" 1 "names an author this repository records, 'Pat Example'" \
  'A store keeps its rows (pat example).'
entry_ "half of a name, and a name inside a word, pass" 0 "OK: 1 entries" \
  'A store keeps its rows for Pat and for the Pat Examples of this world.'

# An author of a commit is refused, and a bot's name is not a person's.
# Skipped, and said so, where git cannot make the commits.
root="$WORK/committed"
mkdir -p "$root"
commit_as() {
  GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL=a@example.org \
    GIT_COMMITTER_NAME=committer GIT_COMMITTER_EMAIL=c@example.org \
    git -C "$root" -c commit.gpgsign=false commit -q --allow-empty -m "$2" 2>/dev/null
}
if git init -q "$root" 2>/dev/null && commit_as "Robin Sample" one && commit_as "release-helper[bot]" two; then
  printf '%s\n' '# Changelog' '' '## [1.1.0] - 2030-01-02' '' '### Added' '' \
    '- A store keeps its rows, as Robin Sample found.' > "$root/CHANGELOG.md"
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  judge "an author of a commit is refused" 1 "names an author this repository records, 'Robin Sample'" "$status" "$out"
  printf '%s\n' '# Changelog' '' '## [1.1.0] - 2030-01-02' '' '### Added' '' \
    '- The release-helper[bot] account and a committer push nothing.' > "$root/CHANGELOG.md"
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  judge "a bot and a committer are no authors" 0 "OK: 1 entries" "$status" "$out"
else
  echo "SKIP: an author of a commit is refused (git made no commit under $root)" >&2
fi

# --- the shape of a section ---

case_ "a heading outside the list is refused" 1 "the heading 'Documentation' is not one of" \
'# Changelog

## [1.1.0] - 2030-01-02

### Documentation

- The book has a page.'

case_ "the Upgrade heading is one of the known headings" 0 "OK: 2 entries in 1 changelog section(s)" \
'# Changelog

## [1.1.0] - 2030-01-02

### Upgrade

- Sessions: Upgrade every node together.

### Security

- Sessions: A session is stored under a digest of its id.'

case_ "a heading that stands twice is refused" 1 "line 9: the heading 'Fixed' stands twice" \
'# Changelog

## [1.1.0] - 2030-01-02

### Fixed

- A rotation keeps its row.

### Fixed

- A load keeps its row.'

case_ "an entry wrapped over two lines is refused" 1 "line 8: not an entry" \
'# Changelog

## [1.1.0] - 2030-01-02

### Fixed

- A rotation keeps
  its row.'

case_ "a nested list is refused" 1 "line 8: not an entry" \
'# Changelog

## [1.1.0] - 2030-01-02

### Fixed

- A rotation keeps its row.
  - And its claim.'

case_ "a paragraph in a section is refused" 1 "line 5: not an entry" \
'# Changelog

## [1.1.0] - 2030-01-02

This release is about rows.

### Fixed

- A rotation keeps its row.'

case_ "an entry under no heading is refused" 1 "line 5: an entry stands under no" \
'# Changelog

## [1.1.0] - 2030-01-02

- A rotation keeps its row.'

case_ "an entry that stands twice is refused" 1 "line 8: the entry stands twice" \
'# Changelog

## [1.1.0] - 2030-01-02

### Fixed

- A rotation keeps its row.
- A rotation keeps its row.'

case_ "the same entry in two sections passes" 0 "OK: 2 entries in 2 changelog section(s)" \
'# Changelog

## [1.2.0] - 2030-02-02

### Fixed

- A rotation keeps its row.

## [1.1.0] - 2030-01-02

### Fixed

- A rotation keeps its row.'

# --- which sections are held ---

case_ "the 0.20.0 section is held" 1 "line 7: more than one sentence" \
'# Changelog

## [0.20.0] - 2030-01-02

### Fixed

- A rotation keeps its row. A load does too.'

case_ "a section below 0.20.0 is left as written" 0 "OK: 0 entries in 0 changelog section(s)" \
'# Changelog

## [0.19.0] - 2030-01-02

Rows, mostly. Z9 asked for AB-123.

### Documentation

- A rotation keeps its row. A load does too.
  And more.

### Documentation

- Pat Example wrote this'

case_ "a held section above an older one is still held" 1 "line 7: more than one sentence" \
'# Changelog

## [0.21.0] - 2030-01-02

### Fixed

- A rotation keeps its row. A load does too.

## [0.19.0] - 2030-01-02

- Anything. Goes.'

case_ "entries under Unreleased are held" 1 "line 7: more than one sentence" \
'# Changelog

## [Unreleased]

### Fixed

- A rotation keeps its row. A load does too.

## [0.19.0] - 2030-01-02'

case_ "a heading inside a code fence opens no section" 0 "OK: 0 entries in 0 changelog section(s)" \
'# Changelog

```text
## [1.1.0] - 2030-01-02
- A rotation keeps its row. A load does too.
```'

# --- the arguments ---

out="$("$CHECK" --root "$WORK/nowhere" 2>"$WORK/stderr")"
status=$?
judge "a root without a changelog is an error" 1 "CHANGELOG.md not found" "$status" "$out"

out="$("$CHECK" --strict 2>"$WORK/stderr")"
status=$?
judge "an unknown argument is an error" 2 "unknown argument: --strict" "$status" "$out"

echo "check-changelog-tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
