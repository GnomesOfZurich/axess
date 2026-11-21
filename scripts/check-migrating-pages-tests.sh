#!/usr/bin/env bash
# axess: crafted cases for scripts/check-migrating-pages.sh.
#
# Each case builds a docs tree under a temporary root, runs the check with
# `--root`, and asserts the exit status and a fragment of the output.
#
# Usage: ./scripts/check-migrating-pages-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-migrating-pages.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-migrating.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case NAME EXPECTED_EXIT FRAGMENT SUMMARY PAGE_CONTENT [RUST_SOURCE]
case_() {
  local name="$1" want="$2" fragment="$3" summary="$4" page="$5" rust="${6:-}"
  local root="$WORK/case-$passed-$failed"
  mkdir -p "$root/docs/production/migrating"
  printf '%s\n' "$summary" > "$root/docs/SUMMARY.md"
  printf '%s\n' "$page" > "$root/docs/production/migrating/1.0.0-to-1.1.0.md"
  if [ -n "$rust" ]; then
    mkdir -p "$root/some-crate/src"
    printf '%s\n' "$rust" > "$root/some-crate/src/lib.rs"
  fi
  local out status
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  judge "$name" "$want" "$fragment" "$status" "$out"
}

LISTED='- [1.0.0 to 1.1.0](production/migrating/1.0.0-to-1.1.0.md)'

case_ "a whole page passes" 0 "OK: 1 migrating pages" "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.

### Decisions left as they are

- One.'

case_ "an empty section in the middle is refused" 1 '"### Decisions left as they are" is empty' "$LISTED" \
'# 1.0.0 to 1.1.0

### Decisions left as they are

### Added

- One.'

case_ "an empty last section is refused" 1 '"### Added" is empty' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.

### Added
'

case_ "a heading inside a code block is not a section" 0 "OK" "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

```text
### not a heading
```'

case_ "a page missing from SUMMARY.md is refused" 1 "is not listed in docs/SUMMARY.md" \
'- [Other](production/other.md)' \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.'

case_ "a stale version span on a page is refused" 1 '"0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- A credential sealed by 0.17 to 0.19 opens under the earlier binding.'

case_ "a stale version span in a doc comment is refused" 1 'some-crate/src/lib.rs:1: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.' \
'//! A credential sealed by 0.17 to 0.19 is bound to its issuer.'

case_ "a stale version span wrapped across two lines of a page is refused" 1 \
  'production/migrating/1.0.0-to-1.1.0.md:5: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- A credential sealed by 0.17 to
  0.19 opens under the earlier binding.'

case_ "a stale version span wrapped across two doc comment lines is refused" 1 \
  'some-crate/src/lib.rs:2: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.' \
'//! A credential sealed by the
//! 0.17
//! to 0.19 releases is bound to its issuer.'

case_ "a stale version span wrapped in a line comment is refused" 1 \
  'some-crate/src/lib.rs:1: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.' \
'    // sealed by 0.17 to
    // 0.19 is bound to its issuer.
fn f() {}'

case_ "a stale version span wrapped in a block comment is refused" 1 \
  'some-crate/src/lib.rs:2: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.' \
'/*
 * sealed by 0.17 to
 * 0.19 is bound to its issuer.
 */
fn f() {}'

case_ "a stale version span wrapped in a blockquote is refused" 1 \
  'production/migrating/1.0.0-to-1.1.0.md:5: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

> A credential sealed by 0.17 to
> 0.19 opens under the earlier binding.'

case_ "a stale version span wrapped in a quoted doc comment is refused" 1 \
  'some-crate/src/lib.rs:1: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.' \
'//! > sealed by 0.17 to
//! > 0.19 is bound to its issuer.'

case_ "a stale version span wrapped in a nested blockquote is refused" 1 \
  'production/migrating/1.0.0-to-1.1.0.md:5: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

> > A credential sealed by 0.17 to
> > 0.19 opens under the earlier binding.'

case_ "a stale version span split by a Markdown hard break is refused" 1 \
  'production/migrating/1.0.0-to-1.1.0.md:5: "0.17 to 0.19" is stale' "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

A credential sealed by 0.17 to\
0.19 opens under the earlier binding.'

case_ "the words of a stale span in separate quoted paragraphs pass" 0 "no stale phrase" "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

> Moved in 0.17 to
>
> 0.19 nothing.'

case_ "the words of a stale span in separate paragraphs pass" 0 "no stale phrase" "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- Moved in 0.17 to

- 0.19 nothing.'

case_ "the corrected span passes" 0 "no stale phrase" "$LISTED" \
'# 1.0.0 to 1.1.0

### Compile breaks

- One.' \
'//! A credential sealed by 0.15 to 0.19 is bound to its issuer.'

# A source that cannot be read stops the check with an error rather than
# passing as if it held no stale phrase. Permissions do not bind the
# superuser, so the case is skipped, and says so, when the file stays
# readable.
root="$WORK/unreadable"
mkdir -p "$root/docs/production/migrating" "$root/some-crate/src"
printf '%s\n' "$LISTED" > "$root/docs/SUMMARY.md"
printf '%s\n' '# 1.0.0 to 1.1.0' '' '### Compile breaks' '' '- One.' \
  > "$root/docs/production/migrating/1.0.0-to-1.1.0.md"
printf '%s\n' '//! Nothing stale.' > "$root/some-crate/src/lib.rs"
chmod 000 "$root/some-crate/src/lib.rs"
if [ -r "$root/some-crate/src/lib.rs" ]; then
  echo "SKIP: a source that cannot be read is refused (the file stays readable to this user)" >&2
else
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  judge "a source that cannot be read is refused" 1 'the sources were not read' "$status" "$out"
fi
chmod 600 "$root/some-crate/src/lib.rs"

echo "check-migrating-pages-tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
