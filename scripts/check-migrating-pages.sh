#!/usr/bin/env bash
# axess: the migrating pages are whole: each is listed in docs/SUMMARY.md,
# and no section of one is a heading with nothing under it.
#
# A migrating page is read by an adopter at the moment of an upgrade, and a
# heading with nothing under it reads as "nothing to do", even where the
# release leaves the adopter something to decide. A page missing from
# SUMMARY.md is not in the book at all. That a page names every break
# cargo-semver-checks reports is held by scripts/check-semver.sh; the breaks
# the tool cannot see (a field changing type, a change of behaviour) are a
# matter for the reader. This check holds the shape that reading starts
# from.
#
# One content fact is held too, because it is easy to state wrong in several
# places at once: the earlier binding of a tenant OAuth credential dates from
# 0.15.0, so no page or doc comment may give its window as "0.17 to 0.19". A phrase
# that was corrected joins STALE_PHRASES below with the reason it is wrong.
#
# Usage: ./scripts/check-migrating-pages.sh [--root DIR]
#   --root DIR  check DIR/docs instead of this repository's (the self-test,
#               scripts/check-migrating-pages-tests.sh, uses it)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "${1:-}" = "--root" ]; then
  ROOT="$2"
fi
DIR="$ROOT/docs/production/migrating"
SUMMARY="$ROOT/docs/SUMMARY.md"

if [ ! -d "$DIR" ] || [ ! -r "$SUMMARY" ]; then
  echo "ERROR: $DIR or $SUMMARY is missing: the layout is broken, not the pages." >&2
  exit 1
fi

pages=0
problems=()
for page in "$DIR"/*.md; do
  [ -e "$page" ] || continue
  pages=$((pages + 1))
  rel="production/migrating/$(basename "$page")"
  grep -qF "($rel)" "$SUMMARY" || problems+=("$rel is not listed in docs/SUMMARY.md")
  while IFS= read -r empty; do
    problems+=("$rel: the section \"$empty\" is empty")
  done < <(awk '
    /^```/ { fence = !fence }
    !fence && /^#{2,4} / { if (heading != "" && body == 0) print heading; heading = $0; body = 0; next }
    /[^[:space:]]/ { body++ }
    END { if (heading != "" && body == 0) print heading }' "$page")
done

# Each entry: the phrase, then why it is wrong.
STALE_PHRASES=(
  "0.17 to 0.19|the earlier tenant credential binding dates from 0.15.0 (0.15 to 0.19)"
)
search=("$ROOT/docs")
while IFS= read -r -d '' src; do
  search+=("$src")
done < <(find "$ROOT" -mindepth 2 -maxdepth 3 -type d -name src -not -path '*/target/*' -print0)
for entry in "${STALE_PHRASES[@]}"; do
  phrase="${entry%%|*}"
  reason="${entry#*|}"
  # Prints FILE:LINE for each place the phrase occurs, LINE being the line
  # the match starts on. Its words may be separated by any run of blanks, or
  # by one line break, which may follow a backslash (a Markdown hard break or
  # a Rust string continuation) and whose next line may open with any run of
  # comment and quote markers (//, ///, //!, *, >, so `/// >` and `> >` as
  # well). A phrase wrapped across two lines of a paragraph, a blockquote, a
  # comment or a quote inside a comment is found as well as one on a single
  # line; a blank line between its words is a paragraph break and is not. A
  # file that cannot be read stops the search.
  if ! hits="$(find "${search[@]}" \( -name target -o -name .git \) -prune -o \
                 -type f \( -name '*.md' -o -name '*.rs' \) -print0 |
               python3 -I -B -c '
import re, sys

gap = r"(?:[ \t]+|[ \t]*\\?\r?\n[ \t]*(?:(?://[/!]?|\*|>)[ \t]*)*)"
phrase = re.compile(gap.join(re.escape(word) for word in sys.argv[1].split()))
for path in sys.stdin.buffer.read().decode("utf-8", "surrogateescape").split("\0"):
    if not path:
        continue
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    for match in phrase.finditer(text):
        print(f"{path}:{text.count(chr(10), 0, match.start()) + 1}")
' "$phrase")"; then
    echo "ERROR: the search for \"$phrase\" failed: the sources were not read." >&2
    exit 1
  fi
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%:*}"
    problems+=("${file#"$ROOT"/}:${hit##*:}: \"$phrase\" is stale: $reason")
  done <<< "$hits"
done

if [ "$pages" -eq 0 ]; then
  echo "ERROR: no migrating page found under $DIR: the selection is broken." >&2
  exit 1
fi
if [ "${#problems[@]}" -gt 0 ]; then
  echo "ERROR: ${#problems[@]} problem(s) in the migrating pages and the docs:" >&2
  printf '  %s\n' "${problems[@]}" >&2
  exit 1
fi
echo "OK: ${pages} migrating pages are listed in SUMMARY.md and have no empty section; no stale phrase in docs or Rust sources."
