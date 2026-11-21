#!/usr/bin/env bash
# axess: verify every documented dependency snippet names the current version.
#
# Docs and doc-comments carry copy-pasteable snippets like
#
#     axess = { version = "0.4.0", features = ["sqlite"] }
#
# and nothing keeps them in step with the workspace version. They drift
# silently: a reader lands on a crate's README from crates.io or the GitHub
# tree view, copies a snippet, and pins a release two minors old. The version
# badge is generated and the docs.rs links are unversioned, so these snippets
# are the only place a stale number can survive.
#
# The rule is cargo's own compatibility rule, not string equality: a snippet
# may say "0.4" or "0.4.0" when the workspace is at 0.4.0, because both
# resolve to it. For 0.x releases the minor is the breaking unit, so
# major.minor must match; from 1.0 on, the major must match.
#
# A migrating page (`docs/production/migrating/<from>-to-<to>.md`) is held
# to the version it moves to, not to the workspace: the page about moving to
# 0.19.0 tells its reader to take 0.19, whatever the current release is, so
# a bump leaves it alone.
#
# Usage: ./scripts/check-doc-versions.sh
# Exit 1 and lists every stale snippet, or prints the number checked.

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

WS_VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml \
  | grep '^version' | sed -n 1p | sed 's/.*"\(.*\)".*/\1/')"

if [ -z "$WS_VERSION" ]; then
  echo "ERROR: could not read [workspace.package] version from Cargo.toml" >&2
  exit 1
fi

# compatible <version>: the part of a version cargo's rule compares.
compatible() {
  local major="${1%%.*}" rest="${1#*.}"
  if [ "$rest" = "$1" ]; then rest=""; fi
  if [ "$major" = "0" ]; then
    echo "0.${rest%%.*}"
  else
    echo "$major"
  fi
}

required="$(compatible "$WS_VERSION")"

echo "Workspace version: ${WS_VERSION} (snippets must be compatible with ${required})"

# CHANGELOG.md is excluded by design: it is a historical record, and its
# entries are *supposed* to name the versions they shipped in.
#
# The files scanned are the tracked ones and the untracked ones git does not
# ignore, so a file not yet added is checked as well, and build output and
# the mutants worktree (both ignored) cannot contribute phantom hits.
matches="$(git ls-files --cached --others --exclude-standard --deduplicate '*.md' '*.rs' \
  | grep -v '^CHANGELOG.md$' \
  | xargs grep -noE '(axess(-[a-z]+)?)[[:space:]]*=[[:space:]]*(\{[^}]*version[[:space:]]*=[[:space:]]*)?"[0-9][^"]*"' \
  2>/dev/null || true)"

# A third shape: prose naming the release ("published on crates.io at
# `v0.3.0`"), which the pattern above does not see because it only matches a
# dependency snippet. A chapter that states the current version is wrong from
# the next release onward, so the rule is not "keep it updated" but "do not
# state it": link to crates.io instead. Historical statements are fine, which
# is why this looks only for a claim about the present.
prose="$(git ls-files --cached --others --exclude-standard --deduplicate '*.md' '*.rs' \
  | grep -v '^CHANGELOG.md$' \
  | grep -v '^docs/production/migrating.md$' \
  | xargs grep -noEi '(published|released|available|current(ly)?)[^.]{0,40}(crates\.io)?[^.]{0,20}(at|is|version)[[:space:]]+.?v?[0-9]+\.[0-9]+\.[0-9]+' \
  2>/dev/null || true)"

if [ -n "$prose" ]; then
  echo "ERROR: prose states a current version, which drifts at the next release:" >&2
  printf '%s\n' "$prose" | sed 's/^/  /' >&2
  echo "" >&2
  echo "       Link to https://crates.io/crates/axess instead of naming a" >&2
  echo "       version. Historical statements (a migration section, a" >&2
  echo "       changelog entry) are exempt and belong in those files." >&2
  exit 1
fi

checked=0
stale=0
stale_report=""

while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  file="${hit%%:*}"
  rest="${hit#*:}"
  line="${rest%%:*}"
  match="${rest#*:}"

  crate="${match%%[[:space:]]*}"
  crate="${crate%%=*}"
  version="$(printf '%s' "$match" | sed 's/.*"\([^"]*\)"$/\1/')"

  # Placeholders such as "0.NEW.0" in the release walkthrough are templates,
  # not claims about the current version. Only real semver is judged.
  if ! grep -qE '^[0-9]+(\.[0-9]+){0,2}$' <<<"$version"; then
    continue
  fi

  checked=$((checked + 1))

  want="$required"
  case "$file" in
    docs/production/migrating/*-to-*.md)
      target="${file##*-to-}"
      target="${target%.md}"
      if grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' <<<"$target"; then
        want="$(compatible "$target")"
      else
        stale=$((stale + 1))
        stale_report="${stale_report}  ${file}: a migrating page whose name gives no X.Y.Z it moves to"$'\n'
        continue
      fi ;;
  esac

  if [ "$(compatible "$version")" != "$want" ]; then
    stale=$((stale + 1))
    stale_report="${stale_report}  ${file}:${line}: ${crate} = \"${version}\" (want ${want})"$'\n'
  fi
done <<< "$matches"

if [ "$checked" -eq 0 ]; then
  echo "ERROR: no dependency snippets found at all: the matcher is broken," >&2
  echo "       not the docs. Check the grep pattern before trusting a pass." >&2
  exit 1
fi

if [ "$stale" -gt 0 ]; then
  echo ""
  echo "ERROR: ${stale} of ${checked} documented snippets name a stale version:" >&2
  printf '%s' "$stale_report" >&2
  echo "" >&2
  echo "Update them to the version named (a migrating page's own target, ${required} elsewhere)." >&2
  exit 1
fi

echo "OK: all ${checked} documented dependency snippets are compatible with ${required}."

# ── MSRV ────────────────────────────────────────────────────────────────────
#
# `rust-version` is a promise to adopters, and it was restated in prose in
# three places that drifted apart: two docs still claimed 1.87 while the
# manifest said 1.93.1 and the dependency tree actually required 1.94.0. The
# manifest is the single source; anything in the docs must agree with it
# exactly (unlike dependency snippets, an MSRV is a specific floor, not a
# compatible range).

MSRV="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml \
  | grep '^rust-version' | sed -n 1p | sed 's/.*"\(.*\)".*/\1/')"

if [ -z "$MSRV" ]; then
  echo "ERROR: could not read [workspace.package] rust-version from Cargo.toml" >&2
  exit 1
fi

# CHANGELOG.md is exempt for the same reason as above: it records the floors
# past releases shipped with.
msrv_hits="$(git ls-files --cached --others --exclude-standard --deduplicate '*.md' \
  | grep -v '^CHANGELOG.md$' \
  | xargs grep -noE 'MSRV `[0-9]+\.[0-9]+(\.[0-9]+)?`|Rust [0-9]+\.[0-9]+(\.[0-9]+)? or later' \
  2>/dev/null || true)"

msrv_checked=0
msrv_stale=""
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  file="${hit%%:*}"; rest="${hit#*:}"; line="${rest%%:*}"; match="${rest#*:}"
  version="$(printf '%s' "$match" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')"
  msrv_checked=$((msrv_checked + 1))
  if [ "$version" != "$MSRV" ]; then
    msrv_stale="${msrv_stale}  ${file}:${line}: says ${version}, manifest says ${MSRV}"$'\n'
  fi
done <<< "$msrv_hits"

if [ "$msrv_checked" -eq 0 ]; then
  echo "ERROR: no documented MSRV found. The docs should state it, or this" >&2
  echo "       check has stopped matching them: either way, not a pass." >&2
  exit 1
fi

if [ -n "$msrv_stale" ]; then
  echo "" >&2
  echo "ERROR: documented MSRV disagrees with rust-version = ${MSRV}:" >&2
  printf '%s' "$msrv_stale" >&2
  exit 1
fi

echo "OK: all ${msrv_checked} documented MSRV mentions match rust-version ${MSRV}."
