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
# Usage: ./scripts/check-doc-versions.sh
# Exit 1 and lists every stale snippet, or prints the number checked.

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

WS_VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml \
  | grep -m1 '^version' | sed 's/.*"\(.*\)".*/\1/')"

if [ -z "$WS_VERSION" ]; then
  echo "ERROR: could not read [workspace.package] version from Cargo.toml" >&2
  exit 1
fi

ws_major="${WS_VERSION%%.*}"
ws_rest="${WS_VERSION#*.}"
ws_minor="${ws_rest%%.*}"

if [ "$ws_major" = "0" ]; then
  required="0.${ws_minor}"
else
  required="${ws_major}"
fi

echo "Workspace version: ${WS_VERSION} (snippets must be compatible with ${required})"

# CHANGELOG.md is excluded by design: it is a historical record, and its
# entries are *supposed* to name the versions they shipped in.
#
# Only tracked files are scanned, so build output and the mutants worktree
# cannot contribute phantom hits.
matches="$(git ls-files '*.md' '*.rs' \
  | grep -v '^CHANGELOG.md$' \
  | xargs grep -noE '(axess(-[a-z]+)?)[[:space:]]*=[[:space:]]*(\{[^}]*version[[:space:]]*=[[:space:]]*)?"[0-9][^"]*"' \
  2>/dev/null || true)"

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
  if ! printf '%s' "$version" | grep -qE '^[0-9]+(\.[0-9]+){0,2}$'; then
    continue
  fi

  checked=$((checked + 1))

  v_major="${version%%.*}"
  v_rest="${version#*.}"
  if [ "$v_rest" = "$version" ]; then v_minor=""; else v_minor="${v_rest%%.*}"; fi

  if [ "$ws_major" = "0" ]; then
    actual="0.${v_minor}"
  else
    actual="${v_major}"
  fi

  if [ "$actual" != "$required" ]; then
    stale=$((stale + 1))
    stale_report="${stale_report}  ${file}:${line}: ${crate} = \"${version}\" (want ${required})"$'\n'
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
  echo "Update them to ${required}, or bump [workspace.package] version." >&2
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
  | grep -m1 '^rust-version' | sed 's/.*"\(.*\)".*/\1/')"

if [ -z "$MSRV" ]; then
  echo "ERROR: could not read [workspace.package] rust-version from Cargo.toml" >&2
  exit 1
fi

# CHANGELOG.md is exempt for the same reason as above: it records the floors
# past releases shipped with.
msrv_hits="$(git ls-files '*.md' \
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
