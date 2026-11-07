#!/usr/bin/env bash
# axess: check that the version being released is the version written down.
#
# A release names its version in three places that nothing tied together:
# `[workspace.package].version` in Cargo.toml (what cargo publishes), the
# `vX.Y.Z` tag (what the release workflow starts from) and the dated
# `## [X.Y.Z] - YYYY-MM-DD` section of CHANGELOG.md (what an adopter reads
# before upgrading). This script refuses, by name, every way they can
# disagree. The pull-request gate into main and the release workflow run it
# in the default mode; pull requests into release/next run it with
# `--allow-unreleased`.
#
# Default mode (a release pull request into main, a release tag):
#   - the workspace version is X.Y.Z (an optional pre-release suffix allowed);
#   - every internal `axess-*` entry in [workspace.dependencies] pins
#     `=X.Y.Z`, so no member publishes against another release of a sibling;
#   - CHANGELOG.md has exactly one `## [X.Y.Z] - YYYY-MM-DD` heading, the
#     date is a real calendar date (`unreleased` in its place is refused), the
#     section has at least one entry, and it is the newest section;
#   - [Unreleased] carries no entries, since those would ship unannounced;
#   - with `--tag T`, T equals `vX.Y.Z`.
#
# `--allow-unreleased` (a release branch before release day): as soon as a
# release's version is known, Cargo.toml carries it and CHANGELOG.md heads
# its section `## [X.Y.Z] - unreleased`; release day writes the date in. This
# mode accepts that heading, accepts no section for X.Y.Z at all when
# CHANGELOG.md has `## [Unreleased]` (the version is not known yet), lets
# [Unreleased] carry entries and does not require entries in the section. A
# section for X.Y.Z must still be unique, the newest, and either marked
# `unreleased` or dated with a real date. It refuses `--tag`, because a tag
# is a release.
#
# Usage: ./scripts/check-release-version.sh [--allow-unreleased] [--tag vX.Y.Z] [--root DIR]
#
#   --root DIR  check DIR/Cargo.toml and DIR/CHANGELOG.md instead of the
#               checkout this script lives in (the tests use it).
#
# Exit 0 with one OK line, or exit 1 with every refusal on stderr.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOW_UNRELEASED=false
TAG=""
HAVE_TAG=false

usage() { sed -n '/^# Usage:/,/^#   *checkout/p' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --allow-unreleased) ALLOW_UNRELEASED=true; shift ;;
    --tag)
      [ $# -ge 2 ] || { echo "ERROR: --tag needs a value" >&2; usage >&2; exit 2; }
      TAG="$2"; HAVE_TAG=true; shift 2 ;;
    --root)
      [ $# -ge 2 ] || { echo "ERROR: --root needs a value" >&2; usage >&2; exit 2; }
      ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$ALLOW_UNRELEASED" = true ] && [ "$HAVE_TAG" = true ]; then
  echo "ERROR: --tag and --allow-unreleased refused together: a tag is a release, and a release needs its dated section." >&2
  exit 2
fi

MANIFEST="$ROOT/Cargo.toml"
CHANGELOG="$ROOT/CHANGELOG.md"
for f in "$MANIFEST" "$CHANGELOG"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found" >&2
    exit 1
  fi
done

errors=0
refuse() {
  echo "REFUSED: $*" >&2
  errors=$((errors + 1))
}

VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/p' "$MANIFEST" \
  | grep -m1 '^version[[:space:]]*=' | sed 's/.*"\(.*\)".*/\1/')"

SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
if [ -z "$VERSION" ]; then
  echo "REFUSED: no version in [workspace.package] of $MANIFEST" >&2
  exit 1
fi
if ! [[ "$VERSION" =~ $SEMVER_RE ]]; then
  echo "REFUSED: workspace version '$VERSION' is not X.Y.Z" >&2
  exit 1
fi

# Dots and the pre-release separators are the only regex metacharacters a
# version can carry; escape them for grep -E and awk.
VERSION_RE="$(printf '%s' "$VERSION" | sed 's/[.+-]/\\&/g')"

# Internal crates are pinned with `=X.Y.Z` in [workspace.dependencies]; a
# release bump that misses one publishes a crate that depends on the last
# release of its sibling.
stale_pins="$(sed -n '/^\[workspace.dependencies\]/,/^\[/p' "$MANIFEST" \
  | grep -E '^axess-[a-z-]+[[:space:]]*=' \
  | grep -vE "version[[:space:]]*=[[:space:]]*\"=${VERSION_RE}\"" || true)"
if [ -n "$stale_pins" ]; then
  while IFS= read -r line; do
    refuse "[workspace.dependencies] does not pin \"=$VERSION\": $line"
  done <<EOF
$stale_pins
EOF
fi

if [ "$HAVE_TAG" = true ] && [ "$TAG" != "v$VERSION" ]; then
  refuse "tag '$TAG' is not v$VERSION, the workspace version in Cargo.toml"
fi

valid_date() {
  local y=$((10#$1)) m=$((10#$2)) d=$((10#$3)) max
  [ "$m" -ge 1 ] && [ "$m" -le 12 ] || return 1
  case "$m" in
    1|3|5|7|8|10|12) max=31 ;;
    4|6|9|11) max=30 ;;
    2)
      if { [ $((y % 4)) -eq 0 ] && [ $((y % 100)) -ne 0 ]; } || [ $((y % 400)) -eq 0 ]; then
        max=29
      else
        max=28
      fi ;;
  esac
  [ "$d" -ge 1 ] && [ "$d" -le "$max" ]
}

# Entries between a heading at line $1 and the next `## ` heading.
section_entries() {
  awk -v start="$1" 'NR > start && /^## / { exit } NR > start && /^[[:space:]]*[-*] / { n++ } END { print n + 0 }' "$CHANGELOG"
}

version_lines="$(grep -nE "^## \[${VERSION_RE}\]" "$CHANGELOG" || true)"
version_count=0
[ -n "$version_lines" ] && version_count="$(printf '%s\n' "$version_lines" | wc -l | tr -d ' ')"
unreleased_line="$(grep -nE '^## \[Unreleased\]' "$CHANGELOG" | head -1 | cut -d: -f1)"
newest_line="$(grep -nE '^## \[' "$CHANGELOG" | grep -vE '^[0-9]+:## \[Unreleased\]' | head -1)"

if [ "$version_count" -eq 0 ]; then
  if [ "$ALLOW_UNRELEASED" = true ] && [ -n "$unreleased_line" ]; then
    echo "NOTE: CHANGELOG.md has no section for $VERSION yet; the dated check is skipped (--allow-unreleased)."
  elif [ "$ALLOW_UNRELEASED" = true ]; then
    refuse "CHANGELOG.md has neither a section for $VERSION nor an [Unreleased] section"
  else
    refuse "CHANGELOG.md has no section for $VERSION; release preparation adds '## [$VERSION] - YYYY-MM-DD'"
  fi
elif [ "$version_count" -gt 1 ]; then
  refuse "CHANGELOG.md has $version_count sections for $VERSION (lines $(printf '%s\n' "$version_lines" | cut -d: -f1 | tr '\n' ' ' | sed 's/ $//'))"
else
  line_no="${version_lines%%:*}"
  heading="${version_lines#*:}"
  DATED_RE="^## \[${VERSION_RE}\] - ([0-9]{4})-([0-9]{2})-([0-9]{2})$"
  PENDING_RE="^## \[${VERSION_RE}\] - unreleased$"
  if [[ "$heading" =~ $DATED_RE ]]; then
    y="${BASH_REMATCH[1]}"; m="${BASH_REMATCH[2]}"; d="${BASH_REMATCH[3]}"
    if ! valid_date "$y" "$m" "$d"; then
      refuse "CHANGELOG.md line $line_no: $y-$m-$d is not a calendar date: $heading"
    fi
  elif [[ "$heading" =~ $PENDING_RE ]]; then
    if [ "$ALLOW_UNRELEASED" != true ]; then
      refuse "CHANGELOG.md line $line_no: the section for $VERSION is still marked unreleased; release day writes the date in: '## [$VERSION] - YYYY-MM-DD'"
    fi
  elif [ "$ALLOW_UNRELEASED" = true ]; then
    refuse "CHANGELOG.md line $line_no: the section for $VERSION is neither '## [$VERSION] - unreleased' nor dated '## [$VERSION] - YYYY-MM-DD': $heading"
  else
    refuse "CHANGELOG.md line $line_no: the section for $VERSION is not dated as '## [$VERSION] - YYYY-MM-DD': $heading"
  fi
  if [ "$ALLOW_UNRELEASED" != true ] && [ "$(section_entries "$line_no")" -eq 0 ]; then
    refuse "CHANGELOG.md line $line_no: the section for $VERSION has no entries"
  fi
  if [ "${newest_line%%:*}" != "$line_no" ]; then
    refuse "CHANGELOG.md line $line_no: the section for $VERSION is not the newest; line ${newest_line%%:*} is: ${newest_line#*:}"
  fi
fi

if [ "$ALLOW_UNRELEASED" != true ] && [ -n "$unreleased_line" ]; then
  pending="$(section_entries "$unreleased_line")"
  if [ "$pending" -gt 0 ]; then
    refuse "CHANGELOG.md line $unreleased_line: [Unreleased] still has $pending entr$([ "$pending" -eq 1 ] && echo y || echo ies); a release moves them into its dated section"
  fi
fi

if [ "$errors" -gt 0 ]; then
  echo "ERROR: release version check failed with $errors refusal(s) for $VERSION." >&2
  exit 1
fi

if [ "$version_count" -eq 0 ]; then
  echo "OK: version $VERSION, pins agree; CHANGELOG.md [Unreleased] present (dated section not yet required)."
elif [ "$HAVE_TAG" = true ]; then
  echo "OK: tag $TAG, version $VERSION, pins agree, CHANGELOG.md ${heading#\#\# }."
else
  echo "OK: version $VERSION, pins agree, CHANGELOG.md ${heading#\#\# }."
fi
