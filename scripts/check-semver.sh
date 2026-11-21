#!/usr/bin/env bash
# axess: semver-check the workspace against the last release tag, and hold
# every break the check reports to the migration page.
#
# The baseline is the newest `v*` tag that is a strict ancestor of HEAD: on
# release/next and on a release pull request into main that is the release
# the branch was cut after; on a tag being released it is the release
# before it (the tag itself is excluded, or the check would compare a
# release with itself). The crates.io registry is not the baseline: a check
# against it is skipped whenever a release is missing there, and a skipped
# semver check reads green, so a missing tag is a refusal.
#
# The release type is forced to minor. Read from the versions, 0.19 to 0.20
# is a major release under the 0.x rules, which every lint allows, so the
# tool would skip all of them and pass; as a minor release every lint that
# needs a major release runs, and a minor-level addition passes.
#
# The inventory. The tool's report is kept, and scripts/lib/semver_inventory.py
# reads every failure and warning block of it: each break it names must be
# named in backticks on the migration page (its full path or its last two
# segments), or this fails and lists the breaks the page leaves out. There is
# no allowlist: a break the release does not mean is fixed in the code. A
# report the reader cannot account for (a changed format, a crashed run, a
# failure with no block it reads) fails as well, so the step cannot pass by
# accident. The report format is that of the version ci.yml pins
# (cargo-semver-checks@X.Y.Z); another installed version is refused.
#
# What the tool cannot see stays hand-documented. It has no lint for a
# public struct field changing type (the nearest are
# `struct_pub_field_missing` and the struct-to-enum conversions), so a change
# like `pub client_secret: String` to `ZeroizedString` is breaking and still
# reports "no semver update required"; nor does it see a change of
# behaviour. Those are written on the migration page and in CHANGELOG.md by
# hand.
#
# The tool reads rustdoc JSON and supports a narrow range of format
# versions: "unsupported rustdoc format vNN" means cargo-semver-checks is
# older than the pinned toolchain, not that the code broke.
#
# Mirrors the "SemVer Checks" job in .github/workflows/ci.yml, which runs
# this script.
#
# Usage: ./scripts/check-semver.sh [BASELINE_TAG]
#   SEMVER_PAGE=FILE  the migration page to hold the breaks to (default:
#                     docs/production/migrating/<baseline>-to-<version>.md,
#                     the baseline tag without its v and the workspace
#                     version)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

pinned="$(grep -oE 'cargo-semver-checks@[0-9]+\.[0-9]+\.[0-9]+' .github/workflows/ci.yml | sort -u)"
if [ "$(printf '%s\n' "$pinned" | grep -c .)" -ne 1 ]; then
  echo "ERROR: .github/workflows/ci.yml does not pin one cargo-semver-checks version (found: ${pinned:-none})." >&2
  exit 1
fi
pinned="${pinned#cargo-semver-checks@}"
if ! command -v cargo-semver-checks >/dev/null 2>&1; then
  echo "ERROR: cargo-semver-checks not installed (cargo install cargo-semver-checks@$pinned --locked)." >&2
  exit 1
fi
installed="$(cargo semver-checks --version 2>/dev/null | sed -n 1p || true)"
echo "cargo-semver-checks: ${installed:-unknown}; ci.yml pins $pinned"
if [ "$installed" != "cargo-semver-checks $pinned" ]; then
  echo "ERROR: the report is read as cargo-semver-checks $pinned writes it, and '${installed:-nothing}' is installed." >&2
  echo "       Install the pinned version: cargo install cargo-semver-checks@$pinned --locked" >&2
  exit 1
fi

baseline="${1:-}"
if [ -z "$baseline" ]; then
  baseline="$(git tag --merged HEAD --no-contains HEAD --list 'v[0-9]*' --sort=-v:refname | sed -n 1p)"
fi
if [ -z "$baseline" ]; then
  echo "ERROR: semver checks NOT run: no release tag v* is an ancestor of HEAD." >&2
  echo "       Fetch the tags (git fetch --tags, or fetch-depth: 0 in CI) or name the baseline." >&2
  exit 1
fi
if ! git rev-parse --verify --quiet "${baseline}^{commit}" >/dev/null; then
  echo "ERROR: semver baseline '$baseline' is not a commit in this repository." >&2
  exit 1
fi

echo "Semver baseline: $baseline ($(git rev-parse --short "${baseline}^{commit}"))"

metadata="$(cargo metadata --no-deps --format-version 1)"
published='.packages[] | select(.publish == null or (.publish | length) > 0)'

# A crate that did not exist at the baseline has no semver to keep; it is
# named and skipped, and the published crates the baseline holds are checked.
pkgs=()
while IFS=$'\t' read -r name dir; do
  rel="${dir#"$AXESS_DIR"/}"
  if git cat-file -e "${baseline}:${rel}/Cargo.toml" 2>/dev/null; then
    pkgs+=(-p "$name")
  else
    echo "note: $name is new since $baseline and has no semver baseline; skipped"
  fi
done < <(jq -r "$published"' | [.name, (.manifest_path | rtrimstr("/Cargo.toml"))] | @tsv' <<<"$metadata")
if [ ${#pkgs[@]} -eq 0 ]; then
  echo "ERROR: no published crate to check against $baseline." >&2
  exit 1
fi

if [ -z "${SEMVER_PAGE:-}" ]; then
  versions="$(jq -r "$published"' | .version' <<<"$metadata" | sort -u)"
  if [ "$(printf '%s\n' "$versions" | grep -c .)" -ne 1 ]; then
    echo "ERROR: the published crates do not share one version (${versions//$'\n'/, }), so the migration page cannot be named; set SEMVER_PAGE." >&2
    exit 1
  fi
  SEMVER_PAGE="docs/production/migrating/${baseline#v}-to-${versions}.md"
fi
echo "Migration page: $SEMVER_PAGE"

report="$(mktemp "${TMPDIR:-/tmp}/axess-semver.XXXXXX")"
trap 'rm -f "$report"' EXIT

# The report is shown as it arrives and kept; the tool's status is kept too,
# for the inventory to weigh, instead of ending the script.
status=0
cargo semver-checks check-release "${pkgs[@]}" --baseline-rev "$baseline" --release-type minor 2>&1 \
  | tee "$report" || status="${PIPESTATUS[0]}"
echo "cargo-semver-checks exited $status"

python3 -I -B "$AXESS_DIR/scripts/lib/semver_inventory.py" --report "$report" --page "$SEMVER_PAGE" --status "$status"
