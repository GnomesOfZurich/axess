#!/usr/bin/env bash
# axess: semver-check the workspace against the last release tag.
#
# The baseline is the newest `v*` tag that is a strict ancestor of HEAD: on
# release/next and on a release pull request into main that is the release
# the branch was cut after; on a tag being released it is the release
# before it (the tag itself is excluded, or the check would compare a
# release with itself). It used to be the crates.io registry, which skipped
# the check whenever a baseline was missing; a missing tag is now a refusal,
# because a skipped semver check reads green.
#
# A pass is a floor, not a ceiling. cargo-semver-checks has no lint for a
# public struct field changing type (the nearest are
# `struct_pub_field_missing` and the struct-to-enum conversions), so a change
# like `pub client_secret: String` to `ZeroizedString` is breaking and still
# reports "no semver update required". Read a green run as "none of the
# covered classes regressed", and keep documenting breaking changes in
# CHANGELOG.md by hand.
#
# The tool reads rustdoc JSON and supports a narrow range of format
# versions: "unsupported rustdoc format vNN" means cargo-semver-checks is
# older than the pinned toolchain, not that the code broke. Fix with
# `cargo install cargo-semver-checks --locked`.
#
# Mirrors the "SemVer Checks" job in .github/workflows/ci.yml, which runs
# this script.
#
# Usage: ./scripts/check-semver.sh [BASELINE_TAG]

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

if ! command -v cargo-semver-checks >/dev/null 2>&1; then
  echo "ERROR: cargo-semver-checks not installed (cargo install cargo-semver-checks --locked)." >&2
  exit 1
fi

baseline="${1:-}"
if [ -z "$baseline" ]; then
  baseline="$(git tag --merged HEAD --no-contains HEAD --list 'v[0-9]*' --sort=-v:refname | head -1)"
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
cargo semver-checks check-release --workspace --baseline-rev "$baseline"
