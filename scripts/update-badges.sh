#!/usr/bin/env bash
# axess — regenerate badges derived from Cargo.toml facts.
#
# Only the badges whose text is derived from a source-of-truth file are
# regenerated here:
#
#   - version.svg → workspace [workspace.package].version (root Cargo.toml)
#   - license.svg → workspace [workspace.package].license (root Cargo.toml,
#                   formatted "X / Y" to match the Gnomes badge convention)
#
# Status ("alpha", "beta", etc.) is an editorial choice — change it by
# regenerating status.svg via generate-badge.sh directly.
#
# Coverage is handled by ci.yml (auto-commit pattern) since it updates
# on every push, not on deliberate edits like version/license. That job
# stays as-is; it is unrelated to this script.
#
# CI runs this script and `git diff --exit-code .github/badges/version.svg
# .github/badges/license.svg`. If the committed badges drift from the
# regenerated ones, CI fails with a hint to re-run this script and commit
# the result.
#
# Usage: ./scripts/update-badges.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$AXESS_DIR"

# Extract the `[workspace.package]` block so we don't accidentally match
# a `version = ` line inside `[workspace.dependencies]` or a member crate
# pulled in via `[patch.*]`. `awk` resets `flag` on any `[` header that
# is not our target section.
section=$(awk '
  /^\[workspace.package\]/ { flag = 1; next }
  /^\[/                    { flag = 0 }
  flag                     { print }
' Cargo.toml)

version=$(printf '%s\n' "$section" | grep -m1 '^version = ' | sed -E 's/version = "([^"]+)"/\1/')
license=$(printf '%s\n' "$section" | grep -m1 '^license = ' | sed -E 's/license = "([^"]+)"/\1/' | sed 's| OR | / |g')

if [ -z "$version" ] || [ -z "$license" ]; then
  echo "Could not parse version/license from [workspace.package] in Cargo.toml" >&2
  exit 1
fi

./scripts/generate-badge.sh version "$version" blue .github/badges/version.svg
./scripts/generate-badge.sh license "$license" blue .github/badges/license.svg

echo "Regenerated .github/badges/version.svg ($version) and license.svg ($license)"
