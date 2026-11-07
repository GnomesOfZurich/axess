#!/usr/bin/env bash
# axess: crafted cases for scripts/check-release-version.sh.
#
# Each case writes a Cargo.toml and a CHANGELOG.md into a temporary
# directory, runs the check against it with `--root`, and asserts the exit
# status and a fragment of the output. The refusals are the contract, so a
# case that passes for the wrong reason (a different refusal) fails here.
#
# Usage: ./scripts/check-release-version-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-release-version.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-release-version.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

passed=0
failed=0

# manifest VERSION [PIN]: a workspace manifest whose internal pin is PIN.
manifest() {
  local version="$1" pin="${2:-$1}"
  cat <<EOF
[workspace]
members = ["axess"]

[workspace.package]
version = "$version"
edition = "2024"

[workspace.dependencies]
axess-core     = { path = "axess-core",     version = "=$pin", default-features = false }
axess-strings  = { path = "axess-strings",  version = "=$version" }
serde = "1"
EOF
}

# case NAME EXPECTED_EXIT FRAGMENT MANIFEST CHANGELOG [ARGS...]
case_() {
  local name="$1" want="$2" fragment="$3" man="$4" log="$5"
  shift 5
  local dir="$WORK/$passed-$failed"
  mkdir -p "$dir"
  printf '%s\n' "$man" > "$dir/Cargo.toml"
  printf '%s\n' "$log" > "$dir/CHANGELOG.md"
  local out status
  out="$("$CHECK" --root "$dir" "$@" 2>&1)"
  status=$?
  rm -rf "$dir"
  if [ "$status" -eq "$want" ] && printf '%s' "$out" | grep -qF -- "$fragment"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment', got exit $status:" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

M="$(manifest 0.18.0)"
HEAD='# Changelog

## [Unreleased]
'
RELEASED="$HEAD
## [0.18.0] - 2026-11-07

### Added

- A thing.

## [0.17.0] - 2026-11-06

### Added

- An older thing."

case_ "dated section passes" 0 "OK: version 0.18.0" "$M" "$RELEASED"
case_ "dated section passes with no [Unreleased] heading" 0 "OK: tag v0.18.0" "$M" "# Changelog

## [0.18.0] - 2026-11-07

### Added

- A thing.

## [0.17.0] - 2026-11-06

- An older thing." --tag v0.18.0
case_ "matching tag passes" 0 "OK: tag v0.18.0" "$M" "$RELEASED" --tag v0.18.0
case_ "tag without v refused" 1 "tag '0.18.0' is not v0.18.0" "$M" "$RELEASED" --tag 0.18.0
case_ "other tag refused" 1 "tag 'v0.18.1' is not v0.18.0" "$M" "$RELEASED" --tag v0.18.1
case_ "tag with allow-unreleased refused" 2 "refused together" "$M" "$RELEASED" --tag v0.18.0 --allow-unreleased

PREPARING="$HEAD
### Added

- Pending work.

## [0.17.0] - 2026-11-06

### Added

- An older thing."

case_ "missing section refused" 1 "has no section for 0.18.0" "$M" "$PREPARING"
case_ "missing section allowed before preparation" 0 "dated check is skipped" "$M" "$PREPARING" --allow-unreleased
case_ "missing section and no Unreleased refused" 1 "neither a section for 0.18.0 nor an [Unreleased]" "$M" \
  "# Changelog

## [0.17.0] - 2026-11-06

- An older thing." --allow-unreleased
case_ "pending Unreleased entries refused" 1 "[Unreleased] still has 1 entry" "$(manifest 0.17.0)" "$PREPARING"
case_ "pending Unreleased entries allowed before preparation" 0 "OK: version 0.17.0" "$(manifest 0.17.0)" "$PREPARING" --allow-unreleased

undated() { printf '%s\n## %s\n\n- A thing.\n\n## [0.17.0] - 2026-11-06\n\n- An older thing.' "$HEAD" "$1"; }
case_ "undated section refused" 1 "is not dated" "$M" "$(undated '[0.18.0]')"
case_ "undated section refused before release day too" 1 "neither '## [0.18.0] - unreleased' nor dated" "$M" "$(undated '[0.18.0]')" --allow-unreleased
case_ "section marked unreleased refused" 1 "is still marked unreleased" "$M" "$(undated '[0.18.0] - unreleased')"
case_ "section marked unreleased refused for a tag" 1 "is still marked unreleased" "$M" "$(undated '[0.18.0] - unreleased')" --tag v0.18.0
case_ "section marked unreleased allowed before release day" 0 "[0.18.0] - unreleased" "$M" "$(undated '[0.18.0] - unreleased')" --allow-unreleased
case_ "capitalised Unreleased marker refused before release day" 1 "neither '## [0.18.0] - unreleased' nor dated" "$M" "$(undated '[0.18.0] - Unreleased')" --allow-unreleased
case_ "impossible date refused before release day too" 1 "2026-02-30 is not a calendar date" "$M" "$(undated '[0.18.0] - 2026-02-30')" --allow-unreleased
case_ "marked section allowed empty before release day" 0 "[0.18.0] - unreleased" "$M" "$HEAD
## [0.18.0] - unreleased

## [0.17.0] - 2026-11-06

- An older thing." --allow-unreleased
case_ "marked section not newest refused before release day" 1 "is not the newest" "$M" "$HEAD
## [0.19.0] - unreleased

- A later thing.

## [0.18.0] - unreleased

- A thing." --allow-unreleased
case_ "unpadded date refused" 1 "is not dated" "$M" "$(undated '[0.18.0] - 2026-11-7')"
case_ "trailing text refused" 1 "is not dated" "$M" "$(undated '[0.18.0] - 2026-11-07 (draft)')"
case_ "TBD date refused" 1 "is not dated" "$M" "$(undated '[0.18.0] - TBD')"
case_ "impossible date refused" 1 "2026-02-30 is not a calendar date" "$M" "$(undated '[0.18.0] - 2026-02-30')"
case_ "month 13 refused" 1 "2026-13-01 is not a calendar date" "$M" "$(undated '[0.18.0] - 2026-13-01')"
case_ "non-leap 29 February refused" 1 "2100-02-29 is not a calendar date" "$M" "$(undated '[0.18.0] - 2100-02-29')"
case_ "leap 29 February passes" 0 "[0.18.0] - 2028-02-29" "$M" "$(undated '[0.18.0] - 2028-02-29')"

case_ "duplicate sections refused" 1 "has 2 sections for 0.18.0" "$M" "$HEAD
## [0.18.0] - 2026-11-07

- A thing.

## [0.18.0] - 2026-11-01

- The same thing, earlier."

case_ "section not newest refused" 1 "is not the newest" "$M" "$HEAD
## [0.19.0] - 2026-11-08

- A later thing.

## [0.18.0] - 2026-11-07

- A thing."

case_ "empty section refused" 1 "has no entries" "$M" "$HEAD
## [0.18.0] - 2026-11-07

### Added

## [0.17.0] - 2026-11-06

- An older thing."

case_ "stale internal pin refused" 1 "does not pin \"=0.18.0\": axess-core" "$(manifest 0.18.0 0.17.0)" "$RELEASED"
case_ "version prefix does not match a longer version" 1 "has no section for 0.1.0" "$(manifest 0.1.0)" "$RELEASED"
case_ "pre-release version passes" 0 "[1.0.0-rc.1] - 2026-11-07" "$(manifest 1.0.0-rc.1)" "$HEAD
## [1.0.0-rc.1] - 2026-11-07

- A candidate." --tag v1.0.0-rc.1
case_ "malformed workspace version refused" 1 "is not X.Y.Z" "$(manifest 0.18)" "$RELEASED"
case_ "unknown argument refused" 2 "unknown argument: --allow-dirty" "$M" "$RELEASED" --allow-dirty

echo "check-release-version: $passed passed, $failed failed."
[ "$failed" -eq 0 ]
