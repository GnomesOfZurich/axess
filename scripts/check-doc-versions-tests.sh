#!/usr/bin/env bash
# axess: crafted cases for scripts/check-doc-versions.sh.
#
# Each case builds a small git tree with a copy of the check, a workspace
# manifest at 0.20.0 and the documents under test, runs the check there and
# asserts the exit status and a fragment of the output.
#
# Usage: ./scripts/check-doc-versions-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="${GATE:-$SCRIPT_DIR/check-doc-versions.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-doc-versions.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case_ NAME EXPECTED_EXIT FRAGMENT FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3"
  shift 3
  local dir="$WORK/$passed-$failed"
  mkdir -p "$dir/scripts"
  cp "$GATE" "$dir/scripts/check-doc-versions.sh"
  printf '[workspace.package]\nversion = "0.20.0"\nrust-version = "1.95.0"\n' > "$dir/Cargo.toml"
  printf '# axess\n\nMSRV `1.95.0`.\n\n```toml\naxess = "0.20"\n```\n' > "$dir/README.md"
  while [ $# -gt 0 ]; do
    mkdir -p "$(dirname "$dir/$1")"
    printf '%s\n' "$2" > "$dir/$1"
    shift 2
  done
  git -C "$dir" init -q && git -C "$dir" add -A
  local out status
  out="$("$dir/scripts/check-doc-versions.sh" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$dir"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

case_ "snippets at the workspace version pass" 0 "OK: all 1 documented dependency snippets are compatible with 0.20."
case_ "a stale snippet is refused" 1 'docs/guide.md:1: axess = "0.19" (want 0.20)' docs/guide.md 'axess = "0.19"'
case_ "a migrating page that names the version it moves to passes" 0 "OK: all 2 documented dependency snippets" \
  docs/production/migrating/0.18.0-to-0.19.0.md 'Take `axess-testing = "0.19"` as a dev-dependency.'
case_ "a migrating page held to the current release is refused" 1 'axess-testing = "0.20" (want 0.19)' \
  docs/production/migrating/0.18.0-to-0.19.0.md 'Take `axess-testing = "0.20"` as a dev-dependency.'
case_ "an early migrating page keeps its own version" 0 "OK: all 2 documented dependency snippets" \
  docs/production/migrating/0.6.0-to-0.7.0.md 'axess = { version = "0.7", features = ["request-id"] }'
case_ "a migrating page from a patch line is held to its target" 1 'axess = "0.2.0" (want 0.3)' \
  docs/production/migrating/0.2.2-to-0.3.0.md 'axess = "0.2.0"'
case_ "a migrating page whose name gives no target is refused" 1 "a migrating page whose name gives no X.Y.Z it moves to" \
  docs/production/migrating/0.19.0-to-next.md 'axess = "0.20"'

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
MANIFEST='[workspace.package]
version = "0.20.0"
rust-version = "1.95.0"'
README='# axess

MSRV `1.95.0`.

```toml
axess = "0.20"
```'
listed "$GATE" "an untracked page is read" 1 'docs/new.md:1: axess = "0.19" (want 0.20)' "ignored.md" \
  Cargo.toml "$MANIFEST" README.md "$README" docs/new.md 'axess = "0.19"' docs/ignored.md 'axess = "0.19"'
listed "$GATE" "an ignored page is not read" 0 "OK: all 1 documented dependency snippets are compatible with 0.20." "ignored.md" \
  Cargo.toml "$MANIFEST" README.md "$README" docs/ignored.md 'axess = "0.19"'

echo "check-doc-versions tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
