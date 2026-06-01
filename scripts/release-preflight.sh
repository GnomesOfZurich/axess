#!/usr/bin/env bash
# axess — fail-fast release preflight for maintainers.
#
# Runs the same local gates documented in docs/production/release.md, but as a
# numbered executable checklist so release validation is reproducible and less
# error-prone than copying a long command block out of markdown.
#
# Usage: ./scripts/release-preflight.sh [--allow-dirty]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ALLOW_DIRTY=false

while [ $# -gt 0 ]; do
  case "$1" in
    --allow-dirty) ALLOW_DIRTY=true; shift ;;
    -h|--help)
      sed -n '1,10p' "$0"
      exit 0
      ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

PACKAGE_ARGS=()
if [ "$ALLOW_DIRTY" = true ]; then
  PACKAGE_ARGS+=(--allow-dirty)
fi

step() {
  local number="$1"
  local label="$2"
  shift 2
  echo ""
  echo "[$number/8] $label"
  "$@"
}

step 1 "Format check" cargo fmt --manifest-path "$AXESS_DIR/Cargo.toml" --all -- --check
step 2 "Clippy" cargo clippy --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features --all-targets -- -D warnings
step 3 "Workspace tests" cargo test --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features
step 4 "Public docs build" cargo doc --manifest-path "$AXESS_DIR/Cargo.toml" --no-deps --all-features -p axess -p axess-core
step 5 "Supply-chain policy" cargo deny check licenses sources bans
step 6 "Semver checks" cargo semver-checks check-release --workspace

step 7 "Leaf crate publish dry-runs" bash -c '
  set -euo pipefail
  for c in axess-strings axess-clock axess-rng; do
    cargo publish --dry-run -p "$c"
  done
'

step 8 "Non-leaf package preflight" bash -c '
  set -euo pipefail
  package_args=("$@")
  for c in axess-identity axess-events axess-cache axess-factors axess-core axess-macros axess; do
    cargo package --list -p "$c" "${package_args[@]}" >/dev/null
  done
' bash "${PACKAGE_ARGS[@]}"

echo ""
echo "Release preflight: OK"