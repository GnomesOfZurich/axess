#!/usr/bin/env bash
# axess — run clippy across the workspace (library crates + example crates).
#
# `cargo clippy --workspace --all-features --all-targets` from the repo
# root already covers everything because `examples/*` is in
# `[workspace] members`. This script is a thin convenience wrapper that
# defaults to `-D warnings` (mirroring `test-all.sh` step 2) and gives
# you a single PASS/FAIL line at the end, plus arg-passthrough for
# things like `--fix`.
#
# Extra arguments after `--` are forwarded to clippy, e.g.:
#
#   ./scripts/clippy-all.sh --allow-warnings -- --fix --allow-dirty
#   ./scripts/clippy-all.sh -- --no-default-features
#
# Usage: ./scripts/clippy-all.sh [--allow-warnings] [-- <extra clippy args>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DENY_WARNINGS=true
EXTRA_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --allow-warnings) DENY_WARNINGS=false; shift ;;
    --) shift; EXTRA_ARGS=("$@"); break ;;
    -h|--help)
      sed -n '1,22p' "$0"
      exit 0
      ;;
    *) echo "Unknown flag: $1 (use '--' to forward extra args to clippy)"; exit 1 ;;
  esac
done

CLIPPY_TAIL=()
if [ "$DENY_WARNINGS" = true ]; then
  CLIPPY_TAIL=(-- -D warnings)
fi

# `${arr[@]+"${arr[@]}"}` is the safe expansion under `set -u`: when the
# array is empty the substitution disappears entirely instead of erroring.
echo "== Clippy axess workspace =="
if cargo clippy \
    --manifest-path "$AXESS_DIR/Cargo.toml" \
    --workspace \
    --all-features \
    --all-targets \
    ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} \
    ${CLIPPY_TAIL[@]+"${CLIPPY_TAIL[@]}"} 2>&1; then
  echo ""
  echo "=============================="
  echo "  Clippy: OK"
  echo "=============================="
else
  echo ""
  echo "=============================="
  echo "  Clippy: FAIL"
  echo "=============================="
  exit 1
fi
