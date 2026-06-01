#!/usr/bin/env bash
# axess — format every Rust crate in the workspace (library + examples).
#
# `cargo fmt --all` from the repo root already covers everything because
# `examples/*` is in `[workspace] members`. This script is a thin
# convenience wrapper that adds a `--check` mode shortcut and forwards
# any extra args to `cargo fmt`.
#
#   ./scripts/fmt-all.sh           # rewrite to canonical form
#   ./scripts/fmt-all.sh --check   # exit non-zero on drift, no edits
#
# Usage: ./scripts/fmt-all.sh [--check] [-- <extra cargo fmt args>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CHECK=false
EXTRA_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=true; shift ;;
    --) shift; EXTRA_ARGS=("$@"); break ;;
    -h|--help)
      sed -n '1,18p' "$0"
      exit 0
      ;;
    *) echo "Unknown flag: $1 (use '--' to forward extra args to cargo fmt)"; exit 1 ;;
  esac
done

FMT_TAIL=()
if [ "$CHECK" = true ]; then
  FMT_TAIL=(-- --check)
fi

# `${arr[@]+"${arr[@]}"}` is the safe expansion under `set -u`: when the
# array is empty the substitution disappears entirely.
echo "== fmt axess workspace =="
if cargo fmt \
    --manifest-path "$AXESS_DIR/Cargo.toml" \
    --all \
    ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} \
    ${FMT_TAIL[@]+"${FMT_TAIL[@]}"}; then
  echo ""
  echo "=============================="
  echo "  fmt: OK"
  echo "=============================="
else
  echo ""
  echo "=============================="
  echo "  fmt: FAIL"
  echo "=============================="
  exit 1
fi
