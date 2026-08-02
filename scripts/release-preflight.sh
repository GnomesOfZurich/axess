#!/usr/bin/env bash
# axess — fail-fast release preflight for maintainers.
#
# Runs the same local gates documented in docs/production/release.md, but as a
# numbered executable checklist so release validation is reproducible and less
# error-prone than copying a long command block out of markdown.
#
# Usage: ./scripts/release-preflight.sh [--allow-dirty] [--with-fuzz]
#
#   --allow-dirty  passed through to `cargo package` so package steps do not
#                  require a clean tree (still fails if a listed file is
#                  actually missing).
#   --with-fuzz    additionally runs the fuzz-smoke step (nightly toolchain +
#                  cargo-fuzz required; adds ~3-5 min warm, 15-20 min cold).
#                  Off by default because CI runs it on every PR anyway.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ALLOW_DIRTY=false
WITH_FUZZ=false

while [ $# -gt 0 ]; do
  case "$1" in
    --allow-dirty) ALLOW_DIRTY=true; shift ;;
    --with-fuzz) WITH_FUZZ=true; shift ;;
    -h|--help)
      sed -n '1,15p' "$0"
      exit 0
      ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

PACKAGE_ARGS=()
if [ "$ALLOW_DIRTY" = true ]; then
  PACKAGE_ARGS+=(--allow-dirty)
fi

TOTAL=10
if [ "$WITH_FUZZ" = true ]; then
  TOTAL=11
fi

step() {
  local number="$1"
  local label="$2"
  shift 2
  echo ""
  echo "[$number/$TOTAL] $label"
  "$@"
}

step 1 "Format check" cargo fmt --manifest-path "$AXESS_DIR/Cargo.toml" --all -- --check

# Mirrors the `Ban #[non_exhaustive]` CI job — see the docstring on that job
# in .github/workflows/ci.yml for the policy rationale (trade one breakage
# class for another; project prefers loud call-site breaks on variant add).
step 2 "Ban #[non_exhaustive]" bash -c '
  set -eu
  cd "$0"
  if grep -RIn --include="*.rs" \
      -e "#\[non_exhaustive\]" \
      -e "#\[ *non_exhaustive *\]" \
      axess axess-core axess-factors axess-macros examples; then
    echo "ERROR: #[non_exhaustive] is forbidden in first-party crates." >&2
    echo "See ROADMAP.md / feedback_no_non_exhaustive memory." >&2
    exit 1
  fi
  echo "OK: no #[non_exhaustive] occurrences."
' "$AXESS_DIR"

step 3 "Clippy" cargo clippy --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features --all-targets -- -D warnings
step 4 "Workspace tests" cargo test --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features
step 5 "Public docs build" cargo doc --manifest-path "$AXESS_DIR/Cargo.toml" --no-deps --all-features -p axess -p axess-core

# `cargo deny` covers bans / licenses / sources policy; `cargo audit` covers
# the RUSTSEC advisory database (CVSS 4.0 handling that cargo-deny 0.18.x
# doesn't do yet, per the note on the CI Security Audit job). Both gate the
# release: a deny hit or an unpatched advisory blocks the tag.
step 6 "Supply-chain policy (cargo deny)" cargo deny --manifest-path "$AXESS_DIR/Cargo.toml" check licenses sources bans
step 7 "Security advisories (cargo audit)" cargo audit --file "$AXESS_DIR/Cargo.lock" --deny warnings

step 8 "Semver checks" cargo semver-checks check-release --manifest-path "$AXESS_DIR/Cargo.toml" --workspace

step 9 "Leaf crate publish dry-runs" bash -c '
  set -euo pipefail
  cd "$0"
  for c in axess-strings axess-clock axess-rng; do
    cargo publish --dry-run -p "$c"
  done
' "$AXESS_DIR"

step 10 "Non-leaf package preflight" bash -c '
  set -euo pipefail
  cd "$0"
  shift
  package_args=("$@")
  for c in axess-identity axess-events axess-cache axess-factors axess-core axess-macros axess; do
    cargo package --list -p "$c" ${package_args[@]+"${package_args[@]}"} >/dev/null
  done
' "$AXESS_DIR" bash ${PACKAGE_ARGS[@]+"${PACKAGE_ARGS[@]}"}

# Fuzz smoke: opt-in because it needs a nightly toolchain + cargo-fuzz and
# takes several minutes even with warm caches. Off by default so the common
# preflight stays fast; the CI `Fuzz Smoke` job runs on every PR regardless.
if [ "$WITH_FUZZ" = true ]; then
  step 11 "Fuzz smoke (nightly)" bash -c '
    set -euo pipefail
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
      echo "ERROR: cargo-fuzz not installed. Run: cargo install cargo-fuzz --locked" >&2
      exit 1
    fi
    if ! rustup toolchain list | grep -q "^nightly"; then
      echo "ERROR: nightly toolchain not installed. Run: rustup install nightly" >&2
      exit 1
    fi
    cd "$0/fuzz"
    cargo +nightly fuzz build
    for target in session_data_msgpack session_data_json jwt_payload_split pkce_verifier_predicate; do
      cargo +nightly fuzz run "$target" -- -max_total_time=30
    done
  ' "$AXESS_DIR"
fi

echo ""
echo "Release preflight: OK"
