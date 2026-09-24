#!/usr/bin/env bash
# axess: fail-fast release preflight for maintainers.
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

# Derived, not declared. This number has desynced twice from the steps that
# actually run -- most recently when "Non-leaf package preflight" landed and
# left the denominator at 13, which failed the guard at the bottom and so
# failed the whole release gate on bookkeeping rather than on a real check.
# Counting the invocations keeps it honest; the guard below stays as a
# backstop for the case this grep cannot see.
TOTAL=$(grep -cE '^[[:space:]]*step "' "$SCRIPT_DIR/release-preflight.sh")
if [ "$WITH_FUZZ" != true ]; then
  # The fuzz smoke step is the one conditional invocation.
  TOTAL=$((TOTAL - 1))
fi

# Steps number themselves. Hand-written ordinals silently desync the moment a
# step is inserted, renumbered or reordered: adding step 2 once shifted the
# non-leaf package step onto 11, which the fuzz step already used, so
# `--with-fuzz` printed "[11/12]" twice with no other symptom.
STEP_NO=0

step() {
  local label="$1"
  shift
  STEP_NO=$((STEP_NO + 1))
  echo ""
  echo "[$STEP_NO/$TOTAL] $label"
  "$@"
}

step "Format check" cargo fmt --manifest-path "$AXESS_DIR/Cargo.toml" --all -- --check

# Sub-second, so it runs before the expensive gates: a stale snippet should
# stop the release immediately, not after a 40-minute test run. Docs carry
# copy-pasteable `axess = { version = "..." }` blocks that nothing else keeps
# in step with the workspace version, and a reader landing on a crate README
# from crates.io or the GitHub tree view will pin whatever it says.
step "Documented versions" "$AXESS_DIR/scripts/check-doc-versions.sh"

# Also sub-second, and the only gate that reads the book. 108 of its 112
# Rust blocks are ```rust,ignore, so a chapter can name a type that does
# not exist and every other check stays green; one sweep found 59 such
# names, including an import in the getting-started tutorial.
step "Documented identifiers" "$AXESS_DIR/scripts/check-doc-identifiers.sh"

# Also sub-second. Guards the AGENTS.md rule that an inline `#[cfg(test)]`
# block over ~200 lines moves to a sibling file: 24 blocks had drifted past
# it before the rule was enforced rather than remembered.
step "Inline test block sizes" "$AXESS_DIR/scripts/check-inline-tests.sh"

# Sub-second too, and the only gate that reads Markdown. `check-doc-links.sh`
# runs rustdoc and sees Rust intra-doc links; nothing saw the READMEs, which
# is how a crates.io front page came to link at a chapter that had moved.
step "Markdown links resolve" "$AXESS_DIR/scripts/check-markdown-links.sh"

# Also sub-second. The 0.6.0 language pass removed every em dash and nothing
# preserved the result: a later documentation sweep reintroduced 101 of them
# across nineteen files with every gate green.
step "Prose style" "$AXESS_DIR/scripts/check-prose-style.sh"


# Mirrors the `Ban #[non_exhaustive]` CI job: see the docstring on that job
# in .github/workflows/ci.yml for the policy rationale (trade one breakage
# class for another; project prefers loud call-site breaks on variant add).
step "Ban #[non_exhaustive]" bash -c '
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

step "Clippy" cargo clippy --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features --all-targets -- -D warnings
step "Workspace tests" cargo test --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features
# Was `cargo doc -p axess -p axess-core` with warnings allowed, which is how 29
# unresolved intra-doc links reached 0.5.0: it documented two crates of
# eighteen and treated the warnings as advice. The script covers the whole
# workspace under -D warnings and proves it documented every member.
step "Public docs build (rustdoc links)" "$AXESS_DIR/scripts/check-doc-links.sh"

# Expensive (a second full build on the MSRV toolchain), so it sits after the
# cheap gates and the main test run. It belongs in the release gate rather than
# in test-all.sh: `rust-version` is a promise to adopters, and the moment to
# check a promise is before publishing it.
step "MSRV build + lib tests" "$AXESS_DIR/scripts/check-msrv.sh"

# `cargo deny` covers bans / licenses / sources policy; `cargo audit` covers
# the RUSTSEC advisory database (CVSS 4.0 handling that cargo-deny 0.18.x
# doesn't do yet, per the note on the CI Security Audit job). Both gate the
# release: a deny hit or an unpatched advisory blocks the tag.
step "Supply-chain policy (cargo deny)" cargo deny --manifest-path "$AXESS_DIR/Cargo.toml" check licenses sources bans
step "Security advisories (cargo audit)" cargo audit --file "$AXESS_DIR/Cargo.lock" --deny warnings

# A pass here is a floor, not a ceiling. cargo-semver-checks has no lint for a
# public struct field changing type (255 lints as of 0.50.0; the nearest are
# `struct_pub_field_missing` and the struct-to-enum conversions), so a change
# like `pub client_secret: String` -> `ZeroizedString` is breaking and still
# reports "no semver update required" against a real baseline. Read a green
# step as "none of the covered classes regressed", and keep documenting
# breaking changes in CHANGELOG.md by hand.
#
# The tool also reads rustdoc JSON and supports only a narrow range of format
# versions: an "unsupported rustdoc format vNN" failure here means
# cargo-semver-checks is older than the pinned toolchain, not that the code
# broke. Fix with `cargo install cargo-semver-checks --locked`.
step "Semver checks" cargo semver-checks check-release --manifest-path "$AXESS_DIR/Cargo.toml" --workspace

step "Leaf crate publish dry-runs" bash -c '
  set -euo pipefail
  cd "$0"
  shift
  publish_args=("$@")
  for c in axess-strings axess-clock axess-rng; do
    cargo publish --dry-run -p "$c" ${publish_args[@]+"${publish_args[@]}"}
  done
' "$AXESS_DIR" bash ${PACKAGE_ARGS[@]+"${PACKAGE_ARGS[@]}"}

step "Non-leaf package preflight" bash -c '
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
  step "Fuzz smoke (nightly)" bash -c '
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

# TOTAL is still declared by hand (the fuzz step is conditional), so make a
# mismatch loud rather than letting the denominator quietly lie.
if [ "$STEP_NO" -ne "$TOTAL" ]; then
  echo "ERROR: ran $STEP_NO steps but TOTAL claims $TOTAL. Update TOTAL." >&2
  exit 1
fi

echo ""
echo "Release preflight: OK"
