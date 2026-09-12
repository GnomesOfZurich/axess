#!/usr/bin/env bash
# axess: run every test pipeline and print one rolled-up summary.
#
# Pipelines:
#   1. Workspace lib tests (--all-features --lib): fast feedback
#   2. Workspace integration tests (--all-features --tests): covers
#      `tests/*.rs` in every workspace crate, including the example
#      crates (e.g. `examples/sqlite/tests/backend_tests.rs`). Without
#      this step, integration tests in example crates compile but
#      never run.
#   3. Workspace doc-tests (--all-features --doc): slower compilation
#   4. Workspace clippy with -D warnings
#   5. Workspace rustfmt --check (backgrounded from t=0)
#   6. Workspace rustdoc links, -D warnings (backgrounded from t=0)
#   0. Ban #[non_exhaustive] grep guard  (backgrounded from t=0)
#
# Design notes:
# - `set -uo pipefail` (no `-e`) so a failing step doesn't abort the
#   whole script. Every step runs every push; the summary lists all
#   failed steps. Matches CI's independent-verdict shape.
# - `pipefail` ensures `cmd | tee log` returns `cmd`'s exit code
#   instead of `tee`'s. Without it, every `run_step` reported PASS
#   even when the inner command failed.
# - `fmt --check` and the `ban_non_exhaustive` grep don't share the
#   cargo target directory, so they're kicked off in background at
#   t=0 and collected at the end. Saves their wall-time entirely.
# - Doc-tests and clippy each run with their own `CARGO_TARGET_DIR` so
#   they fan out alongside each other while lib+integration tests run in
#   the main `target/`. Trades extra disk for serious wall-clock savings.
#
# Usage: ./scripts/test-all.sh [--skip-clippy] [--skip-fmt] [--skip-doc]
#                              [--skip-rustdoc]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$AXESS_DIR/Cargo.toml"

SKIP_CLIPPY=false
SKIP_FMT=false
SKIP_DOC=false
SKIP_RUSTDOC=false

for arg in "$@"; do
  case "$arg" in
    --skip-clippy)   SKIP_CLIPPY=true ;;
    --skip-fmt)      SKIP_FMT=true ;;
    --skip-doc)      SKIP_DOC=true ;;
    --skip-rustdoc)  SKIP_RUSTDOC=true ;;
    -h|--help)       sed -n '1,16p' "$0"; exit 0 ;;
    *)               echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

PASS=0
FAIL=0
TOTAL=0
PASSED_TESTS=0
FAILED_TESTS=0
IGNORED=0
WARNINGS=0
ELAPSED_START=$SECONDS

declare -a FAILED_STEPS=()

# Backgrounded-step bookkeeping, parallel arrays indexed together.
declare -a BG_NAMES=()
declare -a BG_PIDS=()
declare -a BG_LOGS=()
declare -a BG_STARTS=()
declare -a BG_REQUIRE=()

tally_log() {
  local log="$1"
  local passed failed ign warn
  passed=$( (grep -oE '[0-9]+ passed' "$log" || true) | awk '{sum+=$1} END {print sum+0}')
  failed=$( (grep -oE '[0-9]+ failed' "$log" || true) | awk '{sum+=$1} END {print sum+0}')
  ign=$(    (grep -oE '[0-9]+ ignored' "$log" || true) | awk '{sum+=$1} END {print sum+0}')
  warn=$(   (grep -oE 'generated [0-9]+ warning' "$log" || true) | awk '{sum+=$2} END {print sum+0}')
  PASSED_TESTS=$((PASSED_TESTS + passed))
  FAILED_TESTS=$((FAILED_TESTS + failed))
  IGNORED=$((IGNORED + ign))
  WARNINGS=$((WARNINGS + warn))
}

# A step that requires tests must observe at least one. `tally_log` reads the
# runner's summary lines, so "PASS with nothing parsed" has two causes and both
# are failures: the invocation stopped selecting tests, or the runner's output
# format changed and the parser can no longer read it. Neither may report
# green, because a suite that runs zero tests proves nothing.
vacuity_check() {
  local name="$1" observed="$2"
  if [ "$observed" -eq 0 ]; then
    echo "ERROR: $name reported success but no test results were parsed." >&2
    echo "       Either the invocation selected zero tests, or the runner's" >&2
    echo "       output format changed and tally_log can no longer read it." >&2
    return 1
  fi
  return 0
}

run_step() {
  local name="$1"; local require_tests="$2"; local subset="$3"; shift 3
  TOTAL=$((TOTAL + 1))
  local t0=$SECONDS
  echo ""
  echo "== $name =="

  local log status observed before p0 f0 i0
  log=$(mktemp)
  if "$@" 2>&1 | tee "$log"; then status=0; else status=1; fi

  p0=$PASSED_TESTS; f0=$FAILED_TESTS; i0=$IGNORED
  before=$((PASSED_TESTS + FAILED_TESTS + IGNORED))
  tally_log "$log"
  observed=$(((PASSED_TESTS + FAILED_TESTS + IGNORED) - before))

  # `cargo test --tests` selects every target with `test = true`, which
  # includes the lib target --- so the `--lib` step is a strict subset of the
  # `--tests` step, verified by name: 0 of its 1238 tests are absent there.
  # It stays for fast feedback and can still fail the run, but counting it
  # would inflate the summary by a whole lib suite.
  if [ "$subset" = true ]; then
    PASSED_TESTS=$p0; FAILED_TESTS=$f0; IGNORED=$i0
  fi

  if [ "$status" -eq 0 ] && [ "$require_tests" = true ]; then
    vacuity_check "$name" "$observed" || status=1
  fi

  if [ "$status" -eq 0 ]; then
    printf -- '-- %s: PASS (%ds, %d tests)\n' "$name" $((SECONDS - t0)) "$observed"
    PASS=$((PASS + 1))
  else
    printf -- '-- %s: FAIL (%ds, %d tests)\n' "$name" $((SECONDS - t0)) "$observed"
    FAIL=$((FAIL + 1))
    FAILED_STEPS+=("$name")
  fi
  rm -f "$log"
}

# Kick off an independent step in background. Its output is held in a
# tempfile and replayed when `collect_bg_steps` runs at the end. Only
# use for steps that don't share the cargo target dir.
bg_step() {
  local name="$1"; local require_tests="$2"; shift 2
  local log
  log=$(mktemp)
  "$@" >"$log" 2>&1 &
  BG_NAMES+=("$name")
  BG_PIDS+=("$!")
  BG_LOGS+=("$log")
  BG_STARTS+=("$SECONDS")
  BG_REQUIRE+=("$require_tests")
}

collect_bg_steps() {
  local i name pid log start require status observed before
  for i in "${!BG_NAMES[@]}"; do
    name="${BG_NAMES[$i]}"
    pid="${BG_PIDS[$i]}"
    log="${BG_LOGS[$i]}"
    start="${BG_STARTS[$i]}"
    require="${BG_REQUIRE[$i]}"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "== $name (backgrounded from t=0) =="
    if wait "$pid"; then status=0; else status=1; fi
    cat "$log"

    before=$((PASSED_TESTS + FAILED_TESTS + IGNORED))
    tally_log "$log"
    observed=$(((PASSED_TESTS + FAILED_TESTS + IGNORED) - before))

    if [ "$status" -eq 0 ] && [ "$require" = true ]; then
      vacuity_check "$name" "$observed" || status=1
    fi

    if [ "$status" -eq 0 ]; then
      printf -- '-- %s: PASS (%ds, %d tests)\n' "$name" $((SECONDS - start))  "$observed"
      PASS=$((PASS + 1))
    else
      printf -- '-- %s: FAIL (%ds, %d tests)\n' "$name" $((SECONDS - start)) "$observed"
      FAIL=$((FAIL + 1))
      FAILED_STEPS+=("$name")
    fi
    rm -f "$log"
  done
}

# ── 0. ban #[non_exhaustive] in first-party Rust source ─────────────
# Mirrors the `ban_non_exhaustive` job in .github/workflows/ci.yml so the
# rule fails locally before push. Cheap (one grep): backgrounded.

bg_step "Ban #[non_exhaustive]" false bash -c '
  # Skip lines that are doc comments / line comments so prose mentioning
  # `#[non_exhaustive]` does not flag. Real attribute uses live on
  # code lines (optionally indented), not after `//` / `///` / `//!`.
  hits=$(grep -RIn --include="*.rs" \
      -e "#\[non_exhaustive\]" \
      -e "#\[ *non_exhaustive *\]" \
      axess axess-cache axess-clock axess-core axess-events axess-factors \
      axess-identity axess-macros axess-rng axess-strings examples \
      | grep -v ":[[:space:]]*//" || true)
  if [ -n "$hits" ]; then
    echo "$hits"
    echo "#[non_exhaustive] is forbidden in first-party crates." >&2
    echo "See ROADMAP.md / feedback_no_non_exhaustive memory." >&2
    exit 1
  fi
  echo "OK: no #[non_exhaustive] occurrences."
'

# ── 5. Fmt (backgrounded from t=0) ────────────────────────────────────
# `cargo fmt --check` reads source files and doesn't touch `target/`,
# so it can run alongside the heavy serial cargo steps without lock
# contention. Collected at the end with the ban grep.

if [ "$SKIP_FMT" = false ]; then
  bg_step "Workspace rustfmt --check" false \
    cargo fmt --manifest-path "$MANIFEST" --all -- --check
fi

# ── 1. Lib tests ──────────────────────────────────────────────────────────────

run_step "Workspace lib tests (--all-features)" true true \
  cargo test --manifest-path "$MANIFEST" --workspace --all-features --lib

# ── 2. Integration tests ─────────────────────────────────────────────────────
#
# Picks up every `tests/*.rs` in the workspace, including those in
# example crates. Pre-this-step, an example like
# `examples/sqlite/tests/backend_tests.rs` only compiled (via clippy
# `--all-targets`) but never ran, a regression in the example
# integration could land green. The lib step above only runs `--lib`
# unit tests; binary crates (every `examples/*`) have nothing under
# `--lib`, so their `tests/*.rs` files require a separate `--tests`
# invocation.
#
# Runs unconditionally (independent verdict): a lib-test failure
# doesn't tell us whether integration would have passed too.

run_step "Workspace integration tests (--all-features)" true false \
  cargo test --manifest-path "$MANIFEST" --workspace --all-features --tests

# ── 3. Doc-tests (backgrounded with isolated target dir) ─────────────────────
#
# Doc-tests share `target/debug` artifacts with steps 1+2, but routing them
# to their own `CARGO_TARGET_DIR=target/doctest` lets the compile + run
# phase fan out alongside clippy at the cost of one extra crate-build's
# worth of disk. Net wall-clock saving is the smaller of (doc-test time,
# clippy time). Doc-test compilation dominates a typical run; the bg
# pattern reclaims those minutes.

if [ "$SKIP_DOC" = false ]; then
  bg_step "Workspace doc-tests" true \
    env CARGO_TARGET_DIR="$AXESS_DIR/target/doctest" \
    cargo test --manifest-path "$MANIFEST" --workspace --all-features --doc
fi

# ── 4. Clippy (backgrounded with isolated target dir) ─────────────────────────
#
# Clippy invokes `clippy-driver` instead of `rustc`, which doesn't share its
# build cache with the regular `cargo test` artifacts anyway. Pinning a
# separate `CARGO_TARGET_DIR=target/clippy` removes the file-lock
# contention against steps 1+2 and lets clippy run in parallel with the
# doc-test step above.

if [ "$SKIP_CLIPPY" = false ]; then
  bg_step "Workspace clippy (-D warnings)" false \
    env CARGO_TARGET_DIR="$AXESS_DIR/target/clippy" \
    cargo clippy --manifest-path "$MANIFEST" --workspace --all-features --all-targets -- -D warnings
fi

# ── 6. Rustdoc links (backgrounded; the script isolates its own target dir) ──
#
# `cargo doc` ran nowhere in this script until 0.5.0, which is how the
# workspace came to carry 29 unresolved intra-doc links: rustdoc warnings are
# not compile errors and not test failures, so nothing read them. The script
# runs rustdoc with `-D warnings` and then proves it actually documented every
# workspace member: `cargo doc` prints nothing and exits 0 when the docs are
# already fresh, the same "green over nothing" shape the vacuity check above
# exists to reject.

if [ "$SKIP_RUSTDOC" = false ]; then
  bg_step "Workspace rustdoc links (-D warnings)" false \
    "$SCRIPT_DIR/check-doc-links.sh"
fi

# ── Speed-up note ─────────────────────────────────────────────────────────────
#
# `cargo-nextest` (https://nexte.st) typically runs the workspace test
# execution 2-3x faster than `cargo test` by using a process pool and smart
# scheduling. Drop-in replacement for steps 1 and 2:
#   cargo install cargo-nextest --locked
#   # then swap `cargo test ... --lib` → `cargo nextest run ... --lib`
# Not auto-detected here because nextest's output format differs from
# `cargo test` and the `tally_log` parser below would miscount.

# ── Collect backgrounded steps ────────────────────────────────────────────────

collect_bg_steps

# ── Summary ───────────────────────────────────────────────────────────────────

ELAPSED=$((SECONDS - ELAPSED_START))

echo ""
echo "══════════════════════════════════════════════════════════════════"
printf "  STEPS: %d/%d\n" "$PASS" "$TOTAL"
printf "  PASSED: %d   FAILED: %d   IGNORED: %d   WARNINGS: %d   (distinct; --lib is re-run by --tests and not double-counted)\n" "$PASSED_TESTS" "$FAILED_TESTS" "$IGNORED" "$WARNINGS"
printf "  TIME: %dm%02ds\n" "$((ELAPSED / 60))" "$((ELAPSED % 60))"
if [ ${#FAILED_STEPS[@]} -gt 0 ]; then
  echo ""
  echo "  FAILED STEPS:"
  printf "    - %s\n" "${FAILED_STEPS[@]}"
fi
echo "══════════════════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ] || [ "$FAILED_TESTS" -gt 0 ]; then
  exit 1
fi
