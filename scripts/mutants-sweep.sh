#!/usr/bin/env bash
# axess: the sharded mutation sweep, as CI runs it and as you can run it here.
#
#   scripts/mutants-sweep.sh plan [cargo-mutants filter args...]
#       List the mutants the filter selects (none: the whole workspace) and
#       print `total=T` and `shards=N`, with N = ceil(T / MUTANTS_PER_SHARD).
#       Refuses an N above 256, GitHub's cap on one matrix, by name.
#
#   scripts/mutants-sweep.sh shard K N OUT [cargo-mutants filter args...]
#       Run shard K of N (0-based) into OUT/mutants-shard-K and write the
#       cargo-mutants exit status to OUT/mutants-shard-K.exit. Exits 0 when
#       the shard ran to its end (cargo-mutants 0, 2 for missed mutants, 3
#       for timeouts: those are results, judged by mutants-summary.py), and
#       with cargo-mutants' own status otherwise.
#
# Then `scripts/mutants-summary.py --shards N --expected-total T OUT` merges
# the shards and fails the sweep if any shard is missing, unfinished or short.
#
# The flags every shard runs with, and why:
#
#   --sharding round-robin  mutant i goes to shard i % N, so every shard gets
#                           the same mix of axess-core (slow) and the small
#                           crates (fast); the default slices would give some
#                           shards nothing but axess-core.
#   --baseline skip         the full sweep runs the unmutated suite once in
#                           its own job instead of once per shard
#                           (MUTANTS_BASELINE=run keeps it in the shard, as a
#                           pull request's single shard does).
#   --timeout / --build-timeout
#                           a hung mutant costs at most this, instead of five
#                           times the whole-workspace baseline (3354 s each on
#                           the 2026-11-01 run, two of them in six hours).
#   --no-shuffle            the same mutants land in the same shard each week.
#
# Sizing, measured on ubuntu-latest from the 2026-11-01 run's outcomes.json:
# an axess-core mutant costs about 113 s to build and 300 s to test when
# caught (its lib test binary runs all 1540 tests before reporting) and about
# 500 s to test when missed; an axess-factors mutant about 220 s; the small
# crates seconds. That averages about 335 s a mutant over the workspace, so
# 43 a shard is about 4 h of mutants plus setup, inside the 5 h the shard
# step allows and the 6 h a GitHub job allows.

set -euo pipefail

MUTANTS_PER_SHARD="${MUTANTS_PER_SHARD:-43}"
MUTANTS_TEST_TIMEOUT="${MUTANTS_TEST_TIMEOUT:-1500}"
MUTANTS_BUILD_TIMEOUT="${MUTANTS_BUILD_TIMEOUT:-900}"
MUTANTS_BASELINE="${MUTANTS_BASELINE:-skip}"
MATRIX_CAP=256

usage() {
  sed -n '2,15p' "$0" >&2
  exit 64
}

plan() {
  local list total shards
  list="$(cargo mutants --list "$@")"
  if [ -z "$list" ]; then
    total=0
  else
    total="$(printf '%s\n' "$list" | wc -l | tr -d ' ')"
  fi
  shards=$(((total + MUTANTS_PER_SHARD - 1) / MUTANTS_PER_SHARD))
  if [ "$shards" -gt "$MATRIX_CAP" ]; then
    echo "error: $total mutants at $MUTANTS_PER_SHARD a shard need $shards shards," \
      "over GitHub's matrix cap of $MATRIX_CAP; raise MUTANTS_PER_SHARD only with" \
      "a measured per-mutant cost that keeps a shard inside its time limit." >&2
    exit 1
  fi
  echo "total=$total"
  echo "shards=$shards"
}

shard() {
  [ "$#" -ge 3 ] || usage
  local k="$1" n="$2" out="$3"
  shift 3
  case "$k$n" in *[!0-9]*) echo "error: shard index and count must be numbers" >&2; exit 64 ;; esac
  if [ "$k" -ge "$n" ]; then
    echo "error: shard $k does not exist in $n shards (0-based)" >&2
    exit 64
  fi
  local work dest status
  work="$(mktemp -d "${TMPDIR:-/tmp}/mutants-shard-$k.XXXXXX")"
  dest="$out/mutants-shard-$k"
  mkdir -p "$out"
  rm -rf "$dest"
  set +e
  cargo mutants \
    --shard "$k/$n" \
    --sharding round-robin \
    --baseline "$MUTANTS_BASELINE" \
    --timeout "$MUTANTS_TEST_TIMEOUT" \
    --build-timeout "$MUTANTS_BUILD_TIMEOUT" \
    --no-shuffle \
    --output "$work" \
    "$@"
  status=$?
  set -e
  if [ -d "$work/mutants.out" ]; then
    mv "$work/mutants.out" "$dest"
  fi
  rm -rf "$work"
  echo "$status" > "$out/mutants-shard-$k.exit"
  case "$status" in
    0 | 2 | 3) exit 0 ;;
    *)
      echo "error: cargo-mutants exited $status on shard $k/$n: the shard did not run to its end" >&2
      exit "$status"
      ;;
  esac
}

[ "$#" -ge 1 ] || usage
cmd="$1"
shift
case "$cmd" in
  plan) plan "$@" ;;
  shard) shard "$@" ;;
  *) usage ;;
esac
