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
#   scripts/mutants-sweep.sh width EVENT
#       Print how many shards run at a time for a run the event started:
#       MUTANTS_WIDTH_RELEASE for `push` (a release commit on a release
#       branch), MUTANTS_WIDTH_SWEEP for every other event. mutants.yml sets
#       both at its top. Refuses either unset or not a whole number above 0.
#
#   scripts/mutants-sweep.sh live-plan [cargo-mutants filter args...]
#       List the mutants of the live-store modules (LIVE_VALKEY_FILES below)
#       that the filter selects and print `total=T`.
#
#   scripts/mutants-sweep.sh live OUT [cargo-mutants filter args...]
#       Run those mutants as one shard into OUT/mutants-shard-0, each against
#       the crate's lib tests whose name holds `valkey`, the ignored ones
#       included, on the Valkey that VALKEY_URL names. Refuses without
#       VALKEY_URL. Exit status as for `shard`.
#
# Every command that tests a mutant runs its tests with cargo-nextest
# (`cargo nextest run`) under the `mutants` profile of .config/nextest.toml,
# which stops at the first failing test: .cargo/mutants.toml sets both, so a
# run of this script, a plain `cargo mutants` and CI test a mutant alike, and
# cargo-nextest must be installed.
#
# Then `scripts/mutants-summary.py --shards N --expected-total T OUT` merges
# the shards and fails the sweep if any shard is missing, unfinished or short
# (`--shards 1` for the OUT of `live`).
#
# The live-store modules. A module whose tests need a running server has
# them behind `#[ignore]`, so a sweep without the server judges every one of
# its mutants on tests that do not run and reports each as missed. `plan`
# and `shard` leave these files out,
# and `live` judges them with the server up. Its baseline always runs, so a
# Valkey that does not answer fails the run instead of passing every mutant
# as missed.
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
#                           times the whole-workspace baseline (3354 s each,
#                           two of them in six hours, on a measured run).
#   --no-shuffle            the same mutants land in the same shard each week.
#
# Sizing. MUTANTS_PER_SHARD is 48, a provisional value for a release that
# reports the full sweep without requiring it, chosen to fit GitHub's
# matrix cap: the 0.20.0 workspace has 11771 mutants, which at 48 a shard
# make 246 shards, where 43 a shard made 274 and the plan refused. 48 was
# set without the measured per-mutant cost that the refusal in `plan` asks
# for before the size is raised. The measurements behind 43 stand, taken
# on ubuntu-latest from the outcomes.json of a full run under `cargo test`,
# before the sweep tested with cargo-nextest: an axess-core mutant cost
# about 113 s to build and 300 s to test when caught (its lib test binary
# ran all 1540 tests before reporting) and about 500 s to test when missed;
# an axess-factors mutant about 220 s; the small crates seconds. That
# averaged about 335 s a mutant over the workspace, so 43 a shard was about
# 4 h of mutants plus setup, against the 5 h the shard step allows and the
# 6 h a GitHub job allows. In the 0.19.0 sweep (203 shards of 43, under
# `cargo test`) the shard step took about 216 minutes at the median, 3
# shards ran into the 5 h step limit, and 23 ran longer than 269 minutes,
# which is 300 at 48 a shard. At that cost about one shard in nine at 48
# runs into the step limit, in its run and in its second run, which
# repeats the same mutants, and the sweep ends red. How much
# cargo-nextest's stop at the first failing test saves on a caught mutant
# is not yet measured; the outcomes of the shards that finish give that
# cost. Before the release workflow requires the sweep, a per-mutant cost
# measured under cargo-nextest replaces this value.

set -euo pipefail

MUTANTS_PER_SHARD="${MUTANTS_PER_SHARD:-48}"
MUTANTS_TEST_TIMEOUT="${MUTANTS_TEST_TIMEOUT:-1500}"
MUTANTS_BUILD_TIMEOUT="${MUTANTS_BUILD_TIMEOUT:-900}"
MUTANTS_BASELINE="${MUTANTS_BASELINE:-skip}"
MATRIX_CAP=256
LIVE_VALKEY_FILES=(axess-core/src/federation/valkey_logout.rs)
# The package those files are in, and the test selection, as nextest
# options: the lib tests of that package named `valkey`, ignored ones
# included, without the ones that need a cluster. They reach nextest through
# `--cargo-test-arg`, never after a `--`, which would also hand the options
# .cargo/mutants.toml adds (the profile) to the test binaries.
LIVE_VALKEY_PACKAGE=axess-core
LIVE_VALKEY_TESTS=(--run-ignored=all '--filterset=test(valkey) - test(valkey_cluster)')

# `--exclude F` for every live-store file, for `plan` and `shard`.
live_excludes() {
  local f
  for f in "${LIVE_VALKEY_FILES[@]}"; do
    printf '%s\n%s\n' --exclude "$f"
  done
}

# `--file F` for every live-store file, for `live-plan` and `live`.
live_files() {
  local f
  for f in "${LIVE_VALKEY_FILES[@]}"; do
    printf '%s\n%s\n' --file "$f"
  done
}

usage() {
  sed -n '2,30p' "$0" >&2
  exit 64
}

width() {
  [ "$#" -eq 1 ] || usage
  local name value
  case "$1" in
    push) name=MUTANTS_WIDTH_RELEASE ;;
    *) name=MUTANTS_WIDTH_SWEEP ;;
  esac
  value="${!name:-}"
  case "$value" in
    "" | *[!0-9]* | 0*)
      echo "error: $name is '$value'; it must be a whole number above 0 (set at the top of mutants.yml)" >&2
      exit 64
      ;;
  esac
  echo "$value"
}

plan() {
  local list total shards excludes=()
  while IFS= read -r arg; do excludes+=("$arg"); done < <(live_excludes)
  list="$(cargo mutants --list "${excludes[@]}" "$@")"
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
  local work dest status excludes=()
  while IFS= read -r arg; do excludes+=("$arg"); done < <(live_excludes)
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
    "${excludes[@]}" \
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

live_plan() {
  local list total files=()
  while IFS= read -r arg; do files+=("$arg"); done < <(live_files)
  list="$(cargo mutants --list "${files[@]}" "$@")"
  if [ -z "$list" ]; then
    total=0
  else
    total="$(printf '%s\n' "$list" | wc -l | tr -d ' ')"
  fi
  echo "total=$total"
}

live() {
  [ "$#" -ge 1 ] || usage
  local out="$1"
  shift
  if [ -z "${VALKEY_URL:-}" ]; then
    echo "error: live-store mutants NOT run: VALKEY_URL is unset. This is a refusal, not a" \
      "pass; start a Valkey (the recipe is at the top of scripts/check-live-stores.sh)." >&2
    exit 1
  fi
  local work dest status opt files=() tests=()
  while IFS= read -r arg; do files+=("$arg"); done < <(live_files)
  for opt in "${LIVE_VALKEY_TESTS[@]}"; do tests+=("--cargo-test-arg=$opt"); done
  work="$(mktemp -d "${TMPDIR:-/tmp}/mutants-live.XXXXXX")"
  dest="$out/mutants-shard-0"
  mkdir -p "$out"
  rm -rf "$dest"
  set +e
  cargo mutants \
    --baseline run \
    --timeout "$MUTANTS_TEST_TIMEOUT" \
    --build-timeout "$MUTANTS_BUILD_TIMEOUT" \
    --no-shuffle \
    --output "$work" \
    "${files[@]}" \
    "$@" \
    --test-package "$LIVE_VALKEY_PACKAGE" \
    --cargo-arg=--lib \
    "${tests[@]}"
  status=$?
  set -e
  if [ -d "$work/mutants.out" ]; then
    mv "$work/mutants.out" "$dest"
  fi
  rm -rf "$work"
  echo "$status" > "$out/mutants-shard-0.exit"
  case "$status" in
    0 | 2 | 3) exit 0 ;;
    *)
      echo "error: cargo-mutants exited $status on the live-store mutants: the run did not reach its end" >&2
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
  width) width "$@" ;;
  live-plan) live_plan "$@" ;;
  live) live "$@" ;;
  *) usage ;;
esac
