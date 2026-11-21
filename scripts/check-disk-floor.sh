#!/usr/bin/env bash
# axess: a job fails for disk, by name, when the room on a filesystem it
# writes to is under a floor before or after the step that runs its tests.
#
# A build or a test run that meets a full disk does not always fail as one.
# trybuild judges a compile-fail case by the compiler messages cargo printed
# for it and by nothing else: a case with no error message counts as
# compiled, and cargo's exit status and its error stream are dropped. A
# cargo that a full disk stops before the compiler reports on the case
# prints no message for it, so trybuild reports the case as one that
# compiled ("Expected test case to fail to compile, but it succeeded").
# A `compile_fail` doctest passes on any compile error, so a build a full
# disk stops reads as a pass. cargo-mutants reads a build that failed for
# want of space as an unviable mutant, and a test that failed for it as a
# caught one.
#
# So a job that builds the workspace with every feature reads the room twice
# around the step that runs its tests. Before the step, the floor is what
# the step writes, with margin, as the workflow that calls this says; a run
# under it stops before a test runs. After the step, whatever its end
# (`if: always()`), the floor is 2 GiB. Nearly all that the step wrote is
# still on disk when it ends: the target directory, trybuild's target
# directory, the profile data of an instrumented run and the data of the
# services. So the reading after the step is close to the least room the
# step had, and a step that wrote more than the floor before it allowed and
# came near full fails by name, whatever its tests reported. What the
# reading after the step misses is what the step wrote and removed again
# before it ended: the doctest binaries rustdoc builds, runs and deletes,
# the copy of the tree cargo-mutants builds in, and the part of a file a
# write cut short. The 2 GiB are the margin for those. A shard of
# cargo-mutants that fails the reading after its run uploads no outcomes,
# so its mutants are judged again or the sweep is refused, by shard.
#
# Each PATH is a directory the job writes under: the workspace, which holds
# the target directory, and the temporary directory, where rustdoc builds
# the doctests and cargo-mutants copies the tree. Two on one filesystem are
# read once. The free space is the space df reports as available, which on
# ext4 leaves out the blocks reserved for root: the job's user cannot write
# those. Each reading prints the free space it read, so every run measures
# the room its job had at that point.
#
# Usage: ./scripts/check-disk-floor.sh JOB FLOOR_GIB [PATH...]
#   JOB        the job and the step the reading is before or after, for
#              the message
#   FLOOR_GIB  the floor, a whole number of GiB, at least 1
#   PATH       a directory whose filesystem must hold the floor
#              (default: the current directory and ${TMPDIR:-/tmp})
#
# Exit status: 0 when every filesystem holds the floor, 1 when one does
# not, 2 when the arguments are wrong or df gives no reading. On GitHub
# Actions (GITHUB_ACTIONS=true) a refusal is written as an error
# annotation, so it stands on the summary page of the run.
# scripts/check-disk-floor-tests.sh holds the crafted cases.

set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 JOB FLOOR_GIB [PATH...]" >&2
  exit 2
fi
job="$1"
floor="$2"
shift 2
if [ -z "$job" ]; then
  echo "REFUSED: no job named; the message of a refusal names the job." >&2
  exit 2
fi
case "$floor" in
  '' | *[!0-9]*)
    echo "REFUSED: the floor must be a whole number of GiB, not '$floor'." >&2
    exit 2
    ;;
esac
floor=$((10#$floor))
if [ "$floor" -lt 1 ]; then
  echo "REFUSED: the floor must be at least 1 GiB." >&2
  exit 2
fi
[ $# -gt 0 ] || set -- . "${TMPDIR:-/tmp}"
floor_kib=$((floor * 1024 * 1024))

# KiB as GiB with one decimal, rounded down, so a reading one KiB under the
# floor never prints as the floor itself.
gib() {
  awk -v kib="$1" 'BEGIN { printf "%.1f", int(kib * 10 / 1048576) / 10 }'
}

seen=()
low=0
for path in "$@"; do
  if ! reading="$(df -Pk -- "$path" 2>&1)"; then
    echo "REFUSED: df gives no reading for $path: $reading" >&2
    exit 2
  fi
  # POSIX output: a header, then the filesystem, its size, used, available,
  # capacity, and the mount point, which is the rest of the line.
  line="$(awk 'NR == 2' <<<"$reading")"
  avail="$(awk '{ print $4 }' <<<"$line")"
  mount="$(awk '{ for (i = 6; i <= NF; i++) printf "%s%s", $i, (i < NF ? " " : "") }' <<<"$line")"
  case "$avail" in
    '' | *[!0-9]*)
      echo "REFUSED: df gives no available space for $path:" >&2
      printf '%s\n' "$reading" | sed 's/^/    /' >&2
      exit 2
      ;;
  esac
  if [ -z "$mount" ]; then
    echo "REFUSED: df names no mount point for $path:" >&2
    printf '%s\n' "$reading" | sed 's/^/    /' >&2
    exit 2
  fi
  repeat=no
  for m in ${seen[@]+"${seen[@]}"}; do
    [ "$m" = "$mount" ] && repeat=yes
  done
  [ "$repeat" = yes ] && continue
  seen+=("$mount")
  free="$(gib "$avail")"
  if [ "$avail" -lt "$floor_kib" ]; then
    low=$((low + 1))
    message="$job stops for disk: $free GiB free on $mount (holding $path), under the floor of $floor GiB. A test result read from a disk this full can be wrong, so the job fails here for disk."
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
      echo "::error title=Disk floor::$message" >&2
    else
      echo "REFUSED: $message" >&2
    fi
  else
    echo "OK: $job: $free GiB free on $mount (holding $path), at or above the floor of $floor GiB."
  fi
done
[ "$low" -eq 0 ] || exit 1
