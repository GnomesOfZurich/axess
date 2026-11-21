#!/usr/bin/env bash
# axess: crafted cases for scripts/check-disk-floor.sh.
#
# The check asks df; here it asks a stand-in df, first on the PATH, that
# answers `df -Pk -- PATH` from files: the reading for a path stands in a
# file named after the path with each `/` written as `_`, and a path with
# no file of its own reads the file `default`, or fails as df fails on a
# path that does not exist when there is none.
#
# Usage: ./scripts/check-disk-floor-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-disk-floor.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

mkdir -p "$WORK/bin"
cat > "$WORK/bin/df" <<'EOF'
#!/usr/bin/env bash
if [ "$#" -ne 3 ] || [ "$1" != -Pk ] || [ "$2" != -- ]; then
  echo "stand-in df: not a call the check makes: $*" >&2
  exit 99
fi
file="$FAKE_DF/$(printf '%s' "$3" | tr / _)"
[ -f "$file" ] || file="$FAKE_DF/default"
if [ ! -f "$file" ]; then
  echo "df: $3: No such file or directory" >&2
  exit 1
fi
cat "$file"
EOF
chmod +x "$WORK/bin/df"

HEADER='Filesystem     1024-blocks     Used Available Capacity Mounted on'
GIB=1048576

# reading AVAILABLE_KIB MOUNT: the two lines df -Pk prints for one path.
reading() {
  printf '%s\n%s\n' "$HEADER" "/dev/root 76026616 30000000 $1 50% $2"
}

# case_ NAME WANTED_EXIT FRAGMENT UNWANTED READINGS ARG...
# READINGS is a `;`-separated list of `PATH=AVAILABLE_KIB:MOUNT` (PATH
# `default` for any path), or `PATH=raw:TEXT` for df output written out,
# with `\n` between its lines.
case_() {
  local name="$1" want="$2" fragment="$3" unwanted="$4" readings="$5"
  shift 5
  local dir="$WORK/df-$passed-$failed" specs=() spec path value out rc
  mkdir -p "$dir"
  [ -z "$readings" ] || IFS=';' read -r -a specs <<<"$readings"
  for spec in ${specs[@]+"${specs[@]}"}; do
    path="${spec%%=*}"
    value="${spec#*=}"
    if [ "${value%%:*}" = raw ]; then
      printf '%b\n' "${value#raw:}" > "$dir/$(printf '%s' "$path" | tr / _)"
    else
      reading "${value%%:*}" "${value#*:}" > "$dir/$(printf '%s' "$path" | tr / _)"
    fi
  done
  out="$(FAKE_DF="$dir" PATH="$WORK/bin:$PATH" GITHUB_ACTIONS="${CASE_GITHUB_ACTIONS:-}" \
    "$SCRIPT_DIR/check-disk-floor.sh" "$@" 2>"$WORK/stderr")"
  rc=$?
  judge "$name" "$want" "$fragment" "$rc" "$out" "$unwanted"
}

case_ "room above the floor passes and says how much" 0 \
  "OK: Test Suite: 41.0 GiB free on / (holding /work), at or above the floor of 10 GiB." "" \
  "/work=$((41 * GIB)):/" "Test Suite" 10 /work
case_ "a disk under the floor stops the job by name" 1 \
  "Test Suite stops for disk: 0.0 GiB free on / (holding /work), under the floor of 10 GiB." "OK:" \
  "/work=88064:/" "Test Suite" 10 /work
case_ "the refusal says why the job fails" 1 \
  "A test result read from a disk this full can be wrong, so the job fails here for disk." "" \
  "/work=88064:/" "Coverage" 20 /work
case_ "a reading after a step names that step and the floor after it" 1 \
  "Coverage, after the instrumented tests stops for disk: 1.5 GiB free on / (holding /work), under the floor of 2 GiB." "OK:" \
  "/work=$((3 * GIB / 2)):/" "Coverage, after the instrumented tests" 2 /work
case_ "room above the floor after a step passes" 0 \
  "OK: Test Suite, after the workspace tests: 2.0 GiB free on / (holding /work), at or above the floor of 2 GiB." "" \
  "/work=$((2 * GIB)):/" "Test Suite, after the workspace tests" 2 /work
case_ "exactly the floor passes" 0 \
  "OK: Coverage: 20.0 GiB free on /" "" \
  "/work=$((20 * GIB)):/" "Coverage" 20 /work
case_ "one KiB under the floor stops, and does not print as the floor" 1 \
  "19.9 GiB free on / (holding /work), under the floor of 20 GiB." "20.0 GiB free" \
  "/work=$((20 * GIB - 1)):/" "Coverage" 20 /work
case_ "two paths on one filesystem are read once" 0 \
  "OK: Test Suite: 30.0 GiB free on / (holding /work), at or above" "holding /tmp" \
  "/work=$((30 * GIB)):/;/tmp=$((30 * GIB)):/" "Test Suite" 10 /work /tmp
case_ "of two filesystems the one under the floor is named" 1 \
  "1.0 GiB free on /mnt (holding /tmp), under the floor of 10 GiB." "" \
  "/work=$((30 * GIB)):/;/tmp=$GIB:/mnt" "Test Suite" 10 /work /tmp
case_ "the filesystem that holds the floor is still reported beside a refusal" 1 \
  "OK: Test Suite: 30.0 GiB free on / (holding /work)" "" \
  "/work=$((30 * GIB)):/;/tmp=$GIB:/mnt" "Test Suite" 10 /work /tmp
case_ "a mount point with a space in it is named whole" 1 \
  "free on /Volumes/Build Disk (holding /work), under the floor" "" \
  "/work=raw:$HEADER\n/dev/disk4s1 976490576 976000000 490576 100% /Volumes/Build Disk" "Test Suite" 10 /work
case_ "with no path the current directory and the temporary directory are read" 0 \
  "OK: Test Suite: 12.0 GiB free on / (holding .), at or above the floor of 10 GiB." "" \
  "default=$((12 * GIB)):/" "Test Suite" 10
CASE_GITHUB_ACTIONS=true case_ "on GitHub Actions the refusal is an error annotation" 1 \
  "::error title=Disk floor::Mutants shard stops for disk: 2.0 GiB free on /" "REFUSED:" \
  "/work=$((2 * GIB)):/" "Mutants shard" 20 /work
case_ "a floor with leading zeros is read as decimal" 0 \
  "at or above the floor of 8 GiB." "" \
  "/work=$((9 * GIB)):/" "Test Suite" 08 /work
case_ "a fractional floor is refused" 2 \
  "the floor must be a whole number of GiB, not '8.5'." "" \
  "/work=$((9 * GIB)):/" "Test Suite" 8.5 /work
case_ "a floor of zero is refused" 2 \
  "the floor must be at least 1 GiB." "" \
  "/work=$((9 * GIB)):/" "Test Suite" 0 /work
case_ "an empty job name is refused" 2 \
  "no job named" "" \
  "/work=$((9 * GIB)):/" "" 10 /work
case_ "a path df cannot read is refused, not passed" 2 \
  "df gives no reading for /gone: df: /gone: No such file or directory" "OK:" \
  "" "Test Suite" 10 /gone
case_ "a reading with no number of free blocks is refused" 2 \
  "df gives no available space for /work:" "OK:" \
  "/work=raw:$HEADER\n/dev/root 76026616 30000000 - 50% /" "Test Suite" 10 /work
case_ "a reading with no mount point is refused" 2 \
  "df names no mount point for /work:" "OK:" \
  "/work=raw:$HEADER\n/dev/root 76026616 30000000 9000000 50%" "Test Suite" 10 /work
case_ "too few arguments are refused" 2 "usage:" "" "" "Test Suite"

total=$((passed + failed))
if [ "$failed" -ne 0 ]; then
  echo "FAIL: $failed of $total disk-floor case(s) failed." >&2
  exit 1
fi
echo "OK: $total disk-floor case(s) passed."
