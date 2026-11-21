#!/usr/bin/env bash
# axess: crafted cases for scripts/check-file-sizes.sh.
#
# Each case builds a small git tree with a copy of the gate, a Rust file and
# the files under test, runs the gate there and asserts the exit status and
# a fragment of the output.
#
# Usage: ./scripts/check-file-sizes-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="${GATE:-$SCRIPT_DIR/check-file-sizes.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-file-sizes.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# lines N TEXT: N lines of TEXT.
lines() { local i; for ((i = 0; i < $1; i++)); do printf '%s\n' "$2"; done; }

# case_ NAME EXPECTED_EXIT FRAGMENT FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3"
  shift 3
  local dir="$WORK/$passed-$failed"
  mkdir -p "$dir/scripts" "$dir/src"
  cp "$GATE" "$dir/scripts/check-file-sizes.sh"
  printf '# baseline\n' > "$dir/scripts/file-size-baseline.txt"
  printf 'fn main() {\n    println!("ok");\n}\n' > "$dir/src/main.rs"
  printf 'helper() {\n  true\n}\n' > "$dir/scripts/helper.sh"
  while [ $# -gt 0 ]; do
    mkdir -p "$(dirname "$dir/$1")"
    printf '%s\n' "$2" > "$dir/$1"
    shift 2
  done
  git -C "$dir" init -q && git -C "$dir" add -A
  local out status
  out="$("$dir/scripts/check-file-sizes.sh" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$dir"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

case_ "a tree within the limits passes" 0 "OK: no new offenders" scripts/x.sh "$(lines 10 'echo x')"
case_ "a shell file over the limit is refused" 1 "801 lines  file scripts/cases.sh (limit 800, not in the baseline)" scripts/cases.sh "$(lines 801 'echo x')"
case_ "a Python file over the limit is refused" 1 "801 lines  file scripts/lib/x.py (limit 800, not in the baseline)" scripts/lib/x.py "$(lines 801 'x = 1')"
case_ "a shell file at the limit passes" 0 "OK: no new offenders" scripts/cases.sh "$(lines 800 'echo x')"
case_ "a shell function over the limit is refused" 1 "152 lines  fn scripts/long.sh::long (limit 150, not in the baseline)" scripts/long.sh "long() {
$(lines 150 '  echo x')
}"
case_ "a Python function over the limit is refused" 1 "151 lines  fn scripts/long.py::long (limit 150, not in the baseline)" scripts/long.py "def long():
$(lines 150 '    x = 1')"
case_ "a shell function at the limit passes" 0 "OK: no new offenders" scripts/long.sh "long() {
$(lines 148 '  echo x')
}"

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
listed "$GATE" "an untracked file is measured" 1 "801 lines  file scripts/new.sh (limit 800, not in the baseline)" "ignored.sh" \
  scripts/file-size-baseline.txt '# baseline' src/main.rs 'fn main() {}' \
  scripts/new.sh "$(lines 801 'echo x')" scripts/ignored.sh "$(lines 801 'echo x')"
listed "$GATE" "an ignored file is not measured" 0 "OK: no new offenders" "ignored.sh" \
  scripts/file-size-baseline.txt '# baseline' src/main.rs 'fn main() {}' scripts/ignored.sh "$(lines 801 'echo x')"

echo "check-file-sizes tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
