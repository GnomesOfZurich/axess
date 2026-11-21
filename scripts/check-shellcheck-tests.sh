#!/usr/bin/env bash
# axess: crafted cases for scripts/check-shellcheck.sh.
#
# Each case writes files into a fresh git work tree under a temporary
# root, adds the ones it names to the index (the rest stay untracked), runs
# the check on that tree and asserts the exit status and a fragment of the
# output. The cases that read scripts run the ShellCheck on PATH, so they
# need the version scripts/install-shellcheck.sh pins, as the check itself
# does; the cases about the program run against stand-ins on a PATH of their
# own.
#
# Usage: ./scripts/check-shellcheck-tests.sh

# The cases hold shell text as data: a dollar sign in single quotes is
# meant as written.
# shellcheck disable=SC2016
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="${CHECK:-$SCRIPT_DIR/check-shellcheck.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-shellcheck.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

passed=0
failed=0
n=0

# tree [--untracked FILE CONTENT] FILE CONTENT [FILE CONTENT...]: a fresh
# work tree holding the files, every one in the index but those after
# --untracked; its path is in $tree.
tree() {
  n=$((n + 1))
  tree="$WORK/tree-$n"
  mkdir -p "$tree"
  git -C "$tree" -c init.defaultBranch=main init -q
  local track=yes
  while [ $# -gt 0 ]; do
    if [ "$1" = --untracked ]; then
      track=no
      shift
      continue
    fi
    mkdir -p "$(dirname "$tree/$1")"
    printf '%s\n' "$2" > "$tree/$1"
    [ "$track" = yes ] && git -C "$tree" add -- "$1"
    shift 2
  done
}

# case_ NAME EXPECTED_EXIT FRAGMENT [tree arguments...]
case_() {
  local name="$1" want="$2" fragment="$3"
  shift 3
  tree "$@"
  local out status
  out="$("$CHECK" "$tree" 2>"$WORK/stderr")"
  status=$?
  judge "$name" "$want" "$fragment" "$status" "$out"
}

OK='#!/usr/bin/env bash
set -eu
echo "ok"'

case_ "a script with nothing to report passes" 0 "OK: 1 shell scripts pass" \
  scripts/ok.sh "$OK"

# A directive in front of one branch of a case is a parse error: ShellCheck
# takes directives only in front of whole commands.
case_ "a directive in front of a case branch is refused" 1 "SC1124" \
  scripts/branches.sh '#!/usr/bin/env bash
here="$(dirname "$0")"
case "$1" in
  # shellcheck source=one.sh
  one) . "$here/one.sh" ;;
esac' \
  scripts/one.sh '# shellcheck shell=bash
echo one'
case_ "one directive in front of the case passes" 0 "OK: 2 shell scripts pass" \
  scripts/branches.sh '#!/usr/bin/env bash
here="$(dirname "$0")"
# shellcheck source-path=SCRIPTDIR
case "$1" in
  one) . "$here/one.sh" ;;
esac' \
  scripts/one.sh '# shellcheck shell=bash
echo one'

case_ "a warning is refused" 1 "SC2164" \
  scripts/cd.sh '#!/usr/bin/env bash
cd "$1"
echo here'
case_ "an info finding alone passes" 0 "OK: 1 shell scripts pass" \
  scripts/info.sh '#!/usr/bin/env bash
echo $1'

case_ "a sourced file that is not there is refused" 1 "SC1091" \
  scripts/main.sh '#!/usr/bin/env bash
here="$(dirname "$0")"
. "$here/lib/missing.sh"'
case_ "a sourced file is looked for beside the script that sources it" 0 "OK: 2 shell scripts pass" \
  scripts/main.sh '#!/usr/bin/env bash
here="$(dirname "$0")"
. "$here/lib/vars.sh"
echo "$greeting"' \
  scripts/lib/vars.sh '# shellcheck shell=bash disable=SC2034
greeting=hello'

case_ "a script named by its first line alone is read" 1 "In tools/run line 2" \
  tools/run '#!/bin/sh
cd "$1"
echo here'
case_ "a script that names its shell after env -S is read" 1 "SC2034" \
  tools/run '#!/usr/bin/env -S bash -e
unused=1'
case_ "a sourced file named by its directive alone is read" 1 "In lib/env line 2" \
  lib/env '# shellcheck shell=bash
cd "$1"'
case_ "a script deep in the tree is read" 1 "In a/b/c.sh line 2" \
  scripts/ok.sh "$OK" a/b/c.sh '#!/usr/bin/env bash
cd "$1"'
case_ "a program in another language is not read" 0 "OK: 1 shell scripts pass" \
  scripts/ok.sh "$OK" scripts/tool.py '#!/usr/bin/env python3
print("tool")'
# A script not yet added is read; one the ignore rules name is not.
case_ "an untracked script is read" 1 "In scripts/scratch.sh line 2" \
  scripts/ok.sh "$OK" --untracked scripts/scratch.sh '#!/usr/bin/env bash
cd "$1"'
case_ "an ignored script is not read" 0 "OK: 1 shell scripts pass" \
  .gitignore 'ignored.*' scripts/ok.sh "$OK" --untracked scripts/ignored.sh '#!/usr/bin/env bash
cd "$1"'
case_ "a tree with no shell script is refused" 1 "holds no shell script git lists" \
  README.md '# A tree'

# A directory git does not track is refused before anything is read.
mkdir -p "$WORK/plain"
out="$("$CHECK" "$WORK/plain" 2>"$WORK/stderr")"
judge "a directory outside a git work tree is refused" 1 "not a git work tree" "$?" "$out"

# The program: a PATH that holds only what the check runs before it reads
# a script, and a stand-in ShellCheck where a case names one.
mkdir -p "$WORK/bin-none" "$WORK/bin-other"
for tool in bash dirname sed; do
  ln -s "$(command -v "$tool")" "$WORK/bin-none/$tool"
  ln -s "$(command -v "$tool")" "$WORK/bin-other/$tool"
done
printf '#!/bin/sh\nprintf "ShellCheck - shell script analysis tool\\nversion: 0.0.1\\n"\n' > "$WORK/bin-other/shellcheck"
chmod +x "$WORK/bin-other/shellcheck"
tree scripts/ok.sh "$OK"
out="$(PATH="$WORK/bin-none" "$CHECK" "$tree" 2>"$WORK/stderr")"
judge "a missing ShellCheck is refused" 1 "shellcheck is not installed" "$?" "$out"
out="$(PATH="$WORK/bin-other" "$CHECK" "$tree" 2>"$WORK/stderr")"
judge "a ShellCheck of another version is refused by its version" 1 "shellcheck 0.0.1 is installed" "$?" "$out"

echo "check-shellcheck crafted cases: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
