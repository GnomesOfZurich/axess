#!/usr/bin/env bash
# axess: crafted cases for scripts/check-pipe-readers.sh.
#
# Two kinds. The first runs each pipe idiom the repository's scripts used to
# write, and the form each was rewritten to, under pipefail with a writer
# far larger than a pipe's buffer and the line the reader wants first: the
# old form gives the wrong answer on every run, the new one the right one.
# The second writes scripts and workflows under a temporary root, runs the
# check against it with `--root`, and asserts the exit status and a
# fragment of the output: every reader that may stop before the end is
# refused by file and line wherever the pipe stands, and the forms that read
# to the end, or use no pipe, pass.
#
# Usage: ./scripts/check-pipe-readers-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-pipe-readers.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-pipe-readers.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# ── The idioms, old and new, on a writer larger than the pipe ─────
# big: the wanted line, then 200000 more, about 1.4 MiB.
awk 'BEGIN { print "wanted 1.2.3"; for (i = 0; i < 200000; i++) print "filler" }' >"$WORK/big"
mkdir -p "$WORK/src"
echo small >"$WORK/src/a"
awk 'BEGIN { for (i = 0; i < 60000; i++) print "line of the second file" }' >"$WORK/src/b"

# snippet TEXT: run TEXT in bash with errexit and pipefail in $WORK; it
# prints its answer, and then its status is printed. Python starts the
# shell, so the snippets stay text and no file is written for one to run.
snippet() {
  rm -rf "$WORK/out" "$WORK/archive.tar"
  (cd "$WORK" && python3 -I -B -c '
import subprocess, sys
done = subprocess.run(["bash", "-c", "set -eo pipefail\n" + sys.argv[1]], stderr=subprocess.DEVNULL)
print("status=%d" % done.returncode)
' "$1")
}

# idiom NAME WANTED OLD NEW: the old snippet must not give WANTED (its
# answer and status), the new one must.
idiom() {
  local name="$1" want="$2" got_old got_new
  got_old="$(snippet "$3")"
  got_new="$(snippet "$4")"
  got_old="${got_old//$'\n'/ }"
  got_new="${got_new//$'\n'/ }"
  if [ "$got_old" != "$want" ] && [ "$got_new" = "$want" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted the old form to miss and the new to give '$want', got old '$got_old' and new '$got_new'" >&2
  fi
}

idiom "a name looked up in a list written by printf" "found status=0" \
  'list="$(cat big)"; if printf "%s\n" "$list" | grep -qx "wanted 1.2.3"; then echo found; else echo absent; fi' \
  'list="$(cat big)"; if grep -qx -- "wanted 1.2.3" <<<"$list"; then echo found; else echo absent; fi'
idiom "a warning looked for behind a negation" "warned status=0" \
  'out="$(cat big)"; if ! printf "%s\n" "$out" | grep -qE "^wanted"; then echo clean; else echo warned; fi' \
  'out="$(cat big)"; if ! grep -qE "^wanted" <<<"$out"; then echo clean; else echo warned; fi'
idiom "a program's output searched with grep -q" "found status=0" \
  'if cat big | grep -q "^wanted"; then echo found; else echo absent; fi' \
  'if grep -q "^wanted" <<<"$(cat big)"; then echo found; else echo absent; fi'
idiom "two files searched with cat and grep -qF" "found status=0" \
  'if cat src/a big | grep -qF small; then echo found; else echo absent; fi' \
  'seen="$(cat src/a big)"; if grep -qF small <<<"$seen"; then echo found; else echo absent; fi'
idiom "the first match taken with grep -m1" "version=1.2.3 status=0" \
  'v="$(cat big | grep -m1 "^wanted" | sed "s/.* //")"; echo "version=$v"' \
  'v="$(cat big | grep "^wanted" | sed -n 1p | sed "s/.* //")"; echo "version=$v"'
idiom "the first line taken with head" "first=wanted 1.2.3 status=0" \
  'f="$(cat big | head -1)"; echo "first=$f"' \
  'f="$(cat big | sed -n 1p)"; echo "first=$f"'
idiom "a tree copied through a pipe between two tars" "a b status=0" \
  '(cd src && printf "a\0b\0" | xargs -0 -n 1 tar -cf -) | (mkdir out && tar -xf - -C out); ls out | tr "\n" " " | sed "s/ $//"; echo' \
  'printf "a\0b\0" >list; (cd src && tar -cf ../archive.tar --null -T ../list) && mkdir out && tar -xf archive.tar -C out; ls out | tr "\n" " " | sed "s/ $//"; echo'
idiom "a Python program that reads what it needs" "first=wanted 1.2.3 status=0" \
  'f="$(cat big | python3 -I -c "import sys; print(sys.stdin.readline().strip())")"; echo "first=$f"' \
  'f="$(python3 -I -c "import sys; print(sys.stdin.readline().strip())" <<<"$(cat big)")"; echo "first=$f"'

# ── The check ──────────────────────────────────────────────────────
# case_ NAME EXPECTED_EXIT FRAGMENT [UNWANTED] -- FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3" unwanted=""
  shift 3
  if [ "$1" != "--" ]; then unwanted="$1"; shift; fi
  shift
  local root="$WORK/root-$passed-$failed"
  mkdir -p "$root"
  while [ $# -gt 0 ]; do
    mkdir -p "$root/$(dirname "$1")"
    printf '%s\n' "$2" >"$root/$1"
    shift 2
  done
  local out status
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out" "$unwanted"
}
# sh_ NAME EXPECTED_EXIT FRAGMENT LINE...: one script, s.sh, of the lines.
sh_() {
  local name="$1" want="$2" fragment="$3" text
  shift 3
  text="$(printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' "$@")"
  case_ "$name" "$want" "$fragment" -- s.sh "$text"
}
# run_ NAME EXPECTED_EXIT FRAGMENT LINE...: one workflow step running the lines.
run_() {
  local name="$1" want="$2" fragment="$3" text line
  shift 3
  text='on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |'
  for line in "$@"; do text="$text
          $line"; done
  case_ "$name" "$want" "$fragment" -- .github/workflows/w.yml "$text"
}

case_ "nothing to read is no pass" 1 "ERROR: no shell script and no run step read" -- README.md "nothing"
sh_ "a script with no pipe passes" 0 "ok: every pipe reads to the end in 1 shell script(s) and 0 run step(s)" 'echo hello'
sh_ "a script the lexer cannot read is refused" 1 "s.sh:3: a script the check cannot read" 'echo "open'

# Readers that stop early, in every spelling.
sh_ "grep -q is refused" 1 "s.sh:3: grep -q x: grep -q stops before the end of its input" 'cat f | grep -q x'
sh_ "grep -q in a cluster is refused" 1 "grep -qx stops before the end" 'printf "%s\n" "$list" | grep -qx "$name"'
sh_ "grep --quiet is refused" 1 "grep --quiet stops before the end" 'cat f | grep --quiet x'
sh_ "an abbreviated --quiet is refused" 1 "grep --qui stops before the end" 'cat f | grep --qui x'
sh_ "grep --silent is refused" 1 "grep --silent stops before the end" 'cat f | grep --silent x'
sh_ "grep -m1 is refused" 1 "grep -m1 stops before the end" 'cat f | grep -m1 x | sed s/a/b/'
sh_ "grep -m with its count apart is refused" 1 "grep -m stops before the end" 'cat f | grep -m 1 x'
sh_ "grep --max-count is refused" 1 "grep --max-count=1 stops before the end" 'cat f | grep --max-count=1 x'
sh_ "grep -l is refused" 1 "grep -l stops before the end" 'cat f | grep -l x'
sh_ "grep -r reads the tree, not the pipe" 1 "grep -r stops before the end" 'cat f | grep -r x'
sh_ "head is refused" 1 "s.sh:3: head -1: head stops after the lines it prints" 'v="$(cat f | head -1)"'
sh_ "head -n is refused" 1 "head stops after the lines it prints" 'cat f | head -n 10'
sh_ "a sed that quits is refused" 1 "a sed script that may quit (q)" 'cat f | sed 1q'
sh_ "a sed that quits after printing is refused" 1 "a sed script that may quit (q)" "cat f | sed -n '1p;q'"
sh_ "a sed script after -e that quits is refused" 1 "a sed script that may quit (q)" "cat f | sed -e 's/a/b/' -e 2q"
sh_ "a sed script from a file is refused" 1 "a sed script read from a file" 'cat f | sed -f s.sed'
sh_ "a sed script from a variable is refused" 1 "a sed script the check cannot read" 'cat f | sed "s/$a/b/"'
sh_ "an awk program that exits is refused" 1 "an awk program that may exit" "cat f | awk '/x/ { print; exit }'"
sh_ "an awk program with nextfile is refused" 1 "an awk program that may exit" "cat f | awk '{ nextfile }'"
sh_ "an awk program from a file is refused" 1 "an awk program read from a file" 'cat f | awk -f p.awk'
sh_ "read of one line is refused" 1 "read takes one line" 'cat f | read -r first'
sh_ "a loop that breaks is refused" 1 "the loop's body has break" 'cat f | while read -r l; do' '  break' 'done'
sh_ "a loop that exits from a branch is refused" 1 "the loop's body has exit" 'cat f | while read -r l; do' '  if [ "$l" = x ]; then exit 0; fi' 'done'
sh_ "a loop that calls a function of the script is refused" 1 "the loop's body calls leave" 'leave() { exit 0; }' 'cat f | while read -r l; do' '  leave' 'done'
sh_ "a loop on a timed read is refused" 1 "read -t may end the loop" 'cat f | while read -t 1 -r l; do' '  echo "$l"' 'done'
sh_ "a loop that does not read is refused" 1 "a while loop whose condition is not read" 'cat f | while true; do' '  sleep 1' 'done'
sh_ "an until loop is refused" 1 "a compound command reads the pipe" 'cat f | until false; do' '  :' 'done'
sh_ "a group is refused" 1 "a compound command reads the pipe" 'cat f | { read -r a; echo "$a"; }'
sh_ "a subshell is refused" 1 "a subshell reads the pipe" 'cat f | (read -r a; echo "$a")'
sh_ "a function of the script is refused" 1 "a function of the script reads the pipe" 'first() { read -r a; }' 'cat f | first'
sh_ "a Python program is refused" 1 "a Python program reads the pipe" "cat f | python3 -I -c 'import sys; sys.stdin.readline()'"
sh_ "a Python script is refused" 1 "a Python program reads the pipe" 'cat f | python3 tool.py'
sh_ "a shell is refused" 1 "bash is not a program the check knows" 'cat f | bash'
sh_ "tar is refused" 1 "tar is not a program the check knows" 'tar -cf - a | tar -xf - -C b'
sh_ "a program the check does not know is refused" 1 "frobnicate is not a program the check knows" 'cat f | frobnicate'
sh_ "a program from a variable is refused" 1 "a reader whose program the check cannot read" 'cat f | "$tool"'
sh_ "grep into /dev/null is refused" 1 "grep's output is /dev/null" 'if cat f | grep x >/dev/null; then :; fi'
sh_ "grep into /dev/null with its errors is refused" 1 "grep's output is /dev/null" 'cat f | grep x &>/dev/null'
sh_ "grep to the script's own output is refused" 1 "grep's output is the script's own output" 'cat f | grep x'
sh_ "grep to the error stream is refused" 1 "grep's output is a copy of another descriptor" 'cat f | grep x >&2'
sh_ "grep to a file named by a variable is refused" 1 "a file named by a variable" 'cat f | grep x >"$out"'
sh_ "a grep pattern that may be an option is refused" 1 "a word that may expand to an option of grep" 'n="$(cat f | grep -c "$pattern")"'
sh_ "jq -n reads no input" 1 "jq -n reads no input" "cat f | jq -n '1'"
sh_ "a jq filter that reads on is refused" 1 "a jq filter that reads on with input" "cat f | jq 'first(inputs)'"
sh_ "a jq filter that halts is refused" 1 "a jq filter that reads on with input or stops with halt" "cat f | jq 'halt'"
sh_ "a jq filter from a variable is refused" 1 "a word that may expand to an option of jq" 'cat f | jq -r "$filter"'
sh_ "xargs -E stops at a marker" 1 "xargs -E stops at a marker" 'cat f | xargs -E stop echo'
sh_ "xargs -a reads a file" 1 "xargs -a stops at a marker or reads a file" 'cat f | xargs -a list echo'
sh_ "sort -c stops at the first disorder" 1 "sort -c stops before the end" 'cat f | sort -c'
sh_ "a reader of a file operand does not read the pipe" 1 "cut reads the file g, not the pipe" 'cat f | cut -d: -f1 g'
sh_ "|& is a pipe too" 1 "head stops after the lines it prints" 'cat f |& head -1'
sh_ "a negated pipe is read" 1 "grep -q stops before the end" 'if ! cat f | grep -q x; then :; fi'

# Wherever the pipe stands.
sh_ "a pipe in a substitution is read" 1 "s.sh:3: head -1: head" 'echo "$(cat f | head -1)"'
sh_ "a pipe in a function is read" 1 "s.sh:4: grep -q x" 'f() {' '  cat f | grep -q x' '}'
sh_ "a pipe in bash -c is read" 1 "head stops after the lines it prints" "bash -c 'cat f | head -1'"
sh_ "a pipe in bash with options and -c is read" 1 "head stops after the lines it prints" "bash -euo pipefail -c 'cat f | head -1'"
sh_ "a pipe in sh -c after another program is read" 1 "grep -q stops before the end" "find . -exec sh -c 'cat \"\$1\" | grep -q x' _ {} \\;"
sh_ "a pipe in a here-document a shell reads is read" 1 "s.sh:4: grep -q x" "bash <<'EOF'" 'cat f | grep -q x' 'EOF'
sh_ "a pipe in eval is read" 1 "head stops after the lines it prints" "eval 'cat f | head -1'"
sh_ "a script from a variable handed to bash -c is refused" 1 "bash -c runs a script from a variable" 'bash -c "$script"'
sh_ "words from a variable handed to eval are refused" 1 "eval runs words from a variable" 'eval "$script"'
case_ "a script with no .sh suffix and a shell's #! is read" 1 "tool:2: head -1" -- tool '#!/bin/sh
cat f | head -1'
case_ "a file only ever sourced is read" 1 "lib.inc:2: head -1" -- lib.inc '# shellcheck shell=bash
cat f | head -1'
case_ "a file of another language is not read" 0 "in 0 shell script(s) and 1 run step(s)" -- tool.py 'print("cat f | head -1")' \
  .github/workflows/w.yml 'on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello'
run_ "a pipe in a workflow step is refused by its line" 1 ".github/workflows/w.yml:8: head -1: head" 'echo a' 'v="$(cat f | head -1)"'
case_ "a pipe in a local action's step is refused" 1 ".github/actions/x/action.yml:6: grep -q x" -- .github/actions/x/action.yml 'runs:
  using: composite
  steps:
    - shell: bash
      run: |
        cat f | grep -q x'
case_ "a step in a shell the check does not read is skipped" 0 "in 1 shell script(s) and 0 run step(s)" -- .github/workflows/w.yml 'on: push
jobs:
  a:
    runs-on: windows-latest
    steps:
      - shell: pwsh
        run: Get-Content f | Select-Object -First 1' s.sh 'echo none'
case_ "a workflow the reader cannot read is refused" 1 ".github/workflows/w.yml:1: the YAML cannot be read" -- .github/workflows/w.yml '!!str on: push'

# The forms that read to the end, or use no pipe, pass.
OK="ok: every pipe reads to the end"
sh_ "a here-string has no pipe" 0 "$OK" 'if grep -qx -- "$name" <<<"$list"; then :; fi'
sh_ "a file read has no pipe" 0 "$OK" 'grep -m 1 x f >/dev/null'
sh_ "sed -n 1p reads to the end" 0 "$OK" 'v="$(cat f | sed -n 1p)"'
sh_ "sed with a substitution reads to the end" 0 "$OK" "cat f | sed 's/^/  /' >\"\$WORK/out\""
sh_ "a counting grep in a substitution reads to the end" 0 "$OK" 'n="$(cat f | grep -c x)"'
sh_ "a grep piped on reads to the end" 0 "$OK" 'cat f | grep -v x | wc -l >out.txt'
sh_ "a grep into a named file reads to the end" 0 "$OK" 'cat f | grep x >found.txt'
sh_ "a grep pattern after -e may come from a variable" 0 "$OK" 'n="$(cat f | grep -c -e "$pattern")"'
sh_ "a grep pattern after -- may come from a variable" 0 "$OK" 'n="$(cat f | grep -c -- "$pattern")"'
sh_ "an awk program without exit reads to the end" 0 "$OK" "t=\"\$(cat f | awk -v x=\"\$y\" '{ s += \$1 } END { print s }')\""
sh_ "jq reads to the end" 0 "$OK" "n=\"\$(cat f | jq -r --arg t \"\$t\" '.[] | select(.title == \$t) | .number')\""
sh_ "a while read loop that continues reads to the end" 0 "$OK" 'cat f | while IFS= read -r l; do' '  [ -n "$l" ] || continue' '  echo "$l" >>out.txt' 'done'
sh_ "sort, tr, cut, wc, tail, uniq and tee read to the end" 0 "$OK" 'cat f | sort -u | tr -d " " | cut -d: -f2 | uniq | tail -n 1 | tee out.txt | wc -l >n.txt'
sh_ "a checksum of standard input reads to the end" 0 "$OK" 'echo "$sum  file" | sha256sum --check --strict -'
sh_ "xargs reads to the end, whatever its command does" 0 "$OK" 'git ls-files | xargs grep -ln x >hits.txt'
sh_ "a program Python reads from the pipe is read to the end" 0 "$OK" 'cat prog.py | python3 -I -'
sh_ "an assignment before the reader is not its program" 0 "$OK" 'cat f | LC_ALL=C tr -c "[:print:]" " " >out.txt'
sh_ "text that only looks like a pipe is not one" 0 "$OK" "echo 'cat f | head -1' # cat f | head -1" 'case "$x" in a|b) echo ab ;; esac'

# The gate as it runs on the repository, on the files git lists: a script
# not yet added is read, and a script the ignore rules name is not. The
# gate's own copy is the one tracked script.
STOPS="$(printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'v="$(cat f | head -1)"')"
listed "$CHECK" "an untracked script is read" 1 "new.sh:3: head -1" "ignored.sh" \
  new.sh "$STOPS" ignored.sh "$STOPS"
listed "$CHECK" "an ignored script is not read" 0 "ok: every pipe reads to the end in 1 shell script(s)" "ignored.sh" \
  ignored.sh "$STOPS"

echo "check-pipe-readers crafted cases: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
