#!/usr/bin/env bash
# axess: the judgement the crafted-case scripts share (scripts/*-tests.sh).
#
# A case runs a check with its two output streams apart, the error stream
# into "$WORK/stderr", and hands the result to `judge`. A case passes when
# the check ended with the status it wants and one of the two streams holds
# the fragment it wants. A case that wants success also fails when the
# check wrote to its error stream, unless the fragment it wants stands
# there: a check that passes says nothing on that stream, and a tool that
# complains while the check still passes (a `sed` that could not open a
# file, an option a program no longer takes) is a defect the status alone
# does not show.
#
# The script that sources this holds `passed`, `failed` and `WORK`, and for
# `listed` below `SCRIPT_DIR`.

# judge NAME WANTED_EXIT FRAGMENT EXIT OUTPUT [UNWANTED]: count one case.
# UNWANTED is a fragment neither stream may hold.
judge() {
  local name="$1" want="$2" fragment="$3" status="$4" out="$5" unwanted="${6:-}"
  local err all quiet=yes
  err="$(cat "$WORK/stderr" 2>/dev/null)"
  all="$out"
  [ -z "$err" ] || all="${out:+$out
}$err"
  if [ "$want" -eq 0 ] && [ -n "$err" ] && { [ -z "$fragment" ] || ! grep -qF -- "$fragment" <<<"$err"; }; then
    quiet=no
  fi
  if [ "$status" -eq "$want" ] && [ "$quiet" = yes ] && grep -qF -- "$fragment" <<<"$all" \
     && { [ -z "$unwanted" ] || ! grep -qF -- "$unwanted" <<<"$all"; }; then
    passed=$((passed + 1))
    return
  fi
  failed=$((failed + 1))
  if [ "$quiet" = no ] && [ "$status" -eq "$want" ]; then
    echo "FAIL: $name: the check passed and wrote to its error stream:" >&2
    printf '%s\n' "$err" | sed 's/^/    /' >&2
  else
    echo "FAIL: $name: wanted exit $want with '$fragment'${unwanted:+ and without '$unwanted'}, got exit $status:" >&2
    printf '%s\n' "$all" | sed 's/^/    /' >&2
  fi
}

# listed GATE NAME WANTED_EXIT FRAGMENT UNWANTED [FILE CONTENT...]: run a copy
# of GATE on the files git lists, as it runs on the repository (no --root):
# in a git work tree of its own whose index holds the copy, the Python
# helpers of scripts/lib/ beside it and a .gitignore that ignores every file
# named `ignored.*`. The FILEs are written after the index was filled, so
# each is untracked, and git lists it unless it is named so. UNWANTED is a
# fragment neither stream may hold, empty for none.
listed() {
  local gate="$1" name="$2" want="$3" fragment="$4" unwanted="$5"
  shift 5
  local dir="$WORK/listed-$passed-$failed" copy
  copy="scripts/$(basename "$gate")"
  mkdir -p "$dir/scripts/lib"
  cp "$gate" "$dir/$copy"
  cp "$SCRIPT_DIR"/lib/*.py "$dir/scripts/lib/"
  printf 'ignored.*\n' > "$dir/.gitignore"
  git -C "$dir" -c init.defaultBranch=main init -q && git -C "$dir" add -A
  while [ $# -gt 0 ]; do
    mkdir -p "$(dirname "$dir/$1")"
    printf '%s\n' "$2" > "$dir/$1"
    shift 2
  done
  local out status
  out="$("$dir/$copy" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$dir"
  judge "$name" "$want" "$fragment" "$status" "$out" "$unwanted"
}
