#!/usr/bin/env bash
# axess: every shell script of the repository passes ShellCheck.
#
# A shell script is every file git lists whose name ends in `.sh`, whose
# first line is a `#!` naming a shell, or whose first line is a
# `# shellcheck shell=` directive (a file only ever sourced). git lists the
# tracked files and the untracked ones it does not ignore, so a script is
# read before it is added, wherever it stands, and a file the ignore rules
# name is not the repository's.
#
# ShellCheck reads them all at once with `-x`, so a file one script sources
# is read with that script, and with each script's own directory as the
# place a source is looked for, so `. "$SCRIPT_DIR/lib/x.sh"` finds
# lib/x.sh whatever directory the check runs from. A finding at warning or
# above fails the check. So does a sourced file ShellCheck cannot find
# (SC1091, an info finding): the variables and functions that file sets
# would go unread, and the findings that rest on them unmade.
#
# The version is the one scripts/install-shellcheck.sh pins and CI installs.
# Each version reads differently, so any other is refused rather than
# trusted to agree.
#
# Usage: ./scripts/check-shellcheck.sh [DIR]   (default: the repository root)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${1:-$SCRIPT_DIR/..}"
cd "$DIR" || { echo "REFUSED: no directory at $DIR." >&2; exit 1; }

pinned="$(sed -n 's/^SHELLCHECK_VERSION=//p' "$SCRIPT_DIR/install-shellcheck.sh")"
if [ -z "$pinned" ]; then
  echo "REFUSED: scripts/install-shellcheck.sh pins no SHELLCHECK_VERSION." >&2
  exit 1
fi
if ! command -v shellcheck >/dev/null 2>&1; then
  echo "REFUSED: shellcheck is not installed; install ShellCheck $pinned (scripts/install-shellcheck.sh on Linux x86_64)." >&2
  exit 1
fi
found="$(shellcheck --version 2>/dev/null | sed -n 's/^version: //p')"
if [ "$found" != "$pinned" ]; then
  echo "REFUSED: shellcheck ${found:-of no stated version} is installed and scripts/install-shellcheck.sh pins $pinned; another version reports other findings." >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "REFUSED: $DIR is not a git work tree, so its scripts cannot be listed." >&2
  exit 1
fi
scripts=()
while IFS= read -r -d '' file; do
  case "$file" in
    *.sh) scripts+=("$file"); continue ;;
  esac
  [ -f "$file" ] || continue
  first="$(head -n 1 "$file" 2>/dev/null | tr -d '\r')"
  if [[ "$first" =~ ^#!.*[/[:space:]](sh|bash|dash|ksh|mksh)([[:space:]]|$) ]] \
     || [[ "$first" =~ ^#[[:space:]]*shellcheck[[:space:]].*shell= ]]; then
    scripts+=("$file")
  fi
done < <(git ls-files --cached --others --exclude-standard --deduplicate -z)

if [ "${#scripts[@]}" -eq 0 ]; then
  echo "REFUSED: $DIR holds no shell script git lists, so there is nothing to read." >&2
  exit 1
fi

failed=0
if ! shellcheck -x --source-path=SCRIPTDIR --severity=warning -- "${scripts[@]}"; then
  failed=1
fi
# A second pass for the one info finding the gate holds: a source not read.
if ! shellcheck -x --source-path=SCRIPTDIR --severity=info --include=SC1091 -- "${scripts[@]}"; then
  echo "REFUSED: a file a script sources is not where ShellCheck looks; name it with a source= directive." >&2
  failed=1
fi
if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "OK: ${#scripts[@]} shell scripts pass ShellCheck $found at warning and above, every source read."
