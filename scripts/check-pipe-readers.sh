#!/usr/bin/env bash
# axess: no pipe has a reader that may stop before its writer is done.
#
# Under `set -o pipefail` a reader that exits as soon as it has what it
# wants (`grep -q`, `grep -m`, `head`, `sed q`, `awk` with `exit`, a `read`
# of one line) can leave its writer to die of SIGPIPE on its next write,
# and pipefail makes the writer's 141 the pipeline's status. Whether the
# writer still had something to write depends on scheduling, so the
# pipeline fails on a loaded machine and passes on the rerun, and behind a
# `!` the failure reads as a pass. This refuses, by file and line, every
# pipe whose reader the check cannot show to read its input to the end, in:
#
#   - every shell script git lists, tracked or untracked and not ignored:
#     a name ending in `.sh`, a first line `#!` naming a shell, or a
#     `# shellcheck shell=` directive (a file only ever sourced), each
#     whether or not it sets pipefail itself (a sourced file runs under its
#     caller's options);
#   - every `run:` script of a workflow or a local action under .github/;
#   - the scripts those hand to a shell (`bash -c`, `sh -c`, `eval`, a
#     here-document a shell reads).
#
# scripts/lib/pipe_readers.py says which readers pass and why each rule
# holds for every input. In place of a refused pipe: a here-string or a
# file (`grep -qx -- "$name" <<<"$list"`), or a reader that reads to the
# end (`sed -n 1p` for `head -1`). It refuses to report clean when it read
# no script.
#
# Usage: ./scripts/check-pipe-readers.sh [--root DIR]
#   --root DIR  check the files under DIR instead of the files git lists
#               in this repository (scripts/check-pipe-readers-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$2"
  listed="$(find . -type f | sed 's|^\./||' | sort)"
else
  [ $# -eq 0 ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not
  # yet added is checked as well.
  listed="$(git ls-files --cached --others --exclude-standard --deduplicate)"
fi

python3 -I -B -c '
import os, sys

sys.path.insert(0, sys.argv[1])
import pipe_readers
import shell_scripts
import workflow_yaml as yaml

scripts = runs = 0
refused = []
for path in sys.stdin.read().split("\n"):
    if not path or not os.path.isfile(path):
        continue
    if shell_scripts.is_workflow(path):
        try:
            doc = yaml.read(open(path, encoding="utf-8").read())
        except yaml.Refusal as err:
            refused.append(f"{path}:{err.line}: the YAML cannot be read: {err.message}")
            continue
        for run in shell_scripts.run_steps(doc):
            runs += 1
            for line, words, reason in pipe_readers.findings(run.value, line_of=run.line_at):
                refused.append(f"{path}:{line}: {words + ": " if words else ""}{reason}")
        continue
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError):
        continue
    if not shell_scripts.is_script(path, text):
        continue
    scripts += 1
    for line, words, reason in pipe_readers.findings(text):
        refused.append(f"{path}:{line}: {words + ": " if words else ""}{reason}")
for line in refused:
    print(line, file=sys.stderr)
if refused:
    print(f"{len(refused)} pipe(s) refused; see the header of scripts/check-pipe-readers.sh.", file=sys.stderr)
    sys.exit(1)
if scripts + runs == 0:
    print("ERROR: no shell script and no run step read; nothing was checked.", file=sys.stderr)
    sys.exit(1)
print(f"ok: every pipe reads to the end in {scripts} shell script(s) and {runs} run step(s)")
' "$LIB" <<<"$listed"
