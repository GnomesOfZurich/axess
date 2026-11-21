"""More crafted cases for scripts/lib/workflow_installs.py, run by
scripts/check-workflow-pins-tests.sh: the wrappers, runner files, xargs and
find forms and the variable programs, each pinned as workflow_installs_tests.py
pins its own (the refusals, the installs found and the toolchains). Run with
`python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from workflow_installs_tests import run

VAR = "a program whose name comes from a variable (\"$C\") at line 1"
SUB = "line 1: a cargo subcommand from a variable is not read: %s"
PIP = "line 1: an install route the check does not read: pip install (install tools with cargo install --locked crate@X.Y.Z)"
PATH = "a directory put on the path at line 1"
UNPINNED = [("w.yml", "line 1: cargo install without --locked"), ("w.yml", "line 1: no exact version for x (crate@X.Y.Z or --version X.Y.Z)")]

CASES = [
  ("a subcommand that may be install after a variable program", '"$C" in"$x" a',
   ([("w.yml", SUB % 'in"$x"')], [VAR], [])),
  ("a subcommand that may be binstall after a variable program", '"$C" bin"$x" a',
   ([("w.yml", SUB % 'bin"$x"')], [VAR], [])),
  ("a subcommand that may be quickinstall after a variable program", '"$C" quick"$x" a',
   ([("w.yml", SUB % 'quick"$x"')], [VAR], [])),
  ("a subcommand that starts with a variable after a variable program", '"$C" "$x"foo a',
   ([("w.yml", SUB % '"$x"foo')], [VAR], [])),
  ("parameters a script gives itself and runs", 'set -- cargo install x\n"$@"',
   (UNPINNED, ["cargo install at line 1"], [])),
  ("parameters after the options of set", 'set -eu -- cargo install x\n"$1"',
   (UNPINNED, ["cargo install at line 1"], [])),
  ("parameters from a variable that a script runs", 'set -- $TOOLS\n"$@"',
   ([("w.yml", "line 1: a word that splits into words is passed to set --, which runs its arguments, and is not read: $TOOLS")], ["a command it cannot read at line 1"], [])),
  ("parameters a script does not run", "set -- $FILES\necho $#",
   ([], [], [])),
  ("the options of set in a script that runs its parameters", 'set -euo pipefail\n"$@"',
   ([], [], [])),
  ("no parameters after the end of options", 'set --\n"$@"',
   ([], [], [])),
  ("a function that runs its arguments after a label", 'step() { local name="$1"; shift; if "$@"; then echo ok; fi; }\nstep "a label" cargo install x',
   ([("w.yml", "line 2: cargo install without --locked"), ("w.yml", "line 2: no exact version for x (crate@X.Y.Z or --version X.Y.Z)")], ["cargo install at line 2"], [])),
  ("a label that reads as a path, before the command a function runs", 'step() { local name="$1"; shift; "$@"; }\nstep "lists agree (a/b vs c/d)" echo ok',
   ([], [], [])),
  ("a function that shifts two and runs the rest", 'f() { shift 2; "$@"; }\nf a b make all',
   ([("w.yml", "line 2: the recipes make runs are not read: make (run the commands from the workflow or a repository script)")], ["make at line 2"], [])),
  ("a function that runs from its second argument", 'f() { echo "$1"; "${@:2}"; }\nf label make all',
   ([("w.yml", "line 2: the recipes make runs are not read: make (run the commands from the workflow or a repository script)")], ["make at line 2"], [])),
  ("a function that runs its third argument", 'f() { "$3"; }\nf a b make',
   ([("w.yml", "line 2: the recipes make runs are not read: make (run the commands from the workflow or a repository script)")], ["make at line 2"], [])),
  ("a function that shifts in a loop runs any of its arguments", 'f() { while [ "$1" != -- ]; do shift; done; "$@"; }\nf make all',
   ([("w.yml", "line 2: the recipes make runs are not read: make (run the commands from the workflow or a repository script)")], ["make at line 2"], [])),
  ("a function that runs none of its arguments beside one that does", 'say() { echo "$1"; }\nrun() { "$@"; }\nsay make\nrun echo ok',
   ([], [], [])),
  ("a function with a body the reader cannot delimit, beside one that runs its arguments", 'say() ( echo "$1" )\nrun() { "$@"; }\nsay make',
   ([("w.yml", "line 3: the recipes make runs are not read: make (run the commands from the workflow or a repository script)")], ["make at line 3"], [])),
  ("parameters set in a script whose function alone runs arguments", 'run() { "$@"; }\nset -- make all\nrun echo ok',
   ([], [], [])),
  ("find with no path", "find -exec cargo install x \\;",
   (UNPINNED, ["cargo install at line 1"], [])),
  ("eval as the last argument", "echo eval",
   ([], [], [])),
  ("an interpreter given -c among the arguments", "flock f python3 -c \"import os; os.system('cargo install x')\"",
   ([("w.yml", "line 1: the program python3 -c runs is not read: it runs cargo install")], ["a program it cannot read at line 1"], [])),
  ("an interpreter given -e among the arguments", 'flock f perl -e "x"',
   ([("w.yml", "line 1: the program perl -e runs is not read")], ["a program it cannot read at line 1"], [])),
  ("an interpreter among the arguments given another flag", "echo python3 -V",
   ([], [], [])),
  ("declare of the path", "declare PATH=x", ([], [PATH], [])),
  ("typeset of the path", "typeset PATH=x", ([], [PATH], [])),
  ("readonly of the path", "readonly PATH=x", ([], [PATH], [])),
  ("local of the path", "local PATH=x", ([], [PATH], [])),
  ("export of the path before another variable", "export PATH=x A=1", ([], [PATH], [])),
  ("a variable set for a function that runs its arguments", 'f() { "$@"; }\nX=$y f cargo build --locked',
   ([], [], [])),
  ("xargs -J", "xargs -J % cargo % x", ([("w.yml", SUB % "%")], [], [])),
  ("xargs -i", "xargs -i cargo {} x", ([("w.yml", SUB % "{}")], [], [])),
  ("xargs --replace=", "xargs --replace=R cargo R x", ([("w.yml", SUB % "R")], [], [])),
  ("xargs --replace", "xargs --replace cargo {} x", ([("w.yml", SUB % "{}")], [], [])),
  ("xargs -i joined", "xargs -iR cargo R x", ([("w.yml", SUB % "R")], [], [])),
  ("xargs replacing an escaped word", "xargs -I {} cargo \\{\\} x", ([("w.yml", SUB % "\\{\\}")], [], [])),
  ("python -m pip install", "python3 -m pip install x", ([("w.yml", PIP)], ["pip install at line 1"], [])),
  ("python -m pip alone", "python3 -m pip", ([], [], [])),
  ("a route as the last word", "pip install", ([("w.yml", PIP)], ["pip install at line 1"], [])),
  ("a variable program after timeout", 'timeout 10 "$C" x', ([], [VAR], [])),
  ("a quoted --config joined to install", "cargo install --locked --config='net.retry=3' a@1.0.0",
   ([], ["cargo install at line 1"], [])),
  ("a --config from a variable joined to install", 'cargo install --locked --config="$X" a@1.0.0',
   ([("w.yml", 'line 1: a --config that names a file is not read: "$X" (name the setting as key=value)')], ["cargo install at line 1"], [])),
  ("a task runner given -c among the arguments", "echo make -c x",
   ([], [], [])),
  ("find -exec ended by a plus", "find . -exec eval {} + -exec cargo install x \\;",
   ([("w.yml", "line 1: the script eval runs comes from a variable or a substitution, which is not read")] + UNPINNED,
    ["a script it cannot read at line 1", "cargo install at line 1"], [])),
  ("find -exec with nothing to run", "find . -exec \\; -name cargo -name install -exec true \\;",
   ([], [], [])),
  ("xargs -J after another option", "xargs -0 -J % cargo % x", ([("w.yml", SUB % "%")], [], [])),
  ("xargs -J joined", "xargs -J% cargo % x", ([("w.yml", SUB % "%")], [], [])),
  ("the runner path file as the first argument", 'tee "$GITHUB_PATH"', ([], [PATH], [])),
  ("a runner file in an assignment before a program", "X=$GITHUB_ENV ls", ([], [], [])),
]


def main():
    failures = []
    for name, script, want in CASES:
        got = run(script, {})
        if got != want:
            failures.append("%s: %r, wanted %r" % (name, got, want))
    for failure in failures:
        print("FAIL: workflow_installs_more: " + failure, file=sys.stderr)
    print("workflow_installs_more tests: %d passed, %d failed" % (len(CASES) - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
