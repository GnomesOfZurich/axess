"""Crafted cases for scripts/lib/workflow_held.py, run by
scripts/check-workflow-pins-tests.sh.

Each case runs one script through `Installs.script` in a temporary root
holding the files it names, and pins every note the reader keeps for a job
beside a secret: its kind, the file and the line it names, and what it
says. Run with `python3 -I -B`.
"""

import os
import shutil
import sys
import tempfile

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shell_words
import workflow_held as H
import workflow_installs as I


def run(script, files, moved=False, path="w.yml"):
    root = tempfile.mkdtemp()
    try:
        for name, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, name)) or root, exist_ok=True)
            with open(os.path.join(root, name), "w") as f:
                f.write(text)

        def display(p):
            return os.path.relpath(p, root) if p.startswith(root) else p
        inst = I.Installs(root, lambda p, m: None, display)
        inst.script(script, I.line_index(script), path if path == "w.yml" else os.path.join(root, path), moved)
        # The notes of downloads are workflow_downloads_tests.py's.
        return [(kind, display(where), line, what) for kind, where, line, what in inst.notes if kind in H.KINDS]
    finally:
        shutil.rmtree(root)


def unheld(line, what, where="w.yml"):
    return ("unheld", where, line, what)


UNNAMED = "a program the check does not name (%s)"
THROUGH = "a repository file named through a variable (%s): the runner runs the file the variable names, the check read the repository's"
AFTER_CD = "a repository file run after a change of directory (%s): the check read it from the repository's root"
GIT_MOVED = "git after a change of directory: it reads the settings of the repository it stands in"
PYTHON = "a Python program: it is read for cargo install alone"
PASTED = "a value pasted into the script %s: the shell that runs it reads the value as commands (quote the script, and pass the value as an argument or in the environment)"
ENV_VALUE = "a value from a variable written to $GITHUB_ENV (%s): a line break in it sets another variable"
BUILD = "a variable by which a build script finds a program to run (%s)"
A = {"scripts/a.sh": "echo a\n"}

CASES = [
  ("a builtin and a filter", "set -eu; echo x | grep x", {}, []),
  ("an unnamed program", "docker ps", {}, [unheld(1, UNNAMED % "docker")]),
  ("an unnamed program on a second line", "echo\nfrob", {}, [unheld(2, UNNAMED % "frob")]),
  ("an unnamed program after a prefix", "sudo -u x nice frob", {}, [unheld(1, UNNAMED % "frob")]),
  ("an unnamed program after a word that opens a command", "if frob; then echo; fi", {}, [unheld(1, UNNAMED % "frob")]),
  ("a function of the script", "f() { echo; }\nf x", {}, []),
  ("a function declared with the keyword", "function f { echo; }\nf", {}, []),
  ("a function behind command", "f() { echo; }\ncommand f", {}, [unheld(2, UNNAMED % "f")]),
  ("a function behind xargs", "f() { echo; }\necho | xargs f", {}, [unheld(2, UNNAMED % "f")]),
  ("a function after an assignment", "f() { echo; }\nX=1 f", {}, []),
  ("a function removed", "f() { echo; }\nunset -f f", {}, [unheld(2, "a function removed with unset: the program of its name runs after it")]),
  ("a function removed by its name", "f() { echo; }\nunset f", {}, [unheld(2, "a function removed with unset: the program of its name runs after it")]),
  ("a variable unset", "unset X", {}, []),
  ("a word of the grammar in quotes", "'done'", {}, [unheld(1, UNNAMED % "done")]),
  ("a word of the grammar after a prefix", "env fi", {}, [unheld(1, UNNAMED % "fi")]),
  ("a program whose name a variable fills in", '"$TOOL" x', {}, []),
  ("the arguments of a script as its command", '"$@"', {}, []),
  ("a program by a relative path", "./tool", {}, []),
  ("a program by a path in a variable", '"$DIR/tool"', {}, []),
  ("a program by an absolute path", "/tmp/tool", {}, []),
  ("a program by a path of the image", "/usr/bin/git status; /bin/echo; /usr/local/bin/jq .", {}, []),
  ("an unnamed program by a path of the image", "/usr/sbin/frob", {}, [unheld(1, UNNAMED % "frob")]),
  ("a repository script", "./scripts/a.sh", A, [("code", "w.yml", 1, "./scripts/a.sh")]),
  ("a repository script a shell runs", "bash scripts/a.sh", A, [("code", "w.yml", 1, "scripts/a.sh")]),
  ("a repository script sourced", ". scripts/a.sh", A, [("code", "w.yml", 1, "scripts/a.sh")]),
  ("a repository script under the workspace", '"$GITHUB_WORKSPACE/scripts/a.sh"', A, [("code", "w.yml", 1, '"$GITHUB_WORKSPACE/scripts/a.sh"')]),
  ("a repository script under the braced workspace", 'bash "${GITHUB_WORKSPACE}/scripts/a.sh"', A, [("code", "w.yml", 1, '"${GITHUB_WORKSPACE}/scripts/a.sh"')]),
  ("a script under the workspace the repository does not hold", '"$GITHUB_WORKSPACE/scripts/b.sh"', A, []),
  ("an external cargo subcommand", "cargo audit --deny warnings", {}, [("subcommand", "w.yml", 1, "audit")]),
  ("an external cargo subcommand under a toolchain", "cargo +nightly fuzz run t", {}, [("subcommand", "w.yml", 1, "fuzz")]),
  ("a subcommand of the toolchain", "cargo fmt --check; cargo clippy", {},
   [unheld(1, "cargo fmt, which changes the sources or the lockfile or is not needed beside a secret"),
    unheld(1, "cargo clippy, which changes the sources or the lockfile or is not needed beside a secret")]),
  ("a repository script through a variable", '"$DIR/scripts/a.sh"', A,
   [("code", "w.yml", 1, '"$DIR/scripts/a.sh"'), unheld(1, THROUGH % '"$DIR/scripts/a.sh"')]),
  ("a repository script a shell runs through a variable", 'bash "$RUNNER_TEMP/a.sh"', A,
   [("code", "w.yml", 1, '"$RUNNER_TEMP/a.sh"'), unheld(1, THROUGH % '"$RUNNER_TEMP/a.sh"')]),
  ("a repository script after cd", "cd x\n./scripts/a.sh", A,
   [("code", "w.yml", 2, "./scripts/a.sh"), unheld(2, AFTER_CD % "./scripts/a.sh")]),
  ("a repository script after pushd and popd", "pushd x\npopd\n./scripts/a.sh", A,
   [("code", "w.yml", 3, "./scripts/a.sh"), unheld(3, AFTER_CD % "./scripts/a.sh")]),
  ("a repository script after cd with no directory", "cd\nbash scripts/a.sh", A,
   [("code", "w.yml", 2, "scripts/a.sh"), unheld(2, AFTER_CD % "scripts/a.sh")]),
  ("a repository script after cd in a subshell", "(cd x; ls)\n./scripts/a.sh", A, [("code", "w.yml", 2, "./scripts/a.sh")]),
  ("a repository script after cd in a substitution", 'd="$(cd x && pwd)"\n./scripts/a.sh', A, [("code", "w.yml", 2, "./scripts/a.sh")]),
  ("a repository script in the subshell of a cd", "(cd x; ./scripts/a.sh)", A,
   [("code", "w.yml", 1, "./scripts/a.sh"), unheld(1, AFTER_CD % "./scripts/a.sh")]),
  ("a repository script in a substitution after cd", "cd x\nv=$(./scripts/a.sh)", A,
   [("code", "w.yml", 2, "./scripts/a.sh"), unheld(2, AFTER_CD % "./scripts/a.sh")]),
  ("a repository script after a return to the workspace", 'cd x\ncd "$GITHUB_WORKSPACE"\n./scripts/a.sh', A, [("code", "w.yml", 3, "./scripts/a.sh")]),
  ("a return to the workspace in a subshell", 'cd x\n(cd "$GITHUB_WORKSPACE")\n./scripts/a.sh', A,
   [("code", "w.yml", 3, "./scripts/a.sh"), unheld(3, AFTER_CD % "./scripts/a.sh")]),
  ("a repository script under the workspace after cd", 'cd x\n"$GITHUB_WORKSPACE/scripts/a.sh"', A, [("code", "w.yml", 2, '"$GITHUB_WORKSPACE/scripts/a.sh"')]),
  ("a repository script in the text of eval after cd", 'cd x\neval "./scripts/a.sh"', A,
   [("code", "w.yml", 2, "./scripts/a.sh"), unheld(2, AFTER_CD % "./scripts/a.sh")]),
  ("a repository script in a here-document after cd", "cd x\nbash <<EOF\n./scripts/a.sh\nEOF", A,
   [("code", "w.yml", 3, "./scripts/a.sh"), unheld(3, AFTER_CD % "./scripts/a.sh")]),
  ("git after cd", "cd x\ngit status", {}, [unheld(2, GIT_MOVED)]),
  ("git that changes the checkout", "git checkout main", {}, [("tree", "w.yml", 1, "git checkout")]),
  ("git that reads", "git log -1; git fetch origin", {}, []),
  ("a build", "cargo build --locked", {}, [("code", "w.yml", 1, "cargo build")]),
  ("a build after cd", "cd x && cargo test --locked", {},
   [("code", "w.yml", 1, "cargo test"), unheld(1, "cargo test after a change of directory: it builds the package it stands in")]),
  ("a cargo subcommand that builds nothing", "cargo version; cargo metadata --locked", {}, []),
  ("cargo as an argument", "echo cargo build", {}, []),
  ("an install", "cargo install --locked a@1.0.0", {}, []),
  ("a Python program", "python3 -c 'import json'", {}, [unheld(1, "a Python program (python3): it is read for cargo install alone")]),
  ("a Python script of the repository", "python3 scripts/a.py", {"scripts/a.py": "print(1)\n"},
   [unheld(1, "a Python program (python3): it is read for cargo install alone"), ("code", "w.yml", 1, "scripts/a.py"), unheld(1, PYTHON, "scripts/a.py")]),
  ("a repository program in another language", "./scripts/tool", {"scripts/tool": "#!/usr/bin/env node\n"},
   [("code", "w.yml", 1, "./scripts/tool"), unheld(1, "a repository program that is neither a shell nor a Python script", "scripts/tool")]),
  ("a redirection into the checkout", "echo x > out", {}, [unheld(1, "a file a script writes outside the runner's temporary directory (out)")]),
  ("a redirection with no command", "> out", {}, [unheld(1, "a file a script writes outside the runner's temporary directory (out)")]),
  ("a redirection into the temporary directory", 'echo x > "$RUNNER_TEMP/out"', {}, []),
  ("what a repository script runs", "./scripts/b.sh", {"scripts/b.sh": "echo\nfrob\n./scripts/a.sh\n", "scripts/a.sh": "docker ps\n"},
   [("code", "w.yml", 1, "./scripts/b.sh"), unheld(2, UNNAMED % "frob", "scripts/b.sh"), ("code", "scripts/b.sh", 3, "./scripts/a.sh"),
    unheld(1, UNNAMED % "docker", "scripts/a.sh")]),
  ("a repository script run twice", "./scripts/a.sh\n./scripts/a.sh", {"scripts/a.sh": "frob\n"},
   [("code", "w.yml", 1, "./scripts/a.sh"), unheld(1, UNNAMED % "frob", "scripts/a.sh"),
    ("code", "w.yml", 2, "./scripts/a.sh"), unheld(1, UNNAMED % "frob", "scripts/a.sh")]),
  ("a function of a sourced script", ". scripts/lib.sh\nhelper", {"scripts/lib.sh": "helper() { echo; }\n"}, [("code", "w.yml", 1, "scripts/lib.sh")]),
  ("a function no sourced script defines", ". scripts/a.sh\nhelper", A, [("code", "w.yml", 1, "scripts/a.sh"), unheld(2, UNNAMED % "helper")]),
  ("a value pasted into the text of sh -c", 'sh -c "echo $X"', {}, [unheld(1, PASTED % "sh -c runs")]),
  ("a value pasted into the text of eval", 'eval "x=$X"', {}, [unheld(1, PASTED % "eval runs")]),
  ("a value pasted into the string of a trap", 'trap "rm $X" EXIT', {}, [unheld(1, PASTED % "trap runs")]),
  ("a value pasted into a here-string a shell reads", 'bash <<< "echo $X"', {}, [unheld(1, PASTED % "bash runs")]),
  ("a value pasted into a here-document a shell reads", "bash <<EOF\necho $X\nEOF", {}, [unheld(1, PASTED % "bash reads from a here-document")]),
  ("a substitution pasted into a here-document a shell reads", "sh <<EOF\necho `date`\nEOF", {}, [unheld(1, PASTED % "sh reads from a here-document")]),
  ("a here-document with a quoted delimiter", "bash <<'EOF'\necho \"$X\"\nEOF", {}, []),
  ("a here-document with an escaped dollar", "bash <<EOF\necho \\$X\nEOF", {}, []),
  ("a here-document a filter reads", "cat <<EOF\n$X\nEOF", {}, []),
  ("the text of sh -c in single quotes", "sh -c 'echo \"$X\"'", {}, []),
  ("a value written for the later steps", 'echo "A=$X" >> "$GITHUB_ENV"', {}, [unheld(1, ENV_VALUE % "A")]),
  ("a value written for the later steps by printf", 'printf "A=%s\\n" x >> "$GITHUB_ENV"', {}, [unheld(1, ENV_VALUE % "A")]),
  ("a value over several lines written for the later steps", 'echo "A<<EOF" >> "$GITHUB_ENV"', {}, [unheld(1, ENV_VALUE % "A")]),
  ("a value written out for the later steps", 'echo "A=1" >> "$GITHUB_ENV"', {}, []),
  ("a compiler named for a build", "CC=clang cargo build --locked", {}, [unheld(1, BUILD % "CC"), ("code", "w.yml", 1, "cargo build")]),
  ("an exported libclang", "export LIBCLANG_PATH=/x", {}, [unheld(1, BUILD % "LIBCLANG_PATH")]),
  ("a variable of another name", "CCACHE=1 cargo build --locked", {}, [("code", "w.yml", 1, "cargo build")]),
  ("a function of a script that is run, not sourced", "bash scripts/lib.sh\nhelper", {"scripts/lib.sh": "helper() { echo; }\n"},
   [("code", "w.yml", 1, "scripts/lib.sh"), unheld(2, UNNAMED % "helper")]),
]
# A script that starts in another directory (a step's working-directory).
MOVED = [
  ("a repository script", "./scripts/a.sh", A, [("code", "w.yml", 1, "./scripts/a.sh"), unheld(1, AFTER_CD % "./scripts/a.sh")]),
  ("a build", "cargo build --locked", {}, [("code", "w.yml", 1, "cargo build"), unheld(1, "cargo build after a change of directory: it builds the package it stands in")]),
  ("git", "git status", {}, [unheld(1, GIT_MOVED)]),
  ("a return to the workspace", 'cd "$GITHUB_WORKSPACE"; ./scripts/a.sh', A, [("code", "w.yml", 1, "./scripts/a.sh")]),
  ("a filter", "grep x f", {}, []),
]
# A repository script that moves to the root by its own directory.
ROOTED = [
  ("to the directory above its own", 'cd "$(dirname "${BASH_SOURCE[0]}")/.."\n./scripts/a.sh', "scripts/s.sh", False),
  ("to the directory above its own, by $0", 'cd "$(dirname "$0")/.."\n./scripts/a.sh', "scripts/s.sh", False),
  ("to its own directory", 'cd "$(dirname "${BASH_SOURCE[0]}")"\n./scripts/a.sh', "scripts/s.sh", True),
  ("to its own directory, from the root", 'cd "$(dirname "$0")"\n./scripts/a.sh', "s.sh", False),
  ("two directories above its own", 'cd "$(dirname "$0")/../.."\n./scripts/a.sh', "scripts/lib/s.sh", False),
  ("to a directory above the root", 'cd "$(dirname "$0")/../.."\n./scripts/a.sh', "scripts/s.sh", True),
  ("to a directory a variable names", 'cd "$ROOT"\n./scripts/a.sh', "scripts/s.sh", True),
  ("to a directory under its own", 'cd "$(dirname "$0")/$sub"\n./scripts/a.sh', "scripts/s.sh", True),
]


def word(text):
    return shell_words.lex(text, lambda offset: 1).commands[0].words[0]


def main():
    failures = []
    for name, script, files, want in CASES:
        got = run(script, files)
        if got != want:
            failures.append("%s: %r, wanted %r" % (name, got, want))
    for name, script, files, want in MOVED:
        got = run(script, files, moved=True)
        if got != want:
            failures.append("in another directory, %s: %r, wanted %r" % (name, got, want))
    for name, script, path, moved in ROOTED:
        got = run(script, dict(A, **{path: script}), path=path)
        want = [("code", path, 2, "./scripts/a.sh")] + ([unheld(2, AFTER_CD % "./scripts/a.sh", path)] if moved else [])
        if got != want:
            failures.append("a script that moves %s: %r, wanted %r" % (name, got, want))
    for text, want in (('"$GITHUB_WORKSPACE"', ""), ("$GITHUB_WORKSPACE/a/b", "a/b"), ('"${GITHUB_WORKSPACE}/a"', "a"),
                       ('"$GITHUB_WORKSPACE/$x"', None), ('"$GITHUB_WORKSPACEX/a"', None), ('"x$GITHUB_WORKSPACE/a"', None),
                       ('"$RUNNER_TEMP/a"', None), ("a/b", None), ('"$GITHUB_WORKSPACE"a', None)):
        if H.workspace(word(text)) != want:
            failures.append("workspace(%s): %r, wanted %r" % (text, H.workspace(word(text)), want))
    for text, want in (("cargo", "cargo"), ("/usr/bin/cargo", "cargo"), ('"$DIR/bash"', "bash"), ('"$C"', None), ('"$X"sh', None), ("./a/", "")):
        if H.program_name(word(text)) != want:
            failures.append("program_name(%s): %r, wanted %r" % (text, H.program_name(word(text)), want))
    for failure in failures:
        print("FAIL: workflow_held: " + failure, file=sys.stderr)
    total = len(CASES) + len(MOVED) + len(ROOTED) + 9 + 6
    print("workflow_held tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
