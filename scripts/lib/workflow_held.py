"""What a script runs that a job beside a secret may not, for
scripts/check-workflow-pins.sh.

The reader of scripts (scripts/lib/workflow_installs.py) judges every
command for the installs it makes, in every job. This part of it notes, for
every command, what only a job that names a secret, may ask for an OIDC
token or holds a token that can write is refused: a program the check does
not name, a program run by a path the repository does not hold, an option
of a named program that writes a file or runs a program, a file written
outside the runner's temporary directory, and a repository file that may
not be the file the check read (named through a variable, or by a relative
path after a change of directory). The caller holds the job: a note counts
only where the job is one of those.

A note is (kind, path, line, what). `unheld` is one of the above. `code`
is a file of the checkout the job runs (a repository script, a package
cargo builds) and `tree` a command that changes the files of the checkout:
a job beside a secret does not do both. `subcommand` is a cargo subcommand
that is not cargo's own, whose program every job installs itself. A
program run by a path the repository does not hold is refused in every
job, by name.
"""

import os
import re

import workflow_arithmetic
import workflow_programs as programs
import workflow_runners
from workflow_cargo import positional

# The kinds of note this part keeps.
KINDS = ("unheld", "code", "tree", "subcommand")
WORKSPACE = re.compile(r"\$\{?GITHUB_WORKSPACE\}?")
# The directory a script stands in, as a script names it.
SCRIPT_DIR = {'$(dirname "${BASH_SOURCE[0]}")', '$(dirname "$0")', '$(dirname -- "${BASH_SOURCE[0]}")', '$(dirname -- "$0")'}


def program_name(word):
    """The name of the program a word runs: the last part of its path, read
    from the text after its last expansion (`"$DIR/bash"` is bash). None when
    an expansion fills in the name itself (`"$c"`, `"$X"sh`, `"${CARGO}"`)."""
    literal = word.literal()
    if literal is not None:
        return os.path.basename(literal)
    tail = word.tail()
    if "/" in tail and os.path.basename(tail):
        return os.path.basename(tail)
    return None


def workspace(word):
    """The path under the repository's root a word names as
    `$GITHUB_WORKSPACE/path`; None for any other word."""
    parts = programs.pieces(word)
    if parts and parts[0][0] == "exp" and WORKSPACE.fullmatch(parts[0][1]):
        if len(parts) == 1:
            return ""
        if len(parts) == 2 and parts[1][0] == "lit" and parts[1][1].startswith("/"):
            return parts[1][1].lstrip("/")
    return None


class Place:
    """What the values of the script around a command say of a word: the
    host a URL names."""

    def __init__(self, values, command):
        self.values = values
        self.command = command

    def host(self, word):
        return self.values.host(word) if self.values is not None else programs.Unknown.host(word)


class Held:
    """The notes of a reader of scripts; mixed into it. The reader holds
    `root`, `notes`, `toolchains`, `moved`, `current` and `resolve`."""

    def note(self, kind, path, line, what):
        self.notes.append((kind, path, line, what))

    # What a script or a local action read once gives every job that runs it.

    def mark(self):
        return len(self.toolchains), len(self.notes)

    def since(self, mark):
        return self.toolchains[mark[0]:], self.notes[mark[1]:]

    def drop(self, mark):
        del self.toolchains[mark[0]:]
        del self.notes[mark[1]:]

    def replay(self, saved):
        self.toolchains.extend(saved[0])
        self.notes.extend(saved[1])

    # Where a script stands.

    def is_moved(self, command):
        """Whether a `cd` before the command, in its subshell or one around
        it, left the script in a directory the check does not know."""
        return any(command.scope[:len(scope)] == scope for scope in self.moved)

    def moves(self, name, args, command, path):
        """Record a `cd`, `pushd` or `popd`. A `cd` to the repository's root
        (`"$GITHUB_WORKSPACE"`, or the directory above the script's own, as a
        script under the root names it) puts the script back where the check
        reads paths from."""
        if name not in ("cd", "pushd", "popd"):
            return
        target = next((w for w in args if not (w.literal() or "").startswith("-")), None)
        if name == "cd" and target is not None and self.is_root(target, path):
            self.moved = [scope for scope in self.moved if scope[:len(command.scope)] != command.scope]
        else:
            self.moved.append(command.scope)

    def is_root(self, target, path):
        if workspace(target) == "":
            return True
        parts = programs.pieces(target)
        if path.endswith((".yml", ".yaml")) or not parts or parts[0][0] != "exp" or parts[0][1] not in SCRIPT_DIR:
            return False
        rest = "".join(text for _, text in parts[1:]) if all(kind == "lit" for kind, _ in parts[1:]) else None
        if rest is None:
            return False
        there = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(path)), rest.lstrip("/")))
        return there == os.path.normpath(self.root)

    # What a command runs.

    def hold(self, command, words, start, lexed, path, direct):
        """Note what the command at words[start] runs that a job beside a
        secret may not. `direct`: the shell runs the word itself, so that a
        function or a word of its grammar is one; after `command`, `env` or
        `sudo` the word names a program."""
        run, args = words[start], words[start + 1:]
        name = program_name(run)
        if name is None or positional(run):
            return
        literal = run.literal()
        if literal is None or ("/" in literal and not literal.startswith(programs.SYSTEM)):
            self.path_program(run, command, path)
            return
        if direct and (run.bare() in programs.SYNTAX or literal in lexed.functions):
            return
        self.moves(name, args, command, path)
        if name == "unset" and any(w.literal() in lexed.functions or w.head().startswith("-f") for w in args):
            self.note("unheld", path, command.line, "a function removed with unset: the program of its name runs after it")
        for reason in self.reasons(name, args, command, path):
            self.note("unheld", path, command.line, reason)

    def reasons(self, name, args, command, path):
        if name in programs.PURE:
            return programs.pure(name, args)
        if name == "git":
            found, tree, sub = programs.git(args)
            if tree:
                self.note("tree", path, command.line, "git " + sub)
            if self.is_moved(command):
                found.append("git after a change of directory: it reads the settings of the repository it stands in")
            return found
        if name == "gh":
            return programs.gh(args)
        if name == "curl":
            return programs.curl(args, Place(self.values, command))
        if name in ("sed", "gsed"):
            return programs.sed(args)
        if name in workflow_runners.AWKS:
            return programs.awk(args)
        if name == "find":
            return programs.find(args)
        if name in ("python", "python3"):
            return ["a Python program (%s): it is read for cargo install alone" % name]
        if not programs.named(name):
            return ["a program the check does not name (%s)" % name]
        return []

    def path_program(self, run, command, path):
        """A program named by a path: a file the repository holds, or one a
        step made or downloaded."""
        targets = self.resolve(run)
        if isinstance(targets, list):
            self.code(run, command, path)
        elif targets != "missing" and not self.unpacked_path(run, command, path):
            self.refuse(path, "line %d: a program run by a path the repository does not hold is not read: %s (a file a step made or downloaded)" % (command.line, run.raw))

    def code(self, word, command, path):
        """Note that the command runs the repository file `word` names, and
        whether the runner may run another file than the one the check read."""
        self.note("code", path, command.line, word.raw)
        if workspace(word) is not None:
            return
        if word.literal() is None:
            self.note("unheld", path, command.line, "a repository file named through a variable (%s): the runner runs the file the variable names, the check read the repository's" % word.raw)
        elif self.is_moved(command):
            self.note("unheld", path, command.line, "a repository file run after a change of directory (%s): the check read it from the repository's root" % word.raw)

    def holds(self, literal):
        """Whether the repository holds the file a literal path names."""
        there = os.path.normpath(os.path.join(self.root, literal))
        return os.path.isfile(there) and there.startswith(os.path.join(self.root, ""))

    def subcommand(self, sub, flags, rest, locked, path, line):
        """A cargo subcommand other than install, run as the command."""
        reasons, builds, external = programs.cargo(sub, flags, rest, locked, self.holds)
        if external:
            self.note("subcommand", path, line, sub)
        if builds:
            self.note("code", path, line, "cargo " + sub)
            if self.current is not None and self.is_moved(self.current):
                reasons.append("cargo %s after a change of directory: it builds the package it stands in" % sub)
        for reason in reasons:
            self.note("unheld", path, line, reason)

    def pasted(self, path, line, how):
        """Note a script whose text the outer shell fills in before the
        inner one reads it: the value of a variable becomes commands."""
        self.note("unheld", path, line, "a value pasted into the script %s: the shell that runs it reads the value as commands (quote the script, and pass the value as an argument or in the environment)" % how)

    def redirects(self, command, path):
        for op, target in command.redirects:
            for reason in programs.redirect(op, target):
                self.note("unheld", path, command.line, reason)

    def copies(self, command, path):
        """Note what writes the runner's files by another name: a copy of
        the path of $GITHUB_ENV or $GITHUB_PATH in a variable, and an
        indirect expansion (`${!name}`), whose variable a value names."""
        for w in command.words + [target for _, target in command.redirects if target is not None]:
            for kind, text in w.parts:
                if kind == "exp" and re.match(r"\$\{![A-Za-z_][A-Za-z0-9_]*(:?[-=?+][^}]*)?\}$", text):
                    self.note("unheld", path, command.line, "an indirect expansion (%s): the variable it reads is the one a value names" % text)
            if re.match(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=", w.raw) and any(
                    kind == "exp" and re.search(r"\bGITHUB_(ENV|PATH)\b", text) for kind, text in w.parts):
                self.note("unheld", path, command.line, "a copy of the path of a file of the runner (%s): a write through it is not read" % w.raw)

    def arithmetic(self, lexed, path):
        """Note each arithmetic text whose operands are not numbers the
        script made (scripts/lib/workflow_arithmetic.py)."""
        for line, message in workflow_arithmetic.problems(lexed, self.values):
            self.note("unheld", path, line, message)
