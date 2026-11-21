"""The cargo commands of a script, for scripts/check-workflow-pins.sh.

`Cargo.cargo` reads one cargo command: an optional toolchain, cargo's own
flags and the subcommand. A `cargo install` is held to `--locked` and an
exact version for each crate; `cargo binstall` and `cargo quickinstall` are
refused by name; a `--config` is held to the settings scripts/lib/
cargo_config.py allows. Any other subcommand is handed to `subcommand`,
which the reader of a script (scripts/lib/workflow_installs.py) uses to
note what a job beside a secret may not run.
"""

import re

import cargo_config
import workflow_programs

EXACT = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?")
# Global flags of cargo that take a value as the next word, and those that take none.
CARGO_VALUE_FLAGS = {"--color", "--config", "-Z", "-C", "--explain"}
CARGO_FLAGS = re.compile(r"-v+|--verbose|-q|--quiet|-V|--version|--list|--locked|--offline|--frozen|-h|--help")
# The cargo subcommands that install a tool.
SUBCOMMANDS = ("install", "binstall", "quickinstall")
# A positional parameter or the list of them: $1, ${2}, $@, "${@:2}", $*.
POSITIONAL = re.compile(r"\$\{?[@*1-9]")
# Flags of `cargo install` that take a value as the next word, and those that take none.
INSTALL_VALUE_FLAGS = {"--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path",
                       "--root", "--index", "--registry", "--features", "-F", "--jobs", "-j",
                       "--target", "--target-dir", "--profile", "--bin", "--example",
                       "--color", "--config", "-Z", "--message-format", "--lockfile-path"}
INSTALL_FLAGS = {"--list", "--force", "-f", "--no-track", "--offline",
                 "--debug", "--all-features", "--no-default-features", "--bins", "--examples",
                 "--keep-going", "--ignore-rust-version", "--quiet", "-q", "--verbose", "-v",
                 "-vv", "--dry-run", "--help", "-h", "--timings"}


class Install:
    """A tool install a job runs: the workflow line, what, where it stands,
    and the crates a `cargo install` names."""

    def __init__(self, line, what, where=None, crates=()):
        self.line = line
        self.what = what
        self.where = where
        self.crates = tuple(crates)

    def describe(self):
        text = "%s at line %d" % (self.what, self.line)
        return text + (" (%s)" % self.where if self.where else "")


def positional(word):
    """Whether the word is one positional parameter or the list of them."""
    return len(word.parts) == 1 and word.parts[0][0] == "exp" and POSITIONAL.match(word.parts[0][1]) is not None


def could_be(word, names):
    """Whether the value of a word an expansion fills in can be one of `names`."""
    pattern = "".join(re.escape(text) if kind == "lit" else ".*" for kind, text in word.parts)
    return any(re.fullmatch(pattern, name, re.S) for name in names)


def names(crates):
    """The names of the crates among the words of a `cargo install`."""
    return [w.literal().partition("@")[0] for w in crates if w.literal() is not None]


class Cargo:
    """The cargo commands of a script; mixed into the reader of scripts,
    which holds `refuse`, `toolchains` and `subcommand`."""

    def cargo(self, words, j, dynamic, path, line, strict):
        """The Install a cargo command at words[j - 1] makes, after judging its
        pins. `dynamic`: an expansion fills in the program, which may be cargo;
        `strict`: the shell runs that word as the program."""
        first = j
        toolchain = None
        if j < len(words) and (words[j].literal() or words[j].head()).startswith("+"):
            toolchain = words[j].raw[1:] if words[j].literal() is None else words[j].literal()[1:]
            j += 1
        locked = False
        while j < len(words):
            w = words[j]
            literal = w.literal()
            if literal is None:
                flag_or_install = could_be(w, SUBCOMMANDS) or w.parts[0][0] == "exp" or w.head().startswith("-")
                last = j + 1 >= len(words)
                callers = last and positional(w) and w.raw.startswith('"')
                if not dynamic or (strict and ((w.splits and not callers) or (not last and flag_or_install))):
                    self.refuse(path, "line %d: a cargo subcommand from a variable is not read: %s" % (line, w.raw))
                return None
            if not literal.startswith("-"):
                break
            flag, eq, value = literal.partition("=")
            if dynamic and flag not in CARGO_VALUE_FLAGS and not CARGO_FLAGS.fullmatch(flag):
                return None
            if flag in ("--locked", "--frozen"):
                locked = True
            if flag == "--config":
                self.config(value if eq else (words[j + 1] if j + 1 < len(words) else None), path, line)
            if flag in CARGO_VALUE_FLAGS and not eq:
                j += 1
            j += 1
        if j >= len(words):
            return None
        sub = words[j].literal()
        if toolchain is not None and (not dynamic or sub == "install"):
            self.toolchains.append((path, line, toolchain))
        if sub in ("binstall", "quickinstall"):
            self.refuse(path, "line %d: an install route the check does not read: cargo %s (install tools with cargo install --locked crate@X.Y.Z)" % (line, sub))
            return Install(line, "cargo " + sub)
        if sub != "install":
            if not dynamic and sub in workflow_programs.CARGO_SUBCOMMANDS:
                self.settings(words[j + 1:], path, line)
            if strict and not dynamic and sub is not None:
                self.subcommand(sub, words[first:j], words[j + 1:], locked, path, line)
            return None
        return Install(line, "cargo install", crates=self.judge(words[j + 1:], locked, path, line))

    def settings(self, args, path, line):
        """Hold each `--config` after one of cargo's own subcommands, as the
        ones before it are held: `cargo build --config` sets what cargo runs
        like `cargo --config build` does. After an external subcommand the
        words are that program's (`cargo deny --config deny.toml`)."""
        for k, w in enumerate(args):
            if w.literal() == "--":
                break
            flag, eq, value = w.head().partition("=")
            if flag == "--config":
                given = (value if w.literal() is not None else w) if eq else (args[k + 1] if k + 1 < len(args) else None)
                self.config(given, path, line)

    def config(self, given, path, line):
        """Hold the value of a `--config` (a word, or the text after `=`) to
        the settings cargo_config allows."""
        if given is None:
            return
        text = given if isinstance(given, str) else given.literal()
        if text is None:
            self.refuse(path, "line %d: a --config from a variable is not read: %s" % (line, given.raw))
            return
        problem = cargo_config.setting_problem(text)
        if problem:
            self.refuse(path, "line %d: %s" % (line, problem))

    def judge(self, args, locked, path, line):
        """Hold the arguments of one `cargo install` to --locked and exact
        versions; the names of the crates it installs, where they are
        written out."""
        def refuse(message):
            self.refuse(path, "line %d: %s" % (line, message))
        crates, shown, version, source, pending = [], None, None, None, None
        for w in args:
            head = w.head()
            if pending:
                if pending in ("--version", "--vers"):
                    shown, version = w.raw, w.literal()
                elif pending in ("--git", "--path"):
                    source = pending
                elif pending == "--config":
                    self.config(w, path, line)
                elif pending in ("--index", "--registry"):
                    if not (pending == "--registry" and w.literal() == "crates-io"):
                        refuse("a cargo install from another registry is not read (%s %s): install from crates.io" % (pending, w.raw))
                pending = None
                continue
            if head.startswith("-"):
                flag, eq, _ = head.partition("=")
                value_raw = w.raw.partition("=")[2]
                if flag in ("--locked", "--frozen"):
                    locked = True
                elif flag not in INSTALL_VALUE_FLAGS and flag not in INSTALL_FLAGS:
                    refuse("a cargo install flag the check does not read: %s" % flag)
                elif not eq and flag in INSTALL_VALUE_FLAGS:
                    pending = flag
                elif flag in ("--version", "--vers"):
                    shown = value_raw
                    version = None if w.literal() is None else value_raw.strip("'\"")
                elif flag in ("--git", "--path"):
                    source = flag
                elif flag == "--config":
                    self.config(w.raw.partition("=")[2] if w.literal() is None else w.literal().partition("=")[2], path, line)
                elif flag in ("--index", "--registry"):
                    if not (flag == "--registry" and w.literal() == "--registry=crates-io"):
                        refuse("a cargo install from another registry is not read (%s): install from crates.io" % w.raw)
                continue
            crates.append(w)
        if not locked:
            refuse("cargo install without --locked")
        if source:
            refuse("no exact version for a cargo install from --git or --path")
            return names(crates)
        if not crates:
            refuse("cargo install names no crate")
            return names(crates)
        version_ok = version is not None and EXACT.fullmatch(version)
        for w in crates:
            literal = w.literal()
            head = w.head()
            if literal is None and "@" not in head:
                refuse("the crate of a cargo install comes from a variable or a substitution (%s): name it, at an exact version" % w.raw)
            elif "@" in head:
                name, _, rest = (literal if literal is not None else w.raw).partition("@")
                if literal is None or not EXACT.fullmatch(rest):
                    refuse("no exact version for %s (%s is not X.Y.Z)" % (name, rest))
            elif not version_ok and shown is not None:
                refuse("no exact version for %s (--version %s is not a literal X.Y.Z)" % (literal, shown))
            elif not version_ok:
                refuse("no exact version for %s (crate@X.Y.Z or --version X.Y.Z)" % literal)
        return names(crates)
