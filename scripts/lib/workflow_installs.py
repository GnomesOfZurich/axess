"""The tool installs of a shell script, for scripts/check-workflow-pins.sh.

`Installs.script` lexes a script (scripts/lib/shell_words.py) and judges
every command in it. A `cargo install` is held to its pins; every other
route that installs or runs a tool from a registry is refused by name; a
script the command runs (a repository script, `sh -c`, `eval`, a here-
document handed to a shell) is read the same way; and what cannot be read
(a script from a variable, a script piped into a shell, a cargo alias) is
refused by name. The installs found are returned so that the caller can
hold the job that runs them to the rules on secrets and permissions, and
what a script runs that only such a job is refused is kept as notes
(scripts/lib/workflow_held.py). The cargo commands are read by
scripts/lib/workflow_cargo.py and Python programs by
scripts/lib/workflow_python.py.
"""

import bisect
import os
import re

import cargo_config
import shell_words
import workflow_runners
import workflow_values
from workflow_cargo import Cargo, Install, positional
from workflow_downloads import Downloads
from workflow_held import Held, program_name, workspace
from workflow_python import python_runs_install

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "fish"}
INTERPRETERS = {"python", "python3", "node", "perl", "ruby"}
# Commands that run the command after them, and their options that take a value.
PREFIXES = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D"}, "env": {"-u", "-C"},
    "exec": {"-a"}, "command": set(), "builtin": set(), "time": {"-f", "-o"},
    "nice": {"-n"}, "nohup": set(), "stdbuf": {"-i", "-o", "-e"}, "timeout": {"-s", "-k"},
    "xargs": {"-I", "-J", "-R", "-L", "-n", "-P", "-s", "-d", "-a", "-E"}, "coproc": set(),
}
# Words that open a compound command; the command after them is the one run.
RESERVED = {"if", "then", "else", "elif", "do", "while", "until", "!", "{"}
# Programs that run the recipes of a file this check does not read.
TASK_RUNNERS = {"make", "gmake", "bmake", "just", "task", "rake", "ninja", "mage", "invoke", "inv", "nox", "tox"}
# Install routes the check does not read: command, the subcommands that install or run a tool.
ROUTES = {
    "cargo-binstall": None, "cargo-quickinstall": None, "npx": None, "uvx": None, "pipx": None,
    "pip": {"install", "download"}, "pip3": {"install", "download"},
    "uv": {"pip", "tool", "run"}, "npm": None, "pnpm": None, "yarn": None, "bun": None,
    "gem": {"install"}, "go": {"install", "get", "run"}, "apt": {"install"},
    "apt-get": {"install"}, "brew": {"install"}, "dnf": {"install"}, "yum": {"install"},
    "apk": {"add"}, "snap": {"install"}, "conda": {"install"}, "choco": {"install"},
}
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")


def input_word(line, raw):
    """A word a program fills in from its input: unread, and it may split."""
    w = shell_words.Word(line)
    w.exp(raw, splits=True)
    w.raw = raw
    return w



def line_index(text):
    """line_of(offset): the 1-based line of `text` the offset falls on."""
    breaks = [m.end() for m in re.finditer("\n", text)]

    def line_of(offset):
        return bisect.bisect_right(breaks, offset) + 1
    return line_of


class Installs(Cargo, Held, Downloads):
    """Reads scripts for installs; refusals go to `refuse(path, message)`.
    What only a job beside a secret is refused is kept in `notes`
    (scripts/lib/workflow_held.py)."""

    def __init__(self, root, refuse, display):
        self.root = root
        self.refuse = refuse
        self.display = display
        self.read_scripts = {}
        self.files = None
        self.toolchains = []
        self.notes = []
        self.read_notes = {}
        self.functions = {}
        self.moved = []
        self.values = None
        self.current = None
        self.runners = set()

    # Scripts.

    def script(self, text, line_of, path, moved=False):
        """The installs of a script; refusals name `path` and the script's
        lines. `moved`: the script starts in a directory other than the
        repository's root (a step's `working-directory`)."""
        return self.read(text, line_of, path, moved)[0]

    def read(self, text, line_of, path, moved=False):
        """(installs, whether the script runs its arguments as a command,
        the functions it defines, each with the index of the first argument
        it runs or None)."""
        lexed = shell_words.lex(text, line_of)
        for line, message in lexed.problems:
            self.refuse(path, "line %d: a script the check cannot read: %s" % (line, message))
        self.arguments(lexed)
        found = []
        outer, self.moved = self.moved, [()] if moved else []
        outer_values, self.values = self.values, workflow_values.Values(lexed)
        self.script_assigns(path)
        self.arithmetic(lexed, path)
        for command in lexed.commands:
            found.extend(self.command(command, lexed, path))
        self.moved, self.values = outer, outer_values
        return found, lexed.runs_arguments, {name: self.runs(name, lexed) for name in lexed.functions}

    def runs_positional(self, words):
        start = self.command_word(words)
        return start is not None and positional(words[start])

    def arguments(self, lexed):
        """Find what runs its arguments as a command. `lexed.offsets` gets,
        for each function, the index of the first argument it runs, or
        None when it runs none: `step() { local name="$1"; shift; "$@"; }`
        runs its arguments from the second on. A function whose body the
        reader cannot delimit is left out, and is read as one that runs
        every argument when the script runs any. `lexed.runs_arguments`:
        the script runs its own parameters, outside every function."""
        inside = set()
        lexed.offsets = {}
        for name, body in shell_words.bodies(lexed).items():
            inside.update(id(c) for c in body)
            shifted, nested, offset = 0, 0, None
            for c in body:
                bare = [w.bare() for w in c.words]
                run = shell_words.opened(c.words)
                nested += sum(b in ("if", "while", "until") for b in bare[:len(bare) - len(run)]) + (bare[:1] != [] and run[:1] != [] and run[0].bare() in ("for", "case", "select"))
                nested -= run[:1] != [] and run[0].bare() in ("fi", "done", "esac")
                start = self.command_word(c.words)
                if start is None:
                    continue
                word = c.words[start]
                if word.bare() == "shift":
                    count = c.words[start + 1].literal() if start + 1 < len(c.words) else "1"
                    shifted = shifted + int(count) if shifted is not None and not nested and (count or "").isdigit() else None
                elif positional(word):
                    m = re.search(r"\$\{?([1-9][0-9]*)\}?\"?$|\$\{[@*]:([0-9]+)", word.raw)
                    first = (int(m.group(1) or m.group(2)) - 1 if m else 0) + (shifted or 0)
                    first = 0 if shifted is None else first
                    offset = first if offset is None else min(offset, first)
            lexed.offsets[name] = offset
        lexed.any_positional = any(self.runs_positional(c.words) for c in lexed.commands)
        lexed.runs_arguments = any(self.runs_positional(c.words) for c in lexed.commands if id(c) not in inside)

    def runs(self, name, lexed):
        """The index of the first argument the function `name` runs as a
        command, or None when it runs none of them."""
        if name in lexed.offsets:
            return lexed.offsets[name]
        return 0 if name in lexed.functions and lexed.any_positional else None

    def passes_split_words(self, words, line, path, what):
        """A word that splits, passed to a function or a script that runs its
        arguments as a command, is a command the check cannot read."""
        for w in words:
            if w.splits:
                self.refuse(path, "line %d: a word that splits into words is passed to %s, which runs its arguments, and is not read: %s" % (line, what, w.raw))
                return [Install(line, "a command it cannot read")]
        return []

    def repository_script(self, path, line, runner=None):
        """The installs of a repository script, read once, as the job's at `line`.
        A file a shell or python runs is that language whatever its name; one
        run by its path is what its name or its first line says."""
        key = (path, runner)
        if key in self.read_scripts:
            self.replay(self.read_notes[key])
        else:
            mark = self.mark()
            self.read_scripts[key] = []
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            python = runner == "python" if runner else self.is_python(path, text)
            if python:
                self.note("unheld", path, 1, "a Python program: it is read for cargo install alone")
                if python_runs_install(text):
                    self.refuse(path, "a Python script that runs cargo install is not read: run the install from the workflow")
                    self.read_scripts[key] = [Install(1, "cargo install")]
            elif runner == "shell" or self.is_shell(path, text):
                self.read_scripts[key], runs, self.functions[path] = self.read(text, line_index(text), path)
                if runs:
                    self.runners.add(path)
            else:
                self.note("unheld", path, 1, "a repository program that is neither a shell nor a Python script")
            self.read_notes[key] = self.since(mark)
        return [Install(line, f.what, f.where or "%s, line %d" % (self.display(path), f.line), f.crates) for f in self.read_scripts[key]]

    @staticmethod
    def is_python(path, text):
        return path.endswith(".py") or re.match(r"#!.*python", text) is not None

    @staticmethod
    def is_shell(path, text):
        return path.endswith(".sh") or re.match(r"#!\S*/(env\s+)?(ba|da|z|k)?sh\b", text) is not None

    def resolve(self, word, bare=False):
        """The repository files a word names: by its path, by the path after an
        expansion (every file that ends in it), or, with `bare`, by a name with
        no slash. "missing" for a script the repository does not hold; None for
        a word that names no script."""
        literal = word.literal()
        script = (".sh", ".py")
        if workspace(word):
            literal = workspace(word)
        if literal is not None:
            if literal.startswith("/"):
                return "missing" if literal.endswith(script) else None
            if "/" not in literal and not bare and not literal.endswith(script):
                return None
            path = os.path.normpath(os.path.join(self.root, literal))
            if os.path.isfile(path) and path.startswith(os.path.join(self.root, "")):
                return [path]
            return "missing" if literal.endswith(script) or bare else None
        tail = word.tail().lstrip("/")
        if "/" not in word.tail():
            return None
        if self.files is None:
            self.files = []
            for base, dirs, names in os.walk(self.root):
                dirs[:] = [d for d in dirs if d not in (".git", "target", "node_modules", "book")]
                self.files.extend(os.path.join(base, n) for n in names)
        hits = sorted(f for f in self.files if f.endswith(os.sep + tail))
        if hits:
            return hits
        return "missing" if tail.endswith(script) or bare else None

    def read_target(self, word, command, path, runner):
        """The installs of the repository script `runner` runs; refused when the
        repository does not hold it."""
        line = command.line
        targets = self.resolve(word, bare=True)
        if not isinstance(targets, list):
            self.refuse(path, "line %d: a script the check cannot read is run by %s: %s" % (line, runner, word.raw))
            return [Install(line, "a script it cannot read")]
        self.code(word, command, path)
        found = []
        kind = "python" if runner.startswith("python") else "shell"
        for target in targets:
            found.extend(self.repository_script(target, line, kind))
        return found

    # Commands.

    def command(self, command, lexed, path):
        words = command.words
        line = command.line
        self.redirects(command, path)
        self.copies(command, path)
        for op, target in command.redirects:
            if ">" in op and target is not None and re.search(r"\.cargo/config(\.toml)?$", target.literal() or target.tail()):
                self.refuse(path, "line %d: a script that writes cargo's config is not read: name what it sets in the workflow" % line)
        start = self.command_word(words)
        for w in words[:len(words) if start is None else start]:
            m = ASSIGNMENT.match(w.raw)
            if m:
                self.cargo_env(m.group(0).rstrip("+="), path, line, w)
                self.toolchain_env(w, path, line)
        moved = self.runner_files(command, start, lexed, path)
        names, unread = workflow_runners.assigned(words, start)
        for name in names:
            self.cargo_env(name, path, line)
            if name == "PATH":
                moved.append(Install(line, "a directory put on the path"))
        problem = workflow_runners.expansion_problem(words)
        if unread is not None:
            problem = "a variable whose name comes from a variable is not read: %s (name the variable)" % unread.raw
        if problem:
            self.refuse(path, "line %d: %s" % (line, problem))
            moved.append(Install(line, "a command it cannot read"))
        if start is None:
            if workflow_runners.sudo_shell(words):
                moved.extend(self.stdin_script(command, lexed, path, "sudo -s"))
            return moved
        words = self.from_input(words, start)
        run = words[start]
        if run.splits and not (positional(run) and run.raw.startswith('"')):
            self.refuse(path, "line %d: a command from an expansion that splits into words is not read: %s (quote it, or write the command out)" % (line, run.raw))
            return [Install(line, "a command it cannot read")]
        unread = []
        if program_name(run) is None and not positional(run):
            unread = [Install(line, "a program whose name comes from a variable (%s)" % run.raw)]
        return moved + self.named(command, words, start, lexed, path) + unread

    def runner_files(self, command, start, lexed, path):
        """A step's write to $GITHUB_ENV sets variables for the steps after
        it, each held to the rules on variables; a directory a script puts
        on the path (PATH, $GITHUB_PATH, `hash -p`) makes the programs it
        names ones the job wrote, so it counts as an install."""
        words, line = command.words, command.line
        found = []
        name = program_name(words[start]) if start is not None else None
        prefix = words if start is None else words[:start]
        if any(re.match(r"PATH\+?=", w.raw) for w in prefix) or (
                name in ("export", "declare", "typeset", "readonly", "local") and any(re.match(r"PATH\+?=", w.raw) for w in words[start + 1:])) or (
                name == "hash" and any(w.literal() == "-p" for w in words[start + 1:])):
            found.append(Install(line, "a directory put on the path"))
        targets = [workflow_runners.runner_file(t) for op, t in command.redirects if ">" in op and t is not None]
        if start is not None:
            targets += workflow_runners.named_files(name, words[start + 1:])
        if "PATH" in targets:
            found.append(Install(line, "a directory put on the path"))
        if "ENV" in targets:
            pairs = workflow_runners.env_lines(name, words[start + 1:] if start is not None else [], [b for b, _ in lexed.bodies_of(command)])
            if pairs is None:
                self.refuse(path, "line %d: a write to $GITHUB_ENV the check cannot read: write each NAME=value with echo or printf" % line)
                return found + [Install(line, "a command it cannot read")]
            for variable, value in pairs:
                if value is None or "\0" in value:
                    self.note("unheld", path, line, "a value from a variable written to $GITHUB_ENV (%s): a line break in it sets another variable" % variable)
                self.cargo_env(variable, path, line)
                self.env_written(path, line, variable)
                self.flags_env(variable, value if value is not None and "\0" not in value else None, path, line)
                if variable == "RUSTUP_TOOLCHAIN":
                    self.toolchains.append((path, line, value if value is not None and "\0" not in value else "a value it cannot read"))
                if variable == "PATH":
                    found.append(Install(line, "a directory put on the path"))
        return found

    def named(self, command, words, start, lexed, path):
        """The installs of a command whose program is words[start]: a reader
        for the programs that run a script, a program or a recipe, and the
        cargo install among its words."""
        line = command.line
        run = words[start]
        first = run.literal()
        name = program_name(run)
        self.current = command
        direct = all(ASSIGNMENT.match(w.raw) or w.bare() in RESERVED for w in words[:start])
        self.hold(command, words, start, lexed, path, direct)
        self.downloads(command, words, start, lexed, path)
        if name == "alias":
            self.refuse(path, "line %d: a shell alias is not read: write the command out" % line)
        if name in ("export", "declare", "typeset", "readonly", "local"):
            for w in words[start + 1:]:
                m = ASSIGNMENT.match(w.raw) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", w.literal() or "")
                if m:
                    self.cargo_env(m.group(0).rstrip("+="), path, line, w if "=" in w.raw else None)
                    self.toolchain_env(w, path, line)
        if name == "find":
            return self.find_actions(command, words[start + 1:], lexed, path)
        if name == "set" and lexed.runs_arguments:
            return self.parameters(command, words[start + 1:], lexed, path)
        if name in ("su", "script") and not workflow_runners.script_of(name, words[start + 1:]):
            return self.stdin_script(command, lexed, path, name)
        unread = self.runner(name, words[start + 1:], line, path)
        if unread is not None:
            return unread
        if name in SHELLS or name in (".", "source"):
            return self.shell(command, words, start, lexed, path)
        if name == "rustup":
            self.rustup(words[start + 1:], path, line)
        if name == "eval":
            return self.evaluated(words[start + 1:], line, path, "eval")
        if name in INTERPRETERS:
            return self.interpreter(command, words, start, lexed, path)
        found = []
        targets = None
        if first is None or "/" in first or first.endswith((".sh", ".py")):
            targets = self.resolve(words[start])
            if targets == "missing":
                self.refuse(path, "line %d: a script the repository does not hold is not read: %s" % (line, words[start].raw))
            for target in targets if isinstance(targets, list) else []:
                self.call_note(path, line, words[start + 1:])
                found.extend(self.repository_script(target, line))
                self.note("return", path, line, None)
        offset = self.runs(first, lexed)
        if offset is None and isinstance(targets, list) and any(t in self.runners for t in targets):
            offset = 0
        given = words[start + 1 + offset:] if offset is not None else []
        if given:
            refused = self.passes_split_words(given, line, path, run.raw)
            if refused:
                return found + refused
            sub = shell_words.Command(line, command.joined_by, command.scope)
            sub.words = given
            return found + self.command(sub, lexed, path)
        found.extend(self.later(command, words, start, lexed, path))
        self.current = command
        for i, w in enumerate(words):
            literal = w.literal()
            base = name if i == start else (os.path.basename(literal) if literal else None)
            if base == "cargo" or (base is None and literal is None and not ASSIGNMENT.match(w.raw)):
                install = self.cargo(words, i + 1, base != "cargo", path, line, i == start)
                if install:
                    return found + [install]
                if base == "cargo":
                    return found
            elif base in TASK_RUNNERS and i == start:
                self.refuse(path, "line %d: the recipes %s runs are not read: %s (run the commands from the workflow or a repository script)" % (line, base, w.raw))
                return found + [Install(line, base)]
            elif base in ROUTES:
                subs = ROUTES[base]
                nxt = words[i + 1].literal() if i + 1 < len(words) else None
                if subs is None or nxt in subs:
                    what = base if subs is None else "%s %s" % (base, nxt)
                    self.refuse(path, "line %d: an install route the check does not read: %s (install tools with cargo install --locked crate@X.Y.Z)" % (line, what))
                    return found + [Install(line, what)]
        return found

    def parameters(self, command, args, lexed, path):
        """The words `set --` makes the parameters of a script that runs its
        parameters as a command (`"$@"`): read as that command."""
        literals = [w.literal() for w in args]
        given = args[literals.index("--") + 1:] if "--" in literals else []
        if not given:
            return []
        refused = self.passes_split_words(given, command.line, path, "set --")
        if refused:
            return refused
        sub = shell_words.Command(command.line, command.joined_by, command.scope)
        sub.words = given
        return self.command(sub, lexed, path)

    def runner(self, name, args, line, path):
        """The installs of a program that hands a string to a shell (read as
        `sh -c` text), or the refusal of a git setting, an awk or sed
        program or a command composer the check cannot read. None for any
        other program."""
        script = workflow_runners.script_of(name, args)
        if script:
            return self.evaluated(script, line, path, name)
        problem = workflow_runners.builtin_problem(name, args)
        if name == "git":
            problem = workflow_runners.git_problem(args)
        elif name == "gh":
            problem = workflow_runners.gh_problem(args)
        elif name in workflow_runners.AWKS:
            problem = workflow_runners.awk_problem(args)
        elif name in ("sed", "gsed"):
            problem = workflow_runners.sed_problem(args)
        elif name == "enable" and any(re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", w.literal() or "-f") for w in args):
            problem = "a builtin loaded from a file is not read (enable -f)"
        elif name in workflow_runners.COMPOSERS:
            problem = "%s builds the commands it runs from its input, which is not read" % name
        if problem:
            self.refuse(path, "line %d: %s" % (line, problem))
            return [Install(line, "a command it cannot read")]
        return None

    def later(self, command, words, start, lexed, path):
        """A shell with `-c`, `eval`, or an interpreter with `-c` or `-e`
        among the arguments of a program that runs them (`flock f bash -c`,
        `docker run img sh -c`): read from there, as a literal `cargo` is."""
        for k in range(start + 1, len(words) - 1):
            name = program_name(words[k])
            nxt = words[k + 1].literal() or ""
            if (name in SHELLS and re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", nxt)) or name == "eval" or (
                    name in INTERPRETERS and nxt in ("-c", "-e")):
                sub = shell_words.Command(command.line, command.joined_by, command.scope)
                sub.words = words[k:]
                return self.named(sub, sub.words, 0, lexed, path)
        return []

    @staticmethod
    def from_input(words, start):
        """The words of a command under `xargs`, with what xargs fills in
        from its input standing as a word that splits: appended after the
        command, or in place of each word that holds the replace string."""
        names = [os.path.basename(w.literal() or "") for w in words[:start]]
        if "xargs" not in names:
            return words
        replace = None
        options = words[names.index("xargs") + 1:start]
        for k, w in enumerate(options):
            literal = w.literal() or ""
            if literal in ("-I", "-J"):
                replace = options[k + 1].literal() or "{}"
            elif literal.startswith(("-I", "-J")):
                replace = literal[2:]
            elif literal.startswith(("-i", "--replace")):
                replace = literal.partition("=")[2] or literal[2:] if not literal.startswith("--") else literal.partition("=")[2] or "{}"
                replace = replace or "{}"
        if replace is None:
            return words + [input_word(words[-1].line, "the input of xargs")]
        return words[:start] + [input_word(w.line, w.raw) if replace in (w.literal() or w.raw) else w for w in words[start:]]

    def find_actions(self, command, args, lexed, path):
        """The commands `find -exec`, `-execdir`, `-ok` and `-okdir` run, each
        read as a command, with `{}` standing as a word from input."""
        found = []
        k = 0
        while k < len(args):
            if args[k].literal() in ("-exec", "-execdir", "-ok", "-okdir"):
                end = k + 1
                while end < len(args) and args[end].literal() not in (";", "+"):
                    end += 1
                sub = shell_words.Command(command.line, command.joined_by, command.scope)
                sub.words = [input_word(w.line, w.raw) if "{}" in (w.literal() or "") else w for w in args[k + 1:end]]
                found.extend(self.command(sub, lexed, path))
                k = end
            k += 1
        return found

    @staticmethod
    def command_word(words):
        """The index of the word the shell runs, past assignments and prefixes."""
        i = 0
        while i < len(words) and (ASSIGNMENT.match(words[i].raw) or words[i].bare() in RESERVED or words[i].bare() == "function"):
            i += 2 if words[i].bare() == "function" else 1
        while i < len(words):
            name = os.path.basename(words[i].literal() or "")
            if name not in PREFIXES or (name == "env" and workflow_runners.script_of("env", words[i + 1:])):
                return i
            i += 1
            if name == "coproc" and i + 1 < len(words) and words[i + 1].bare() == "{":
                i += 2
            while i < len(words):
                literal = words[i].literal() or ""
                if name == "command" and literal in ("-v", "-V"):
                    return None
                if literal in PREFIXES[name]:
                    i += 2
                elif literal.startswith("-") or (name in ("env", "sudo") and ASSIGNMENT.match(words[i].raw)):
                    i += 1
                else:
                    break
            if name == "timeout":
                i += 1
        return None

    def rustup(self, args, path, line):
        """Record the toolchain `rustup` installs or selects, for the toolchain rule."""
        words = []
        skip = False
        for w in args:
            text = w.literal() if w.literal() is not None else w.raw
            if skip:
                skip = False
            elif text in ("--profile", "-c", "--component", "-t", "--target"):
                skip = True
            elif not text.startswith("-"):
                words.append(text)
        for prefix in (["toolchain", "install"], ["install"], ["default"], ["override", "set"], ["run"]):
            if words[:len(prefix)] == prefix and len(words) > len(prefix):
                names = words[len(prefix):] if prefix[-1] == "install" else words[len(prefix):len(prefix) + 1]
                for name in names:
                    self.toolchains.append((path, line, name))
                return

    def toolchain_env(self, word, path, line):
        """Record the toolchain a `RUSTUP_TOOLCHAIN=...` assignment selects."""
        name, eq, value = word.raw.partition("=")
        if name == "RUSTUP_TOOLCHAIN" and eq:
            literal = word.literal()
            self.toolchains.append((path, line, literal.partition("=")[2] if literal is not None else value))

    def cargo_env(self, name, path, line, word=None):
        """Refuse a variable that changes what cargo, a shell or git runs;
        `word`: the assignment that sets it, whose value is read where the
        variable holds flags for rustc."""
        if cargo_config.ENV.fullmatch(name):
            self.refuse(path, "line %d: %s changes what cargo installs or runs (an alias, a source, its configuration or a program in place of rustc), which is not read" % (line, name))
        problem = workflow_runners.env_problem(name)
        if problem:
            self.refuse(path, "line %d: %s" % (line, problem))
        if workflow_runners.BUILD_ENV.fullmatch(name):
            self.note("unheld", path, line, "a variable by which a build script finds a program to run (%s)" % name)
        if workflow_runners.stand_in(name):
            self.note("unheld", path, line, workflow_runners.stand_in(name))
        if word is not None:
            literal = word.literal()
            self.flags_env(name, literal.partition("=")[2] if literal is not None else None, path, line)

    def flags_env(self, name, value, path, line):
        """Refuse flags for rustc that name a program it runs or code it loads."""
        problem = cargo_config.flags_problem(name, value)
        if problem:
            self.refuse(path, "line %d: %s" % (line, problem))

    # Scripts a command runs.

    def shell(self, command, words, start, lexed, path):
        """A shell or `source` at words[start]: read the script it runs.
        `words` are the command's, with what `xargs` fills in standing as
        a word from its input."""
        line = command.line
        name = program_name(words[start])
        i = start + 1
        inline = False
        while i < len(words) and name not in (".", "source"):
            literal = words[i].literal() or ""
            if literal == "--":
                i += 1
                break
            if literal[:1] not in ("-", "+") or literal in ("-", "+"):
                break
            if literal in ("-o", "+o", "-O", "+O"):
                i += 1
            elif not literal.startswith("--") and "c" in literal[1:]:
                inline = True
            i += 1
        if inline:
            return self.evaluated(words[i:i + 1], line, path, name + " -c")
        if i < len(words) and words[i].literal() != "-":
            found = self.read_target(words[i], command, path, name)
            targets = self.resolve(words[i], bare=True)
            for target in targets if name in (".", "source") and isinstance(targets, list) else []:
                lexed.offsets.update(self.functions.get(target, {}))
                lexed.functions.update(self.functions.get(target, {}))
            return found
        return self.stdin_script(command, lexed, path, name)

    def stdin_script(self, command, lexed, path, name):
        """What a shell reads on its input: a here-document, a file, or a pipe."""
        line = command.line
        for op, target in command.redirects:
            if op in ("<<", "<<-"):
                found = []
                moved = self.is_moved(command)
                quoted = target is not None and any(mark in target.raw for mark in "'\"\\")
                for body, offset in lexed.bodies_of(command):
                    if not quoted and re.search(r"(?<!\\)[$`]", body):
                        self.pasted(path, line, name + " reads from a here-document")
                    found.extend(self.script(body, lambda k, o=offset: lexed.line_of(o + k), path, moved))
                return found
            if op == "<<<" and target is not None:
                return self.evaluated([target], line, path, name)
            if op == "<" and target is not None:
                return self.read_target(target, command, path, name)
        if command.joined_by in ("|", "|&"):
            self.refuse(path, "line %d: a script piped into %s is not read: run a script the repository holds" % (line, name))
            return [Install(line, "a script it cannot read")]
        return []

    def evaluated(self, words, line, path, how):
        """The installs of the text `eval` or `sh -c` runs. An expansion in the
        text stands in it as written, a value the inner shell reads; text that
        is all expansion is not read."""
        if not words or any(all(kind == "exp" for kind, _ in w.parts) for w in words):
            self.refuse(path, "line %d: the script %s runs comes from a variable or a substitution, which is not read" % (line, how))
            return [Install(line, "a script it cannot read")]
        texts = ["".join(text for _, text in w.parts) for w in words]
        moved = self.current is not None and self.is_moved(self.current)
        if any(kind == "exp" for w in words for kind, _ in w.parts):
            self.pasted(path, line, how + " runs")
        return self.script(" ".join(texts), lambda k: line, path, moved)

    def interpreter(self, command, words, start, lexed, path):
        """python at words[start]: read the program it runs. node, perl and ruby
        programs are not read, so running one is refused by name."""
        line = command.line
        name = program_name(words[start])
        python = name.startswith("python")
        i = start + 1
        while i < len(words):
            literal = words[i].literal() or ""
            if literal == "-m" and python:
                module, sub = ([w.literal() for w in words[i + 1:]] + [None, None])[:2]
                if module in ("pip", "pipx") and sub in ("install", "download", "run"):
                    self.refuse(path, "line %d: an install route the check does not read: %s %s (install tools with cargo install --locked crate@X.Y.Z)" % (line, module, sub))
                    return [Install(line, "%s %s" % (module, sub))]
                return []
            if literal in ("-c", "-e"):
                program = words[i + 1] if i + 1 < len(words) else None
                return self.program(program, line, path, "%s %s" % (name, literal), python)
            if not literal.startswith("-") or literal == "-":
                break
            i += 1
        if i < len(words) and words[i].literal() != "-":
            if not python:
                self.refuse(path, "line %d: a %s program is not read: %s" % (line, name, words[i].raw))
                return [Install(line, "a program it cannot read")]
            return self.read_target(words[i], command, path, name)
        for body, _ in lexed.bodies_of(command):
            if not python or python_runs_install(body):
                self.refuse(path, "line %d: a %s program on its input is not read%s" % (line, name, ": it runs cargo install" if python else ""))
                return [Install(line, "a program it cannot read")]
        if command.joined_by in ("|", "|&"):
            self.refuse(path, "line %d: a script piped into %s is not read: run a script the repository holds" % (line, name))
            return [Install(line, "a script it cannot read")]
        return []

    def program(self, word, line, path, how, python):
        """The text after `-c` or `-e`: read for cargo install when it is Python."""
        if word is None or all(kind == "exp" for kind, _ in word.parts):
            self.refuse(path, "line %d: the program %s runs comes from a variable or a substitution, which is not read" % (line, how))
            return [Install(line, "a program it cannot read")]
        code = "".join(text if kind == "lit" else "0" for kind, text in word.parts)
        if not python or python_runs_install(code):
            self.refuse(path, "line %d: the program %s runs is not read%s" % (line, how, ": it runs cargo install" if python else ""))
            return [Install(line, "a program it cannot read")]
        return []
