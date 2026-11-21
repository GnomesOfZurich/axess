"""Pipes whose reader may stop reading before its writer has written all.

Used by scripts/check-pipe-readers.sh. Under `set -o pipefail` a pipeline's
status is that of the last of its commands to fail. A reader that exits once
it has what it wants (`grep -q`, `head`, `sed q`) closes the pipe while its
writer may still be writing; the writer's next write gets SIGPIPE, the writer
ends with status 141, and pipefail makes that the pipeline's status. Whether
the writer has anything left to write by then depends on how the two are
scheduled (bash writes the output of `printf` and `echo` a line at a time),
so such a pipeline fails on some runs and passes on others, and a `!` in
front of it turns the failure into a pass.

Every pipe of every script is held, whether or not the script sets pipefail
itself: a file another script sources runs under that script's options, a
bash started with SHELLOPTS exported inherits them, and the runner starts a
`shell: bash` step as `bash -eo pipefail`.

The rule is that a reader passes only when it reads its standard input to
the end on every run that ends well, which is established from its words:

  - a program known to read all of its input, with options that do not make
    it stop early and operands that are not files it reads in place of the
    pipe (SPECS, and `sed`, `awk`, `jq` and a `while read` loop, whose
    scripts are read too);
  - GNU grep stops at its first match when its output is /dev/null, as if
    `-q` were given, so a grep passes only when its output goes on down the
    pipe, into a command substitution, or to a file named in the script;
  - a word that may expand to an option, a script the check cannot see (a
    `-f` file, a variable), and a program it does not know are refused.

So the rule refuses some pipes that could never fail, and none that can.
The forms that pass in their place: a here-string or a file read instead of
the pipe (`grep -qx -- "$name" <<<"$list"`), and a reader that reads to the
end (`sed -n 1p` for `head -1`, `grep -c` or a captured `grep` for
`grep -q`).
"""

import re

import shell_words

# Words that only name a reader: an assignment before the program.
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")

# program: (short options that take an argument, long options that take
# one, short options that stop early or read no pipe, long ones that do,
# what an operand is: "files" refuses any but "-", "free" passes them).
SPECS = {
    "cat": ("", (), "", (), "files"),
    "cut": ("bcdf", ("--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"), "", (), "files"),
    "wc": ("", (), "", ("--files0-from",), "files"),
    "tail": ("bcn", ("--bytes", "--lines", "--pid", "--sleep-interval", "--max-unchanged-stats"), "", (), "files"),
    "uniq": ("fsw", ("--skip-fields", "--skip-chars", "--check-chars", "--all-repeated", "--group"), "", (), "files"),
    "sort": ("kotST", ("--key", "--field-separator", "--output", "--buffer-size", "--temporary-directory",
                       "--parallel", "--batch-size", "--compress-program", "--random-source", "--sort"),
             "cC", ("--check", "--files0-from"), "files"),
    "base64": ("bow", ("--wrap", "--output", "--break"), "i", ("--input",), "files"),
    "sha256sum": ("", (), "", (), "files"),
    "sha512sum": ("", (), "", (), "files"),
    "sha1sum": ("", (), "", (), "files"),
    "md5sum": ("", (), "", (), "files"),
    "shasum": ("a", ("--algorithm",), "", (), "files"),
    "tac": ("s", ("--separator",), "", (), "files"),
    "rev": ("", (), "", (), "files"),
    "tr": ("", (), "", (), "free"),
    "tee": ("", ("--output-error",), "", (), "free"),
}
GREP_ARGS = "efmABCdD"
GREP_LONG_ARGS = ("--regexp", "--file", "--max-count", "--after-context", "--before-context",
                  "--context", "--directories", "--devices", "--label", "--binary-files",
                  "--include", "--exclude", "--exclude-from", "--exclude-dir", "--group-separator")
# -q stops at the first match, -l and -L at the first match of a file, -m
# at a count; -r and -R read the tree, not the pipe.
GREP_EARLY = "qlLmrR"
GREP_LONG_EARLY = ("--quiet", "--silent", "--files-with-matches", "--files-without-match",
                   "--max-count", "--recursive", "--dereference-recursive")
SED_ARGS = "efl"
XARGS_ARGS = "IJLnPRSsdaE"
# -E and -e end the input at a marker; -a reads a file instead.
XARGS_EARLY = "Eea"
XARGS_LONG_EARLY = ("--eof", "--arg-file")
JQ_ARITY = {"--arg": 2, "--argjson": 2, "--slurpfile": 2, "--rawfile": 2, "--indent": 1, "-L": 1}
# `input` and `inputs` read on from the filter, which may stop; `halt`
# ends the program.
JQ_STOPS = re.compile(r"\b(input|inputs|halt|halt_error)\b")
AWK_STOPS = re.compile(r"\b(exit|nextfile)\b")
LOOP_LEAVES = ("break", "exit", "return", "exec")
SHELLS = ("bash", "sh")
PYTHON = re.compile(r"python(3(\.[0-9]+)?)?")


def name_of(word):
    """The program a word names: its last path component, or None."""
    text = word.literal()
    if text is None:
        return None
    return text.rsplit("/", 1)[-1]


def program(words):
    """(index of the program word, its name) past the words that open a
    compound command and the assignments before it."""
    k = 0
    while k < len(words) and words[k].bare() in ("!", "time"):
        k += 1
    while k < len(words) and ASSIGNMENT.match(words[k].raw):
        k += 1
    if k >= len(words):
        return k, None
    return k, name_of(words[k])


def may_be_option(word):
    """Whether a word that is not all literal may start with a dash."""
    head = word.head()
    return head == "" or head.startswith("-")


def early_word(text, short, long_names):
    """Whether one literal word before `--` asks for a flag that stops the
    reader early. Every letter of a cluster counts, even where it may be an
    option's argument (`-eq`), and a long option counts by any prefix
    GNU getopt takes for it: a word read as a flag it is not refuses a
    pipe that could not fail, never the reverse."""
    if text.startswith("--"):
        name = text.split("=", 1)[0]
        return len(name) > 2 and any(full.startswith(name) for full in long_names)
    return text.startswith("-") and len(text) > 1 and any(ch in short for ch in text[1:])


def options(args, short_args, long_args, arity=None, stop_at_operand=False):
    """Split a program's arguments into (options, operands, problem).

    options are (flag, [argument words]); a problem is a word that is not
    literal where an option may stand."""
    arity = arity or {}
    found, operands = [], []
    i = 0
    while i < len(args):
        w = args[i]
        text = w.literal()
        if text is None:
            if may_be_option(w):
                return found, operands, w
            operands.append(w)
            i += 1
            if stop_at_operand:
                operands.extend(args[i:])
                break
            continue
        if text == "--":
            operands.extend(args[i + 1:])
            break
        if text.startswith("--"):
            name = text.split("=", 1)[0]
            n = arity.get(name, 1 if name in long_args and "=" not in text else 0)
            found.append((name, args[i + 1:i + 1 + n]))
            i += 1 + n
            continue
        if text.startswith("-") and text != "-":
            if text in arity:
                n = arity[text]
                found.append((text, args[i + 1:i + 1 + n]))
                i += 1 + n
                continue
            i += 1
            for j, ch in enumerate(text[1:], start=1):
                if ch in short_args:
                    rest = text[j + 1:]
                    if rest:
                        found.append(("-" + ch, [rest]))
                    else:
                        found.append(("-" + ch, args[i:i + 1]))
                        i += 1
                    break
                found.append(("-" + ch, []))
            continue
        operands.append(w)
        i += 1
        if stop_at_operand:
            operands.extend(args[i:])
            break
    return found, operands, None


def before_dashdash(args):
    out = []
    for w in args:
        if w.literal() == "--":
            break
        out.append(w)
    return out


def early_flag(args, short, long_names):
    for w in before_dashdash(args):
        text = w.literal()
        if text is not None and early_word(text, short, long_names):
            return text
    return None


def file_operands(operands):
    return [w for w in operands if w.literal() != "-"]


def show(words):
    """The reader as written, to its first line and at most 80 characters."""
    text = " ".join(w.raw for w in words).split("\n", 1)[0]
    return text if len(text) <= 80 else text[:77] + "..."


class Reader:
    """The judgement of one command that reads a pipe."""

    def __init__(self, lexed, index):
        self.lexed = lexed
        self.index = index
        self.command = lexed.commands[index]

    def piped_on(self):
        commands = self.lexed.commands
        k = self.index + 1
        return (k < len(commands) and commands[k].joined_by in ("|", "|&")
                and commands[k].scope == self.command.scope)

    def output(self):
        """Where the command's standard output goes: "pipe", "captured",
        "file", or a reason it may be /dev/null."""
        target = "inherited"
        for fd, (op, word) in zip(self.command.fds, self.command.redirects):
            if op in (">", ">>", ">|") and fd in (None, "1"):
                target = word
            elif op in ("&>", "&>>") and fd is None:
                target = word
            elif op == ">&" and fd in (None, "1"):
                text = word.literal() if word is not None else None
                target = word if fd is None and text is not None and not text.isdigit() and text != "-" else "a copy of another descriptor"
        if self.piped_on() and target == "inherited":
            return "pipe"
        if target == "inherited":
            scope = self.command.scope
            if scope and scope[-1] in self.lexed.substitutions:
                return "captured"
            return "the script's own output, which may be /dev/null"
        if isinstance(target, str):
            return target
        if target is None:
            return "a redirection with no target"
        text = target.literal()
        if text is None:
            head = target.head()
            if head and not head.startswith("/dev/"):
                return "file"
            return "a file named by a variable, which may be /dev/null"
        if text.startswith("/dev/"):
            return text
        return "file"

    def judge(self):
        """None when the command reads its input to the end, else why not."""
        words = self.command.words
        if not words:
            return "a reader with no command"
        first = words[0].bare()
        if first in ("{", "if", "for", "case", "select", "until", "[[", "(("):
            return "a compound command reads the pipe, and its commands may stop before the end"
        if first == "while":
            return self.loop()
        k, name = program(words)
        if name is None:
            return "a reader whose program the check cannot read"
        if name in self.lexed.functions:
            return "a function of the script reads the pipe, and it may stop before the end"
        args = words[k + 1:]
        if name in SPECS:
            return self.spec(name, args)
        if name == "grep":
            return self.grep(args)
        if name == "sed":
            return self.sed(args)
        if name == "awk":
            return self.awk(args)
        if name == "jq":
            return self.jq(args)
        if name == "xargs":
            return self.xargs(args)
        if name in ("mapfile", "readarray"):
            return self.mapfile(args)
        if name == "read":
            return "read takes one line and leaves the rest of the pipe unread"
        if name == "head":
            return "head stops after the lines it prints"
        if PYTHON.fullmatch(name):
            return self.python(args)
        return "%s is not a program the check knows to read its whole input" % name

    def spec(self, name, args):
        short_args, long_args, early, long_early, operands_are = SPECS[name]
        if operands_are == "free":
            # No option of these makes them stop before the end, and what
            # their operands name is not their input.
            return None
        flag = early_flag(args, early, long_early)
        if flag:
            return "%s %s stops before the end of its input, or reads another" % (name, flag)
        _, operands, problem = options(args, short_args, long_args)
        if problem is not None:
            return "a word that may expand to an option of %s (%s)" % (name, problem.raw)
        if operands_are == "files" and file_operands(operands):
            return "%s reads the file %s, not the pipe" % (name, file_operands(operands)[0].raw)
        return None

    def grep(self, args):
        flag = early_flag(args, GREP_EARLY, GREP_LONG_EARLY)
        if flag:
            return "grep %s stops before the end of its input" % flag
        found, operands, problem = options(args, GREP_ARGS, GREP_LONG_ARGS)
        if problem is not None:
            return "a word that may expand to an option of grep (%s): write the pattern after -e or --" % problem.raw
        given = any(flag in ("-e", "-f", "--regexp", "--file") for flag, _ in found)
        files = file_operands(operands if given else operands[1:])
        if files:
            return "grep reads the file %s, not the pipe" % files[0].raw
        out = self.output()
        if out not in ("pipe", "captured", "file"):
            return "grep's output is %s, and GNU grep stops at the first match when it is /dev/null" % out
        return None

    def sed(self, args):
        found, operands, problem = options(args, SED_ARGS, ("--expression", "--file", "--line-length"))
        if problem is not None:
            return "a word that may expand to an option of sed (%s)" % problem.raw
        scripts = [arg[0] for flag, arg in found if flag in ("-e", "--expression") and arg]
        if any(flag in ("-f", "--file") for flag, _ in found):
            return "a sed script read from a file, which the check cannot see"
        if not scripts:
            if not operands:
                return "sed with no script"
            scripts, operands = [operands[0]], operands[1:]
        for script in scripts:
            text = script.literal()
            if text is None:
                return "a sed script the check cannot read (%s)" % script.raw
            if "q" in text or "Q" in text:
                return "a sed script that may quit (q) before the end of its input"
        if file_operands(operands):
            return "sed reads the file %s, not the pipe" % file_operands(operands)[0].raw
        return None

    def awk(self, args):
        found, operands, problem = options(args, "fvF", ("--file", "--assign", "--field-separator", "--source"))
        if problem is not None:
            return "a word that may expand to an option of awk (%s)" % problem.raw
        if any(flag in ("-f", "--file") for flag, _ in found):
            return "an awk program read from a file, which the check cannot see"
        programs = [arg[0] for flag, arg in found if flag in ("-e", "--source") and arg]
        if not programs:
            if not operands:
                return "awk with no program"
            programs, operands = [operands[0]], operands[1:]
        for prog in programs:
            text = prog.literal()
            if text is None:
                return "an awk program the check cannot read (%s)" % prog.raw
            if AWK_STOPS.search(text):
                return "an awk program that may exit before the end of its input"
        for w in operands:
            if w.literal() == "-" or ASSIGNMENT.match(w.head() or ""):
                continue
            return "awk reads the file %s, not the pipe" % w.raw
        return None

    def jq(self, args):
        found, operands, problem = options(args, "fL", ("--from-file",), JQ_ARITY)
        if problem is not None:
            return "a word that may expand to an option of jq (%s)" % problem.raw
        flags = {flag for flag, _ in found}
        if flags & {"-n", "--null-input"}:
            return "jq -n reads no input"
        if flags & {"-f", "--from-file"}:
            return "a jq filter read from a file, which the check cannot see"
        if not operands:
            return "jq with no filter"
        text = operands[0].literal()
        if text is None:
            return "a jq filter the check cannot read (%s)" % operands[0].raw
        if JQ_STOPS.search(text):
            return "a jq filter that reads on with input or stops with halt"
        if not flags & {"--args", "--jsonargs"} and file_operands(operands[1:]):
            return "jq reads the file %s, not the pipe" % file_operands(operands[1:])[0].raw
        return None

    def xargs(self, args):
        found, operands, problem = options(args, XARGS_ARGS, (), stop_at_operand=True)
        if problem is not None:
            return "a word that may expand to an option of xargs (%s)" % problem.raw
        for flag, _ in found:
            if early_word(flag, XARGS_EARLY, XARGS_LONG_EARLY):
                return "xargs %s stops at a marker or reads a file instead" % flag
        return None

    def mapfile(self, args):
        found, _, problem = options(args, "dnOsuCc", ())
        if problem is not None:
            return "a word that may expand to an option of mapfile (%s)" % problem.raw
        for flag, _ in found:
            if flag in ("-n", "-u", "-C"):
                return "mapfile %s stops at a count, reads another descriptor or runs a callback" % flag
        return None

    def python(self, args):
        """Python reads all of a program it is handed on its standard input
        (`python3 -`) before it runs it; any other program it runs may stop
        reading the pipe where it likes."""
        i = 0
        while i < len(args):
            text = args[i].literal()
            if text is None:
                return "a word that may expand to an option of python (%s)" % args[i].raw
            if text == "-":
                return None
            if text in ("-W", "-X"):
                i += 2
                continue
            if text.startswith("-") and not text.startswith("--") and not set(text[1:]) & set("cmWX"):
                i += 1
                continue
            break
        return "a Python program reads the pipe, and the check cannot see that it reads it to the end: hand it a here-string or a file"

    def loop(self):
        """A `while read` loop reads to the end unless it is left early: no
        break, exit, return or exec in its body, and no function of the
        script, which may hold one."""
        words = self.command.words
        k, name = program(words[1:])
        cond = words[1 + k:]
        if name != "read":
            return "a while loop whose condition is not read may stop before the end of the pipe"
        found, _, problem = options(cond[1:], "adinNptu", ())
        if problem is not None:
            return "a word that may expand to an option of read (%s)" % problem.raw
        for flag, _ in found:
            if flag in ("-t", "-u"):
                return "read %s may end the loop before the end of the pipe" % flag
        depth = 1
        scope = self.command.scope
        for later in self.lexed.commands[self.index + 1:]:
            if later.scope[:len(scope)] != scope:
                continue
            leads = []
            for w in later.words:
                if w.bare() not in shell_words.LEADS:
                    break
                leads.append(w.bare())
            run = shell_words.opened(later.words)
            first = run[0].bare() if run else None
            if "while" in leads or "until" in leads or first in ("for", "select"):
                depth += 1
            if first == "done":
                depth -= 1
                if depth == 0:
                    return None
                continue
            _, name = program(run)
            if name in LOOP_LEAVES:
                return "the loop's body has %s, which leaves it before the end of the pipe" % name
            if name in self.lexed.functions:
                return "the loop's body calls %s, a function of the script that may leave it" % name
        return "a while loop the check cannot see the end of"


def nested_scripts(lexed):
    """(text, line of its first character) of every script a command hands
    to a shell: `bash -c TEXT`, `sh -c TEXT`, the words of `eval`, and the
    here-document a shell reads; and the commands whose script cannot be
    read."""
    found, unread = [], []
    for command in lexed.commands:
        words = command.words
        for k, w in enumerate(words):
            name = name_of(w)
            if name in SHELLS:
                j = k + 1
                while j < len(words):
                    text = words[j].literal()
                    if text in ("-o", "+o", "-O", "+O"):
                        j += 2
                        continue
                    if text is None or text[:1] not in ("-", "+") or text.startswith("--"):
                        break
                    if "c" in text[1:]:
                        script = words[j + 1] if j + 1 < len(words) else None
                        if script is None or script.literal() is None:
                            unread.append((command.line, "%s -c runs a script from a variable or a substitution, which the check cannot read" % name))
                        else:
                            found.append((script.literal(), script.line))
                        break
                    # A cluster that ends in o or O takes the next word as
                    # an option's name (`-euo pipefail`).
                    j += 2 if text[-1] in "oO" else 1
                if k == program(words)[0]:
                    for body, offset in lexed.bodies_of(command):
                        found.append((body, lexed.line_of(offset)))
            if name == "eval" and k == program(words)[0]:
                rest = words[k + 1:]
                if any(r.literal() is None for r in rest):
                    unread.append((command.line, "eval runs words from a variable or a substitution, which the check cannot read"))
                else:
                    found.append((" ".join(r.literal() for r in rest), command.line))
    return found, unread


def findings(text, first_line=1, line_of=None):
    """(line, the reader's words, why it may stop early) of every pipe in
    a shell script, its substitutions and the scripts it hands to a shell."""
    if line_of is None:
        starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]

        def line_of(offset):
            lo, hi = 0, len(starts)
            while lo + 1 < hi:
                mid = (lo + hi) // 2
                if starts[mid] <= offset:
                    lo = mid
                else:
                    hi = mid
            return first_line + lo
    lexed = shell_words.lex(text, line_of)
    out = [(line, "", "a script the check cannot read: %s" % message) for line, message in lexed.problems]
    for k, command in enumerate(lexed.commands):
        if command.joined_by in ("|", "|&"):
            reason = Reader(lexed, k).judge()
            if reason:
                out.append((command.line, show(command.words), reason))
    for line in lexed.piped_subshells:
        out.append((line, "( ... )", "a subshell reads the pipe, and its commands may stop before the end"))
    inner, unread = nested_scripts(lexed)
    out.extend((line, "", reason) for line, reason in unread)
    for body, line in inner:
        out.extend(findings(body, line))
    return sorted(set(out))
