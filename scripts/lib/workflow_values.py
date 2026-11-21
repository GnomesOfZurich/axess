"""What a script assigns to its variables, for scripts/check-workflow-pins.sh.

A rule that holds a job beside a secret sometimes needs to know what a
variable can hold: whether the shell may evaluate it as arithmetic, which
host a URL in it names, whether a path in it is one of a temporary
directory. The script is read whole: every assignment to a name, wherever
it stands, is one of its values, and a name is known only when every one of
them is known. A name the script never assigns comes from the environment,
the runner or a caller, and is known only when the runner itself sets it
(the URLs of the runner's services, `$#`, `$?`, `$RANDOM`, ...).

  - A number the script made: every value is a literal, an arithmetic
    expansion whose operands are such numbers, or a command substitution
    whose output is a number by its form (`date +%s`, `wc -l`, `grep -c`,
    `expr`, `echo 0`, joined by `||`, `&&` or `;`, the last of a pipeline).
  - A literal: every value is written out, and the values are known.
"""

import re

import shell_words

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\+?=")
DECLARERS = {"export", "declare", "typeset", "readonly", "local"}
# Names whose value the shell itself sets to a number.
SHELL_NUMBERS = {"#", "?", "$", "!", "RANDOM", "SECONDS", "LINENO", "BASHPID", "PPID", "UID", "EUID",
                 "SRANDOM", "EPOCHSECONDS", "OPTIND"}
# Variables the runner sets to the URL of one of its services, which no
# script or `env:` may set (scripts/lib/workflow_runners.py).
RUNNER_URLS = {"ACTIONS_ID_TOKEN_REQUEST_URL": "the runner's OIDC token service",
               "GITHUB_API_URL": "api.github.com", "GITHUB_SERVER_URL": "github.com",
               "GITHUB_GRAPHQL_URL": "api.github.com"}
# The value of a name an arithmetic expression or `let` assigns.
ARITHMETIC = [("exp", "$((0))")]
# The literal text of a number: what an arithmetic expression may read
# from a value without evaluating a name.
NUMBER_TEXT = re.compile(r"\s*-?(0[xX][0-9A-Fa-f]+|[0-9]+(#[0-9A-Za-z@_]+)?)?\s*")
# A date format that prints digits alone.
DIGITS_FORMAT = re.compile(r"\+(%[sYmdHMSjuwNeVGg]|[0-9])+")


def value_of(word):
    """The parts of an assignment word after its `=`."""
    parts, seen = [], False
    for kind, text in word.parts:
        if seen:
            parts.append((kind, text))
        elif kind == "lit" and "=" in text:
            seen = True
            rest = text.split("=", 1)[1]
            if rest:
                parts.append(("lit", rest))
        elif kind == "exp":
            return None
    return parts if seen else None


def number_output(text):
    """Whether the commands of a substitution print a number by their form."""
    lexed = shell_words.lex(text, lambda offset: 1)
    if lexed.problems or not lexed.commands:
        return False
    for k, command in enumerate(lexed.commands):
        last = k + 1 == len(lexed.commands) or lexed.commands[k + 1].joined_by not in ("|", "|&")
        if not last:
            continue
        words = [w for w in command.words if not ASSIGNMENT.match(w.raw)]
        literals = [w.literal() for w in words]
        if not words or literals[0] is None:
            return False
        name = literals[0].rsplit("/", 1)[-1]
        rest = literals[1:]
        if name in ("echo", "printf") and len(rest) == 1 and re.fullmatch(r"-?[0-9]+", rest[0] or ""):
            continue
        if name == "date" and rest and rest[-1] is not None and DIGITS_FORMAT.fullmatch(rest[-1]):
            continue
        if name == "wc" and any(r in ("-l", "-c", "-w", "-m") for r in rest):
            continue
        if name == "grep" and any(r is not None and re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", r) for r in rest):
            continue
        if name in ("expr", "true", ":"):
            continue
        return False
    return True


class Values:
    """The values a script assigns, read once for the rules that ask."""

    def __init__(self, lexed):
        self.assigned = {}
        self.functions = shell_words.bodies(lexed)
        self.first = {}
        self.commands = lexed.commands
        # The command `f` of `f() { ...; }` names the function it defines.
        self.definitions = {id(lexed.commands[start - 1]) for _, start in lexed.definitions
                            if 0 < start <= len(lexed.commands) and len(lexed.commands[start - 1].words) == 1}
        for command in lexed.commands:
            self.read(command)
        self.order = {id(c): k for k, c in enumerate(lexed.commands)}
        self.paths = self.blocks(lexed)
        # A name an arithmetic expression assigns holds a number.
        for _, expression, _, _ in lexed.arithmetics:
            for name in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:[-+*/%&|^]|<<|>>)?=(?!=)|([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\+|--)|(?:\+\+|--)\s*([A-Za-z_][A-Za-z0-9_]*)", expression):
                self.add(next(n for n in name if n), ARITHMETIC)

    def add(self, name, value, command=None):
        self.assigned.setdefault(name, []).append(value)
        if command is not None and value is not None and not mentions(value, name):
            self.first.setdefault(name, []).append(command)

    def blocks(self, lexed):
        """The block each command stands in, as a path of block numbers: an
        `if`, `elif` or `else` branch, a loop body, a `case` arm or the
        body of a function opens one, and a command runs whenever the
        commands of every block on its path run."""
        paths, stack, number = {}, [], 0
        ends = {id(lexed.commands[self.order[id(body[-1])] + 1]) for body in self.functions.values()
                if body and self.order[id(body[-1])] + 1 < len(lexed.commands)}
        for k, command in enumerate(lexed.commands):
            bare = [w.bare() for w in command.words]
            run = [w.bare() for w in shell_words.opened(command.words)]
            leads = bare[:len(bare) - len(run)]
            if run[:1] and run[0] in ("fi", "done", "esac") and stack:
                stack.pop()
            if id(command) in ends and stack:
                stack.pop()
            if any(b in ("elif", "else") for b in leads) or (command.joined_by == ")" and stack and stack[-1][0] == "case"):
                number += 1
                stack[-1:] = [(stack[-1][0] if stack else "if", number)]
            paths[id(command)] = tuple(n for _, n in stack)
            for opener in [b for b in leads if b in ("if", "while", "until")] + [b for b in run[:1] if b in ("for", "select", "case")]:
                number += 1
                stack.append(("case" if opener == "case" else "block", number))
            if id(command) in self.definitions:
                number += 1
                stack.append(("function", number))
        return paths

    def before(self, name, index, path, scope):
        """Whether an assignment that reads nothing of the name sets it on
        every way to a read at command `index`, in block `path` and `scope`:
        a command before it, outside a pipeline and the right of `||` or
        `&&`, in a block and a scope that hold the read."""
        for command in self.first.get(name, []):
            k = self.order[id(command)]
            nxt = self.commands[k + 1] if k + 1 < len(self.commands) else None
            if (k < index and command.joined_by not in ("|", "|&", "||", "&&")
                    and (nxt is None or nxt.joined_by not in ("|", "|&"))
                    and path[:len(self.paths[id(command)])] == self.paths[id(command)]
                    and scope[:len(command.scope)] == command.scope):
                return True
        return False

    def read(self, command):
        words = command.words
        k = 0
        while k < len(words) and words[k].bare() in shell_words.LEADS:
            k += 1
        while k < len(words) and ASSIGNMENT.match(words[k].raw) and "[" not in words[k].raw.split("=")[0]:
            self.add(ASSIGNMENT.match(words[k].raw).group(1), value_of(words[k]), command)
            k += 1
        for w in words:
            for kind, text in w.parts:
                for m in re.finditer(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?=([^}]*)\}", text) if kind == "exp" else ():
                    self.add(m.group(1), [("lit", m.group(2))] if "$" not in m.group(2) and "`" not in m.group(2) else None)
        if k >= len(words):
            return
        head, rest = words[k], words[k + 1:]
        name = head.literal()
        if head.bare() in ("for", "select") and rest:
            given = rest[2:] if len(rest) > 1 and rest[1].bare() == "in" else []
            values = [list(w.parts) if not w.splits and w.literal() is not None else None for w in given]
            for value in values or [None]:
                self.add(rest[0].literal() or "", value)
        elif name in DECLARERS:
            for w in rest:
                m = ASSIGNMENT.match(w.raw)
                if m:
                    self.add(m.group(1), value_of(w), command)
                elif w.literal() and NAME.fullmatch(w.literal()):
                    self.add(w.literal(), [], command)
        elif name in ("read", "mapfile", "readarray", "getopts", "printf", "wait"):
            for w in rest:
                if w.literal() and NAME.fullmatch(w.literal()):
                    self.add(w.literal(), None)
        if name == "let":
            for w in rest:
                m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", w.literal() or "")
                if m:
                    self.add(m.group(1), ARITHMETIC)

    # What a name can hold.

    def number(self, name):
        """Whether every value of `name` is a number the script made: a
        number written out, the result of arithmetic, a substitution that
        prints a number by its form, `$?` or `$#`."""
        if name in SHELL_NUMBERS:
            return True
        values = self.assigned.get(name)
        if not values:
            return False
        for value in values:
            if value is None:
                return False
            for kind, text in value:
                if kind == "lit" and NUMBER_TEXT.fullmatch(text):
                    continue
                # The result of arithmetic is a number; its operands are
                # judged where it stands, as arithmetic of its own.
                if kind == "exp" and (text.startswith("$((") and text.endswith("))") or re.fullmatch(r"\$\{?[#?]\}?|\$\{#[^}]*\}", text)):
                    continue
                if kind == "exp" and text.startswith("$(") and text.endswith(")") and number_output(text[2:-1]):
                    continue
                return False
        return True

    def path_at(self, index):
        """The block of the command read at `index`, or of the last one."""
        if not self.commands:
            return ()
        return self.paths[id(self.commands[min(index, len(self.commands) - 1)])]

    def operand_number(self, operand, index, scope):
        """Whether an operand of arithmetic read before command `index`, in
        `scope` (a name, `$name`, `${name}`, a number, a length) is a
        number: one written out, one the shell sets, or a name every value
        of which is a number the script made and which an assignment sets
        on every way to the read."""
        if re.fullmatch(r"[0-9]+(#[0-9A-Za-z@_]*)?|0[xX][0-9A-Fa-f]+|\$\{#[^}]*\}", operand):
            return True
        m = re.fullmatch(r"\$?\{?([A-Za-z_][A-Za-z0-9_]*|[#?$!])(:?-[0-9]*)?\}?", operand)
        if m is None:
            return False
        name = m.group(1)
        return name in SHELL_NUMBERS or (self.number(name) and self.before(name, index, self.path_at(index), scope))

    def literals(self, name):
        """The values of `name` when every one is written out, else None."""
        values = self.assigned.get(name)
        if not values or any(v is None or any(kind != "lit" for kind, _ in v) for v in values):
            return None
        return {"".join(text for _, text in v) for v in values}

    def host(self, word):
        """The host a URL word names, when it is written out, comes from a
        variable whose every value is written out, or from a variable the
        runner sets to the URL of one of its services; else None. The text
        after the host is written out up to a `/`, a `?` or the word's end,
        so that no expansion after it extends the name."""
        parts = []
        for kind, part in word.parts:
            if kind == "lit" and parts and parts[-1][0] == "lit":
                parts[-1] = ("lit", parts[-1][1] + part)
            else:
                parts.append((kind, part))
        if not parts:
            return None
        follow = []
        for kind, part in parts[1:]:
            if kind != "lit":
                break
            follow.append(part)
        follow = "".join(follow)
        whole = len(parts) == 1 + len([p for p in parts[1:] if p[0] == "lit"]) and all(p[0] == "lit" for p in parts[1:])
        if parts[0][0] == "lit":
            return host_of(parts[0][1] + follow, whole)
        m = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", parts[0][1])
        if m is None:
            return None
        if m.group(1) in RUNNER_URLS and self.assigned.get(m.group(1)) is None:
            return RUNNER_URLS[m.group(1)] if whole or re.match(r"[/?&]", follow) else None
        values = self.literals(m.group(1))
        hosts = {host_of(v + follow, whole) for v in values} if values else {None}
        return hosts.pop() if len(hosts) == 1 else None


def mentions(value, name):
    """Whether an assignment's value reads the name it assigns: as `$name`
    or `${name...}`, or as a name inside arithmetic."""
    for kind, text in value:
        if kind != "exp":
            continue
        if re.search(r"\$\{?%s\b" % re.escape(name), text):
            return True
        if text.startswith("$((") and re.search(r"(?<![A-Za-z0-9_$])%s\b" % re.escape(name), text[3:-2]):
            return True
    return False


def host_of(url, whole=True):
    """The host of a URL written out to its host, or None. When an
    expansion follows the text (`whole` false), the host must end at a
    `/` or a `?` written out."""
    m = re.match(r"https?://([A-Za-z0-9.-]+)(?::[0-9]+)?(/|\?|$)", url)
    if not m or (not whole and m.group(2) == ""):
        return None
    return m.group(1).lower()


def operands(text):
    """The names, expansions, numbers and substitutions an arithmetic
    expression holds, in order."""
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if text.startswith("$(", i) or c == "`":
            out.append("$(substitution)")
            depth, i = 0, i + (1 if c == "`" else 2)
            if c == "`":
                close = text.find("`", i)
                i = len(text) if close == -1 else close + 1
                continue
            while i < len(text) and not (text[i] == ")" and depth == 0):
                depth += {"(": 1, ")": -1}.get(text[i], 0)
                i += 1
            i += 1
            continue
        m = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9#?$!@*-]|[A-Za-z_][A-Za-z0-9_]*|[0-9]+#[0-9A-Za-z@_]*|0[xX][0-9A-Fa-f]+|[0-9]+").match(text, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            if i < len(text) and text[i] == "[" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", m.group(0)):
                out.append("an array subscript")
        else:
            i += 1
    return out
