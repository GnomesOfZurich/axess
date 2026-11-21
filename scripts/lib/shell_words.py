"""A shell script read as the shell reads it: commands made of words.

Used by scripts/check-workflow-pins.sh for the `run:` scripts of a workflow
and the repository scripts they run. The lexer takes the POSIX and bash
syntax a workflow script is written in: quotes of every kind (`'...'`,
`"..."`, `$'...'`), backslash escapes and continued lines, comments, the
operators that end a command (`;`, `&`, `|`, `&&`, `||`, `;;`, a line
break, a parenthesis), every redirection with its file descriptor and its
target (`>file`, `2>&1`, `<file`, `<<<word`, `2<&1`, `{fd}>file`), here-
documents with their bodies, and the substitutions inside a word (`$(...)`,
backticks, `$((...))`, `${...}`, `<(...)`, `${{ ... }}`), wherever one
stands: in a word, in the value a `${...}` falls back to, in an array.

A word keeps what it is made of: the literal text the shell passes on once
the quotes are removed, and each part an expansion fills in on the runner,
which the check cannot read. A word whose value can split into several
words (an expansion outside double quotes, `"$@"`, `"${a[@]}"`, or a
`${{ }}` the runner pastes in as text) says so, and so does a word the
shell expands into words it does not hold as written: an unquoted brace
expansion (`{a,b}`, `{1..3}`) or pathname pattern (`*`, `?`, `[...]`).
Inside `[[ ]]` nothing is expanded, and its parentheses, bars and angle
brackets belong to the expression. The commands inside a substitution, a subshell
or the body of a here-document whose delimiter is not quoted are commands
of the script like any other; what a quote holds is text. Each command
keeps the subshells and substitutions it stands in (`scope`), so that a
reader can tell a `cd` that moves the script from one that moves a
subshell alone. The text of every arithmetic expression (`$((...))`,
`((...))`, `for ((...))`) is kept with its line, the number of commands
read before it and its scope (`arithmetics`), since the shell evaluates
the values it names as arithmetic. The comments the shell skips are kept
with their offsets (`comments`), for the rules about how a comment is
written.
"""

import re

# A quoted expansion that still makes one word per element: "$@", "${@...}", "${a[@]}".
QUOTED_LIST = re.compile(r"\$(@|\{!?(@|[A-Za-z_][A-Za-z0-9_]*\[@\]))")
ARRAY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")
REDIRECT = re.compile(r"(\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?(<<<|<<-|<<|<>|<&|>&|>>|>\||&>>|&>|<|>)")
OPERATORS = ("&&", "||", ";;", ";&", "|&", "|", "&", ";")
# A character the shell takes as written: quoted, escaped or an expansion.
QUOTED = "\x00"
ANSI_C = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b",
          "E": "\x1b", "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


# Words that open a compound command before the command it runs.
LEADS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"}


def opened(words):
    """The words of a command past those that open a compound one: the
    command `do case x in` runs is the `case`."""
    k = 0
    while k < len(words) and words[k].bare() in LEADS:
        k += 1
    return words[k:]


def bodies(script):
    """{name: the commands of its body} for each function of a script
    whose body is a brace group, which is where the reader can tell the
    body's end: the commands from the `{` that opens it to the `}` that
    closes it. A function with a body of another kind is left out."""
    out = {}
    for name, start in script.definitions:
        depth, body = 0, []
        for command in script.commands[start:]:
            bare = [w.bare() for w in command.words]
            lead = 0
            while lead < len(bare) and (bare[lead] in LEADS or bare[lead] == "function" or (lead and bare[lead - 1] == "function")):
                depth += bare[lead] == "{"
                lead += 1
            if depth == 0:
                break
            if bare[:1] == ["}"]:
                depth -= 1
                if depth == 0:
                    out[name] = body
                    break
            body.append(command)
    return out


def in_conditional(words):
    """Whether the words so far open a `[[` that no `]]` has closed."""
    k = 0
    while k < len(words) and words[k].bare() in LEADS:
        k += 1
    return k < len(words) and words[k].bare() == "[[" and not any(w.bare() == "]]" for w in words[k + 1:])


def expands(bare):
    """Whether the unquoted text of a word (each quoted, escaped or expanded
    character standing as QUOTED) makes the shell expand it into words it
    does not hold as written: a brace expansion (`{a,b}`, `{1..3}`) or a
    pathname pattern (`*`, `?`, `[...]`)."""
    if "*" in bare or "?" in bare or re.search(r"\[[^]]+\]", bare):
        return True
    opened = []
    for k, c in enumerate(bare):
        if c == "{":
            opened.append(k)
        elif c == "}" and opened:
            inner = bare[opened.pop() + 1:k]
            if "," in inner or re.fullmatch(r"-?[A-Za-z0-9]+\.\.-?[A-Za-z0-9]+(\.\.-?[0-9]+)?", inner):
                return True
    return False


class Word:
    """A word: literal parts (quotes removed) and the expansions among them."""

    def __init__(self, line):
        self.parts = []
        self.line = line
        self.raw = ""
        self.splits = False

    def lit(self, text):
        if text:
            self.parts.append(("lit", text))

    def exp(self, text, splits=False):
        self.parts.append(("exp", text))
        self.splits = self.splits or splits

    def literal(self):
        """The word's text, or None when an expansion fills in part of it."""
        if any(kind == "exp" for kind, _ in self.parts):
            return None
        return "".join(text for _, text in self.parts)

    def bare(self):
        """The word's text when it is written with no quote, escape or
        expansion, as a reserved word must be; None otherwise. A quoted or
        escaped `case` is a command named case, not the start of one."""
        literal = self.literal()
        return literal if literal == self.raw else None

    def head(self):
        """The literal text before the first expansion."""
        out = []
        for kind, text in self.parts:
            if kind == "exp":
                break
            out.append(text)
        return "".join(out)

    def tail(self):
        """The literal text after the last expansion."""
        out = []
        for kind, text in reversed(self.parts):
            if kind == "exp":
                break
            out.append(text)
        return "".join(reversed(out))


class Command:
    """A simple command: its words, its redirections, how it was joined and
    the subshells and substitutions it stands in, outermost first."""

    def __init__(self, line, joined_by, scope=()):
        self.words = []
        self.redirects = []
        # The file descriptor written before each redirection, or None.
        self.fds = []
        self.line = line
        self.joined_by = joined_by
        self.scope = scope


class Script:
    """The commands of one script and what could not be read."""

    def __init__(self, text, line_of):
        self.text = text
        self.line_of = line_of
        self.commands = []
        self.problems = []
        # (offset, text) of each comment the shell skips, `#` included.
        self.comments = []
        self.heredocs = []
        self.bodies = {}
        self.functions = set()
        self.definitions = []
        self.arithmetics = []
        self.scopes = 0
        # The scopes that are command or process substitutions (their output
        # is read by the shell), and the lines where a subshell reads a pipe.
        self.substitutions = set()
        self.piped_subshells = []
        self.i = 0

    def bodies_of(self, command):
        """(text, offset) of each here-document body the command reads."""
        return self.bodies.get(id(command), [])

    def problem(self, offset, message):
        self.problems.append((self.line_of(min(offset, max(len(self.text) - 1, 0))), message))


def lex(text, line_of):
    """The Script of `text`; `line_of(offset)` maps an offset to a line."""
    script = Script(text, line_of)
    Lexer(script).commands(stop=None)
    return script


class Lexer:
    def __init__(self, script):
        self.s = script
        self.t = script.text
        self.scope = ()

    @property
    def i(self):
        return self.s.i

    @i.setter
    def i(self, value):
        self.s.i = value

    def enter(self):
        """Open a subshell or a substitution: a scope of its own."""
        self.s.scopes += 1
        self.scope += (self.s.scopes,)

    def commands(self, stop):
        """Read commands until the end, or until the `)` that closes a `$(`,
        whose commands stand in a scope of their own."""
        if stop is None:
            return self.read(stop)
        self.enter()
        self.s.substitutions.add(self.scope[-1])
        try:
            return self.read(stop)
        finally:
            self.scope = self.scope[:-1]

    def read(self, stop):
        t = self.t
        cur = None
        joined = "\n"
        depth = 0
        case_depth = 0
        pattern = False

        def finish():
            nonlocal cur, case_depth, pattern
            if cur is not None and (cur.words or cur.redirects):
                run = opened(cur.words)
                first = run[0].bare() if run else None
                if first == "case":
                    case_depth += 1
                    pattern = True
                elif first == "esac" and case_depth:
                    case_depth -= 1
                elif first == "function" and len(run) > 1:
                    self.s.functions.add(run[1].literal())
                    self.s.definitions.append((run[1].literal(), len(self.s.commands)))
                self.s.commands.append(cur)
            cur = None

        while self.i < len(t):
            c = t[self.i]
            if c in " \t":
                self.i += 1
                continue
            if t.startswith("\\\n", self.i):
                self.i += 2
                continue
            if c == "\n":
                finish()
                joined = "\n"
                self.i += 1
                self.bodies()
                continue
            if c == "#":
                end = t.find("\n", self.i)
                end = len(t) if end == -1 else end
                self.s.comments.append((self.i, t[self.i:end]))
                self.i = end
                continue
            if cur is not None and in_conditional(cur.words):
                # A conditional expression: its parentheses, bars and angle
                # brackets belong to it, and its words are not expanded.
                if c in "()|&<>":
                    self.i += 1
                elif c == ";":
                    self.s.problem(self.i, "a conditional expression that does not close")
                    finish()
                else:
                    cur.words.append(self.word(conditional=True))
                continue
            if c == ")" and pattern and case_depth:
                cur = None
                pattern = False
                joined = ")"
                self.i += 1
                continue
            if c == ")":
                finish()
                self.i += 1
                if depth:
                    depth -= 1
                    self.scope = self.scope[:-1]
                    joined = ")"
                    continue
                if stop == ")":
                    return
                self.s.problem(self.i - 1, "a closing parenthesis that closes nothing")
                continue
            if c == "(" and not t.startswith("((", self.i):
                if pattern and case_depth and cur is None:
                    self.i += 1
                    continue
                defined = cur is not None and len(cur.words) == 1 and re.match(r"[ \t]*\)", t[self.i + 1:])
                if defined:
                    self.s.functions.add(cur.words[0].literal())
                finish()
                if defined:
                    self.s.definitions.append((self.s.commands[-1].words[0].literal(), len(self.s.commands)))
                elif joined in ("|", "|&"):
                    self.s.piped_subshells.append(self.s.line_of(self.i))
                depth += 1
                self.enter()
                joined = "("
                self.i += 1
                continue
            if c == "(":
                self.i = self.arithmetic(self.i + 2)
                continue
            m = REDIRECT.match(t, self.i)
            if m and not (m.group(2) in ("<", ">") and t[m.end():m.end() + 1] == "("):
                if cur is None:
                    cur = Command(self.s.line_of(self.i), joined, self.scope)
                self.i = m.end()
                cur.fds.append(m.group(1))
                self.redirect(cur, m.group(2))
                continue
            op = next((o for o in OPERATORS if t.startswith(o, self.i)), None)
            if op:
                if op == "|" and pattern and case_depth:
                    cur = None
                    self.i += 1
                    continue
                finish()
                joined = op
                if op in (";;", ";&"):
                    pattern = True
                self.i += len(op)
                continue
            if cur is None:
                cur = Command(self.s.line_of(self.i), joined, self.scope)
            word = self.word()
            if pattern and case_depth:
                if word.bare() == "esac":
                    case_depth -= 1
                    pattern = False
                    cur = None
                    continue
            if opened(cur.words)[:1] and opened(cur.words)[0].bare() == "case" and word.bare() == "in":
                cur.words.append(word)
                finish()
                continue
            cur.words.append(word)
        finish()
        if stop == ")":
            self.s.problem(len(t), "a substitution that does not close")

    def arithmetic(self, i):
        """The index after the `))` that closes an arithmetic expression whose
        `((` ends just before i. A substitution inside it runs; it is read."""
        t = self.t
        start = i
        depth = 2
        while i < len(t):
            if t[i] == "(":
                depth += 1
            elif t[i] == ")":
                depth -= 1
                if depth == 0:
                    self.s.arithmetics.append((self.s.line_of(start), t[start:i - 1], len(self.s.commands), self.scope))
                    self.expansions(start, i)
                    return i + 1
            i += 1
        self.s.problem(len(t), "an arithmetic expression that does not close")
        return len(t)

    def redirect(self, cur, op):
        t = self.t
        while self.i < len(t) and t[self.i] in " \t":
            self.i += 1
        substitution = t.startswith("<(", self.i) or t.startswith(">(", self.i)
        if self.i >= len(t) or (t[self.i] in "\n;&|()<>" and not substitution):
            self.s.problem(self.i, "a redirection with no target")
            cur.redirects.append((op, None))
            return
        target = self.word()
        cur.redirects.append((op, target))
        if op in ("<<", "<<-"):
            quoted = any(ch in target.raw for ch in "'\"\\")
            delimiter = target.literal()
            if delimiter is None:
                self.s.problem(self.i, "a here-document delimiter from an expansion")
                return
            self.s.heredocs.append((delimiter, op == "<<-", quoted, cur))

    def bodies(self):
        """Read the bodies of the here-documents the line just ended opened."""
        pending, self.s.heredocs = self.s.heredocs, []
        t = self.t
        for delimiter, tabs, quoted, command in pending:
            start = self.i
            while True:
                if self.i >= len(t):
                    self.s.problem(start, "a here-document with no closing %s" % delimiter)
                    return
                end = t.find("\n", self.i)
                end = len(t) if end == -1 else end
                line = t[self.i:end]
                if (line.lstrip("\t") if tabs else line) == delimiter:
                    body_end = self.i
                    self.i = min(end + 1, len(t))
                    break
                self.i = end + 1
            self.s.bodies.setdefault(id(command), []).append((t[start:body_end], start))
            if not quoted:
                self.expansions(start, body_end)

    def expansions(self, start, end):
        """Read the substitutions in t[start:end] as commands of the script."""
        saved = self.i
        j = start
        t = self.t
        while j < end:
            if t[j] == "\\":
                j += 2
                continue
            if t.startswith("$((", j):
                j = self.arithmetic(j + 3)
                continue
            if t.startswith("$(", j):
                self.i = j + 2
                self.commands(stop=")")
                j = self.i
                continue
            if t[j] == "`":
                close = self.backtick_end(j)
                self.nested(t[j + 1:close - 1].replace("\\`", "`"), j + 1)
                j = close
                continue
            j += 1
        self.i = saved

    def nested(self, text, offset):
        line_of = self.s.line_of
        inner = lex(text, lambda k: line_of(offset + k))
        # The inner script numbers its scopes from 1; they are moved past
        # the outer script's so that no two scopes share a number.
        self.s.scopes += 1
        own = self.s.scopes
        self.s.scopes += inner.scopes
        for command in inner.commands:
            command.scope = self.scope + (own,) + tuple(own + k for k in command.scope)
        self.s.substitutions.add(own)
        self.s.substitutions.update(own + k for k in inner.substitutions)
        self.s.piped_subshells.extend(inner.piped_subshells)
        self.s.commands.extend(inner.commands)
        self.s.problems.extend(inner.problems)

    def backticks(self, j):
        """Read the backtick substitution that opens at j as commands of the
        script; the index after it."""
        close = self.backtick_end(j)
        self.nested(self.t[j + 1:close - 1].replace("\\`", "`"), j + 1)
        return close

    def backtick_end(self, j):
        t = self.t
        k = j + 1
        while k < len(t):
            if t[k] == "`":
                return k + 1
            k += 2 if t[k] == "\\" else 1
        self.s.problem(j, "a backtick substitution that does not close")
        return len(t)

    def word(self, conditional=False):
        t = self.t
        start = self.i
        w = Word(self.s.line_of(self.i))
        bare = []
        while self.i < len(t):
            c = t[self.i]
            bare.append(QUOTED)
            if c in "<>" and t[self.i + 1:self.i + 2] == "(":
                self.i += 2
                self.commands(stop=")")
                w.exp(t[start:self.i])
                continue
            if c == "(" and ARRAY.fullmatch(t[start:self.i]):
                self.i = self.array_end(self.i + 1)
                w.exp(t[start:self.i])
                continue
            if c in " \t\n;&|()<>":
                break
            if c == "\\":
                if t[self.i + 1:self.i + 2] == "\n":
                    self.i += 2
                    continue
                w.lit(t[self.i + 1:self.i + 2])
                self.i += 2
            elif c == "'":
                close = t.find("'", self.i + 1)
                if close == -1:
                    self.s.problem(self.i, "a quote that does not close")
                    close = len(t)
                w.lit(t[self.i + 1:close])
                self.i = close + 1
            elif c == '"':
                self.dquote(w)
            elif c == "$":
                self.dollar(w)
            elif c == "`":
                close = self.backtick_end(self.i)
                self.nested(t[self.i + 1:close - 1].replace("\\`", "`"), self.i + 1)
                w.exp(t[self.i:close], splits=True)
                self.i = close
            else:
                w.lit(c)
                bare[-1] = c
                self.i += 1
        w.raw = t[start:self.i]
        if not conditional and not ARRAY.match("".join(bare)) and expands("".join(bare)):
            w.parts = [("exp", w.raw)]
            w.splits = True
        return w

    def array_end(self, i):
        """The index after the `)` that closes an array assignment whose body starts at i."""
        t = self.t
        while i < len(t):
            c = t[i]
            if c == "\\":
                i += 2
            elif c == "'":
                close = t.find("'", i + 1)
                i = len(t) if close == -1 else close + 1
            elif c == '"':
                saved = self.i
                self.i = i
                self.dquote(Word(None))
                i, self.i = self.i, saved
            elif c == "#" and t[i - 1] in " \t\n":
                end = t.find("\n", i)
                i = len(t) if end == -1 else end
            elif c == "$":
                saved = self.i
                self.i = i
                self.dollar(Word(None))
                i, self.i = self.i, saved
            elif c == "`":
                i = self.backticks(i)
            elif c in "<>" and t[i + 1:i + 2] == "(":
                saved = self.i
                self.i = i + 2
                self.commands(stop=")")
                i, self.i = self.i, saved
            elif c == ")":
                return i + 1
            else:
                i += 1
        self.s.problem(len(t), "an array that does not close")
        return len(t)

    def dquote(self, w):
        t = self.t
        opened = self.i
        self.i += 1
        while self.i < len(t):
            c = t[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "\\" and t[self.i + 1:self.i + 2] in ("$", "`", '"', "\\", "\n"):
                if t[self.i + 1] != "\n":
                    w.lit(t[self.i + 1])
                self.i += 2
            elif c == "$":
                self.dollar(w, quoted=True)
            elif c == "`":
                close = self.backtick_end(self.i)
                self.nested(t[self.i + 1:close - 1].replace("\\`", "`"), self.i + 1)
                w.exp(t[self.i:close])
                self.i = close
            else:
                w.lit(c)
                self.i += 1
        self.s.problem(opened, "a quote that does not close")

    def dollar(self, w, quoted=False):
        """An expansion at `$`; outside double quotes its value splits."""
        t = self.t
        start = self.i
        if t.startswith("${{", self.i):
            end = t.find("}}", self.i)
            end = len(t) if end == -1 else end + 2
            w.exp(t[start:end], splits=True)
            self.i = end
        elif t.startswith("$((", self.i):
            self.i = self.arithmetic(self.i + 3)
            w.exp(t[start:self.i], splits=not quoted)
        elif t.startswith("$(", self.i):
            self.i += 2
            self.commands(stop=")")
            w.exp(t[start:self.i], splits=not quoted)
        elif t.startswith("${", self.i):
            self.i = self.brace_end(self.i + 2)
            w.exp(t[start:self.i], splits=not quoted or QUOTED_LIST.match(t, start) is not None)
        elif t.startswith("$'", self.i) and not quoted:
            self.ansi_c(w)
        elif t.startswith('$"', self.i) and not quoted:
            self.i += 1
        else:
            m = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])").match(t, self.i)
            if m:
                w.exp(m.group(0), splits=not quoted or m.group(1) == "@")
                self.i = m.end()
            else:
                w.lit("$")
                self.i += 1

    def brace_end(self, i):
        """The index after the `}` that closes a `${` whose body starts at i."""
        t = self.t
        depth = 1
        while i < len(t):
            c = t[i]
            if c == "\\":
                i += 2
                continue
            if c == "'":
                close = t.find("'", i + 1)
                i = len(t) if close == -1 else close + 1
                continue
            if c == '"':
                saved = self.i
                self.i = i
                self.dquote(Word(None))
                i = self.i
                self.i = saved
                continue
            if t.startswith("$(", i) and not t.startswith("$((", i):
                saved = self.i
                self.i = i + 2
                self.commands(stop=")")
                i = self.i
                self.i = saved
                continue
            if c == "`":
                i = self.backticks(i)
                continue
            if t.startswith("$((", i):
                i = self.arithmetic(i + 3)
                continue
            if t.startswith("${", i):
                depth += 1
                i += 2
                continue
            if c == "}":
                depth -= 1
                i += 1
                if depth == 0:
                    return i
                continue
            i += 1
        self.s.problem(len(t), "a parameter expansion that does not close")
        return len(t)

    def ansi_c(self, w):
        t = self.t
        self.i += 2
        out = []
        while self.i < len(t) and t[self.i] != "'":
            if t[self.i] == "\\" and self.i + 1 < len(t):
                code = t[self.i + 1]
                m = re.compile(r"x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|([0-7]{1,3})").match(t, self.i + 1)
                if code in ANSI_C:
                    out.append(ANSI_C[code])
                    self.i += 2
                elif m:
                    out.append(chr(int(next(g for g in m.groups() if g), 8 if m.group(4) else 16)))
                    self.i = m.end()
                else:
                    out.append("\\" + code)
                    self.i += 2
            else:
                out.append(t[self.i])
                self.i += 1
        if self.i >= len(t):
            self.s.problem(self.i, "a quote that does not close")
        self.i += 1
        w.lit("".join(out))
