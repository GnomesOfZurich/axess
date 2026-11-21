"""The arithmetic of a script, for scripts/check-workflow-pins.sh.

bash evaluates as arithmetic the text of `$((...))`, `((...))`,
`for ((...))`, `$[...]` and `let`, the operands of `-eq`, `-lt` and the
like inside `[[ ]]`, an array subscript (`${a[i]}`, `a[i]=`, `unset
'a[i]'`, `read 'a[i]'`, `[[ -v a[i] ]]`) and the offsets of
`${x:offset:length}`. It evaluates the value of every name in
that text as arithmetic in turn, and a subscript in a value runs the
command it holds: `x='a[$(id)]'; echo $((x))` runs `id`. So in a job that
holds a secret, an OIDC permission or a token that can write, every
operand of every such text is a number the script made
(scripts/lib/workflow_values.py), a number written out, or a number the
shell sets (`$#`, `$?`); and an integer variable (`declare -i`), every
assignment to which is arithmetic, is refused by name. `[ ]` and `test`
compare integers and evaluate nothing, so they are not judged.
"""

import re

import shell_words
from workflow_values import operands

COMPARE = {"-eq", "-ne", "-lt", "-le", "-gt", "-ge"}
# The text of a legacy arithmetic expansion, `$[...]`, which the reader
# does not take apart: it is refused whole.
LEGACY = "$[legacy]"
SUBSCRIPT = re.compile(r"\$\{[#!]?[A-Za-z_][A-Za-z0-9_]*\[([^]]*)\]")
OFFSET = re.compile(r"\$\{#?(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*])(?:\[[^]]*\])?:(?![-=?+])([^}]*)\}")
SET_SUBSCRIPT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\[([^]]*)\]\+?=")


def text(word):
    """A word as the shell hands it to arithmetic: its literal text with
    each expansion written as it stands."""
    return "".join(part for _, part in word.parts)


def legacy(raw):
    """Whether a word holds `$[` outside single quotes and unescaped: the
    legacy arithmetic expansion, which bash evaluates in double quotes too."""
    i, quoted = 0, False
    while i < len(raw):
        c = raw[i]
        if c == "\\":
            i += 2
            continue
        if c == "'" and not quoted and (i == 0 or raw[i - 1] != "$"):
            close = raw.find("'", i + 1)
            i = len(raw) if close == -1 else close + 1
            continue
        if c == '"':
            quoted = not quoted
        if raw.startswith("$[", i):
            return True
        i += 1
    return False


def word_contexts(word):
    """The arithmetic texts inside a word: its subscripts and offsets."""
    out = []
    for kind, part in word.parts:
        if kind != "exp":
            continue
        out.extend(sub for sub in SUBSCRIPT.findall(part) if sub not in ("@", "*"))
        for offsets in OFFSET.findall(part):
            out.extend(offsets.split(":"))
    return out


def contexts(lexed):
    """(line, arithmetic text, the number of commands read before it, its
    scope) for each place the script evaluates text as arithmetic, with a
    text of None for each integer variable it declares."""
    out = list(lexed.arithmetics)
    for index, command in enumerate(lexed.commands):
        line, scope = command.line, command.scope

        def add(expression):
            out.append((line, expression, index, scope))
        words = command.words
        run = shell_words.opened(words)
        while len(run) > 1 and run[0].bare() in ("builtin", "command"):
            run = run[1:]
        bare = [w.bare() for w in run]
        if bare[:1] == ["[["]:
            for k, b in enumerate(bare):
                if b in COMPARE:
                    for w in run[k - 1:k] + run[k + 1:k + 2]:
                        add(text(w))
        if bare[:1] == ["let"]:
            for w in run[1:]:
                add(text(w))
        # A name with a subscript that a builtin reads or sets: the operand
        # of `-v` in a test, and the names `read`, `mapfile`, `getopts`,
        # `printf -v` and `wait -p` assign.
        if run and run[0].literal() in ("[[", "[", "test", "read", "mapfile", "readarray", "getopts", "printf", "wait"):
            for w in run[1:]:
                for sub in re.findall(r"^[A-Za-z_][A-Za-z0-9_]*\[([^]]*)\]$", text(w)):
                    if sub not in ("@", "*"):
                        add(sub)
        for w in words:
            if legacy(w.raw):
                add(LEGACY)
        if run and run[0].literal() in ("declare", "typeset", "local", "export", "readonly") and any(
                re.fullmatch(r"-[A-Za-z]*i[A-Za-z]*", w.head()) for w in run[1:]):
            add(None)
        # The words that assign: those before the command word, and the
        # operands of a builtin that declares.
        k = 0
        while k < len(run) and re.match(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=", run[k].raw):
            k += 1
        assigning = run[:k]
        if k < len(run) and run[k].literal() in ("declare", "typeset", "local", "export", "readonly"):
            assigning += run[k + 1:]
        if k < len(run) and run[k].literal() == "unset":
            for w in run[k + 1:]:
                for sub in re.findall(r"\[([^]]*)\]", text(w)):
                    if sub not in ("@", "*"):
                        add(sub)
        for w in assigning:
            m = SET_SUBSCRIPT.match(w.raw)
            if m:
                add(m.group(2))
            if re.match(r"[A-Za-z_][A-Za-z0-9_]*\+?=\(", w.raw):
                for sub in re.findall(r"\[([^]]*)\]\+?=", w.raw):
                    add(sub)
        for w in words:
            for sub in word_contexts(w):
                add(sub)
    return out


def assigned_first_in(expression):
    """The names an arithmetic text assigns, with `=`, before it reads
    them: the first time the name stands in the text, it is the target of
    an `=` whose value does not read it (`i = 0`, not `i = i + 1`)."""
    seen, first = set(), set()
    for m in re.finditer(r"(?<![A-Za-z0-9_$])([A-Za-z_][A-Za-z0-9_]*)\b", expression):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        rest = expression[m.end():]
        assign = re.match(r"\s*=(?!=)([^;,]*)", rest)
        if assign and not re.search(r"(?<![A-Za-z0-9_$])%s\b" % re.escape(name), assign.group(1)):
            first.add(name)
    return first


def problems(lexed, values):
    """(line, message) for each arithmetic text with an operand that is not
    a number, and each integer variable. A name the text assigns before it
    reads it (`for ((i = 0; i < n; i++))`) holds a number there."""
    found = []
    for line, expression, index, scope in contexts(lexed):
        if expression is None:
            found.append((line, "an integer variable (declare -i): every assignment to it is evaluated as arithmetic, and a subscript in a value runs a command"))
            continue
        if expression == LEGACY:
            found.append((line, "a legacy arithmetic expansion ($[...]): write it as $((...))"))
            continue
        assigned_first = assigned_first_in(expression)
        for operand in operands(expression):
            bare = operand.lstrip("$").strip("{}")
            if bare in assigned_first and values.number(bare):
                continue
            if not values.operand_number(operand, index, scope):
                found.append((line, "an arithmetic operand that is not a number the script made (%s): the shell evaluates its value as arithmetic, and a subscript in it runs a command" % operand))
                break
    return found
