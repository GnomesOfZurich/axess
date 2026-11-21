"""The `${{ ... }}` expressions of a GitHub workflow, read as tokens.

Used by scripts/check-workflow-pins.sh to tell whether a job names a secret.
An expression is read with the runner's grammar: names, `.` and `[...]`
property access, function calls, string literals in single quotes, numbers
and operators, without regard to case and with any white space, a line
break included. So `toJSON( github )`, `format('{0}', 1, github, 2)` and an
expression folded over two lines are each read as what they are, and a
word in a script or a step name that is not inside `${{ }}` names nothing.

A name is a context only where it starts a reference: not after a `.`
(`matrix.github` is a property of `matrix`) and not before `(` (a call).
`secrets` names a secret in every use. `github` does in every use but one:
a property of it other than `token` (`github.ref`, `github.event.name`).
`github.token`, `github.*`, `github['...']` and the whole context
(`toJSON(github)`) each hand the job's token on. In a workflow another one
calls, `inputs` may carry a secret the caller passed in, so it counts as
one there, in every use.
"""

import re

TOKEN = re.compile(
    r"""(?P<space>\s+)
      | (?P<string>'(?:[^']|'')*')
      | (?P<number>0x[0-9A-Fa-f]+|[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
      | (?P<name>[A-Za-z_][A-Za-z0-9_-]*)
      | (?P<op>==|!=|<=|>=|&&|\|\||[!<>()\[\].,*])
    """,
    re.VERBOSE,
)


class Unreadable(Exception):
    """An expression the check cannot read: it does not close, or holds a
    character that is not of the grammar."""


def spans(text):
    """(start, inner text) of each `${{ ... }}` in `text`."""
    out = []
    i = 0
    while True:
        start = text.find("${{", i)
        if start < 0:
            return out
        j = start + 3
        while True:
            if j >= len(text):
                raise Unreadable("an expression that does not close")
            if text.startswith("}}", j):
                break
            if text[j] == "'":
                close = j + 1
                while True:
                    close = text.find("'", close)
                    if close == -1:
                        raise Unreadable("a string in an expression that does not close")
                    if text.startswith("''", close):
                        close += 2
                        continue
                    break
                j = close + 1
                continue
            j += 1
        out.append((start, text[start + 3:j]))
        i = j + 2


def tokens(expression):
    """The tokens of one expression, white space dropped, as (kind, text)."""
    out = []
    i = 0
    while i < len(expression):
        m = TOKEN.match(expression, i)
        if not m:
            raise Unreadable("a character an expression cannot hold: %r" % expression[i])
        if m.lastgroup != "space":
            out.append((m.lastgroup, m.group(0)))
        i = m.end()
    return out


def names_secret(expression, inputs=False):
    """Whether one expression names a secret or hands on the job's token;
    with `inputs`, whether it names the inputs of a called workflow."""
    toks = tokens(expression)
    for k, (_, text) in enumerate(toks):
        if k > 0 and toks[k - 1] == ("op", "."):
            continue
        if k + 1 < len(toks) and toks[k + 1] == ("op", "("):
            continue
        name = text.lower()
        if name == "secrets" or (inputs and name == "inputs"):
            return True
        if name == "github":
            after = toks[k + 1:k + 3]
            if len(after) == 2 and after[0] == ("op", ".") and after[1][0] == "name":
                if after[1][1].lower() == "token":
                    return True
                continue
            return True
    return False
