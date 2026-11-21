"""Crafted cases for scripts/lib/workflow_expressions.py, run by
scripts/check-workflow-pins-tests.sh. Run with `python3 -I -B`."""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import workflow_expressions as X

SPANS = [
    ("", []),
    ("no expression", []),
    ("${{ a }}", [(0, " a ")]),
    ("x ${{a}} y ${{ b.c }}", [(2, "a"), (11, " b.c ")]),
    ("${{ format('}}', x) }}", [(0, " format('}}', x) ")]),
    ("${{ 'it''s }}' }} ${{c}}", [(0, " 'it''s }}' "), (18, "c")]),
    ("$ {{ a }} ${ {b}}", []),
    ("${{'}}'}}", [(0, "'}}'")]),
    ("${{ '' }}", [(0, " '' ")]),
    ("${{ 'a''' }}", [(0, " 'a''' ")]),
    ("${{'a'}}", [(0, "'a'")]),
    ("${{a}}${{b}}", [(0, "a"), (6, "b")]),
    ("${{ '${{' }}", [(0, " '${{' ")]),
]
UNREADABLE_SPANS = [
    ("${{ a", "an expression that does not close"),
    ("${{ 'a }}", "a string in an expression that does not close"),
    ("${{ 'a'' }}", "a string in an expression that does not close"),
]
TOKENS = [
    ("", []),
    ("  a\t.b \n", [("name", "a"), ("op", "."), ("name", "b")]),
    ("a-b_c1 'x''y' 0x1F -2 3.5e+2 1e3",
     [("name", "a-b_c1"), ("string", "'x''y'"), ("number", "0x1F"), ("number", "-2"),
      ("number", "3.5e+2"), ("number", "1e3")]),
    ("== != <= >= && || ! < > ( ) [ ] . , *",
     [("op", o) for o in "== != <= >= && || ! < > ( ) [ ] . , *".split()]),
]
# (expression, names a secret in a workflow, names one in a called workflow)
INPUTS = [
    ("inputs.tok", False, True),
    ("Inputs['tok']", False, True),
    ("toJSON(inputs)", False, True),
    ("format('{0}', inputs.a)", False, True),
    ("matrix.inputs", False, False),
    ("inputs(1)", False, False),
    ("'inputs.tok'", False, False),
    ("secrets.T", True, True),
]
UNREADABLE_TOKENS = ["{a}", "$a", '"a"', "a:b", "+a", "@a", "~a", "a;b"]
SECRET = [
    "secrets", "secrets.X", "SECRETS.x", "secrets['x']", "secrets.*", "toJSON(secrets)",
    "github", "github.token", "GITHUB.TOKEN", "github . token", "github['token']", "github.*",
    "toJSON(github)", "f(1, github)", "a || github", "!github", "(github)", "x[github]",
    "github[0]", "a.b && secrets.c", "github.ref || secrets",
]
NOT_SECRET = [
    "", "github.ref", "github.event.name", "matrix.github", "x.github.token", "steps.secrets.outputs.x",
    "secrets(1)", "github(1)", "'secrets'", "format('{0}', 'github.token')", "github.token_x",
    "a.secrets", "github-x", "githubx", "github_x.token", ".github", "github(", "x(github(1))",
]


def main():
    failures = []
    for text, want in SPANS:
        got = X.spans(text)
        if got != want:
            failures.append("spans(%r): %r, wanted %r" % (text, got, want))
    for text, message in UNREADABLE_SPANS:
        try:
            got = X.spans(text)
        except X.Unreadable as e:
            got = str(e)
        if got != message:
            failures.append("spans(%r): %r, wanted %r" % (text, got, message))
    for text, want in TOKENS:
        got = X.tokens(text)
        if got != want:
            failures.append("tokens(%r): %r, wanted %r" % (text, got, want))
    for text in UNREADABLE_TOKENS:
        try:
            got = X.tokens(text)
        except X.Unreadable as e:
            got = str(e)
        if not (isinstance(got, str) and got.startswith("a character an expression cannot hold")):
            failures.append("tokens(%r): %r, wanted a refusal" % (text, got))
    for text in SECRET:
        if X.names_secret(text) is not True:
            failures.append("names_secret(%r) is not True" % text)
    for text in NOT_SECRET:
        if X.names_secret(text) is not False:
            failures.append("names_secret(%r) is not False" % text)
    for text, plain, called in INPUTS:
        got = (X.names_secret(text), X.names_secret(text, inputs=True))
        if got != (plain, called):
            failures.append("names_secret(%r) outside and inside a called workflow: %r, wanted %r" % (text, got, (plain, called)))
    for failure in failures:
        print("FAIL: workflow_expressions: " + failure, file=sys.stderr)
    total = len(SPANS) + len(UNREADABLE_SPANS) + len(TOKENS) + len(UNREADABLE_TOKENS) + len(SECRET) + len(NOT_SECRET) + len(INPUTS)
    print("workflow_expressions tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
