"""Crafted cases for scripts/lib/workflow_values.py and
scripts/lib/workflow_arithmetic.py, run by scripts/check-workflow-pins-tests.sh.

Each case lexes one script and pins what the readers return: whether a
substitution prints a number by its form, the host a URL word names, and
the operand of each
arithmetic text that is not a number the script made. Run with
`python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shell_words
import workflow_arithmetic as A
import workflow_values as V


def lexed(text):
    return shell_words.lex(text, lambda offset: 1 + text.count("\n", 0, offset))


NUMBERS = [
  ("date -u +%s", True), ("date -u -d \"$after\" +%s 2>/dev/null || echo 0", True), ("date +%Y%m%d", True),
  ("date +%Y-%m-%d", False), ("date", False), ("wc -l < f", True), ("cat f | wc -l", True), ("grep -c x f || true", True),
  ("expr \"$1\" + 0", True), ("echo 0", True), ("echo -3", True), ("echo x", False), ("printf 5", True), ("cat f", False),
  ("wc -l < f | tr -d ' '", False), ("cat f; echo 1", False), ("", False), ("\"$CMD\"", False), (": ", True),
]
HOSTS = [
  ("curl https://crates.io/api", "crates.io"), ("curl https://Crates.IO:443/x", "crates.io"), ("curl https://crates.io", "crates.io"),
  ("curl \"https://crates.io/$p\"", "crates.io"), ("curl \"https://crates.io$p\"", None), ("curl \"https://crates.io?$q\"", "crates.io"),
  ("A=https://crates.io/api; curl \"$A/x\"", "crates.io"), ("A=https://crates.io; curl \"$A$x\"", None), ("A=https://crates.io; curl \"$A/x\"", "crates.io"),
  ("A=https://crates.io/a; A=https://example.invalid/b; curl \"$A\"", None), ("A=https://crates.io/a; A=https://crates.io/b; curl \"$A\"", "crates.io"),
  ("A=$X; curl \"$A\"", None), ("curl \"$URL\"", None), ("curl \"$ACTIONS_ID_TOKEN_REQUEST_URL&audience=x\"", "the runner's OIDC token service"),
  ("curl \"$GITHUB_API_URL/repos\"", "api.github.com"), ("curl \"$GITHUB_SERVER_URL$x\"", None),
  ("GITHUB_API_URL=https://example.invalid; curl \"$GITHUB_API_URL/x\"", "example.invalid"), ("curl ftp://crates.io/x", None),
]
OPERAND = "an arithmetic operand that is not a number the script made (%s)"
ARITHMETIC = [
  ("attempt=0\nwhile [ \"$attempt\" -lt 10 ]; do attempt=$((attempt + 1)); done", []),
  ("t=$(date -u +%s)\nn=$(date -u +%s)\nw=$((t - n + 10))", []), ("echo $((VALUE))", ["VALUE"]), ("echo $(( $(cat f) ))", ["$(substitution)"]),
  ("x=$1\necho $((x))", ["x"]), ("y=$((10#$1))", ["$1"]), ("n=3\n[[ $n -gt 1 ]]", []), ("[[ $x -gt 1 ]]", ["$x"]),
  ("let i=i+1", ["i"]), ("i=0\nlet i=i+1", []), ("k=1\necho ${a[$k]} ${a[@]}", []), ("echo ${a[$k]}", ["$k"]), ("a[$k]=1", ["$k"]),
  ("unset \"a[$k]\"", ["$k"]), ("echo ${s:$o:2}", ["$o"]), ("s=abc\necho ${s:1:2} ${s:-x}", []), ("x=foo\necho $((x))", ["x"]),
  ("n=4\nfor ((i=0; i<n; i++)); do :; done", []), ("for ((i=0; i<n; i++)); do :; done", ["n"]), ("(( n++ ))", ["n"]),
  ("n=0\n(( n++ ))", []), ("echo $((n))\nn=1", ["n"]), ("if c; then n=1; fi\necho $((n))", ["n"]), ("if c; then n=1; echo $((n)); fi", []),
  ("if c; then n=1; else echo $((n)); fi", ["n"]), ("case x in a) n=1 ;; b) echo $((n)) ;; esac", ["n"]), ("while c; do n=1; done\necho $((n))", ["n"]),
  ("n=1 | cat\necho $((n))", ["n"]), ("c || n=1\necho $((n))", ["n"]), ("(n=1)\necho $((n))", ["n"]), ("n=1\nf() { echo $((n)); }\nf", []),
  ("f() { echo $((n)); }\nn=1\nf", ["n"]), ("n=$((n+1))", ["n"]), ("status=0\ncmd || status=$?\necho $((status))", []),
  ("echo $((RANDOM % 6 + $# + ${#s}))", []), ("y=$(expr \"$1\" + 0) || exit 1\necho $((y % 4))", []), ("echo $(( i = i + 1 ))", ["i"]),
  ("cat <<EOF\n$((x * 2))\nEOF", ["x"]), ("echo \"${v:-$((w))}\"", ["w"]),
  ("builtin let i=i+1", ["i"]), ("command let x=$V", ["x"]), ("[[ -v a[$X] ]]", ["$X"]), ("[ -v \"a[$X]\" ]", ["$X"]),
  ("test -v a[$X]", ["$X"]), ("read \"a[$X]\"", ["$X"]), ("printf -v \"a[$X]\" %s v", ["$X"]), ("k=1\nread \"a[$k]\"", []),
]
LEGACY = [('$[VALUE]', True), ("'$[x]'", False), ('\\$[x]', False), ('"$[x]"', True), ('"a\'$[x]"', True), ("a'b'$[x]", True),
          ('"\\$[x]"', False), ('$x[1]', False)]


def main():
    failures = []
    for text, want in NUMBERS:
        if V.number_output(text) is not want:
            failures.append("number output of %r: %r" % (text, V.number_output(text)))
    for text, want in HOSTS:
        script = lexed(text)
        got = V.Values(script).host(script.commands[-1].words[-1])
        if got != want:
            failures.append("host of %r: %r, wanted %r" % (text, got, want))
    for text, want in ARITHMETIC:
        script = lexed(text)
        got = [m.split(" (", 1)[1].split("):", 1)[0] for _, m in A.problems(script, V.Values(script))]
        if got != want:
            failures.append("arithmetic of %r: %r, wanted %r" % (text, got, want))
    for raw, want in LEGACY:
        if A.legacy(raw) is not want:
            failures.append("legacy arithmetic in %r: %r" % (raw, A.legacy(raw)))
    legacy = [m for _, m in A.problems(lexed("echo \"$[n + 1]\""), V.Values(lexed("x=1")))]
    if legacy != ["a legacy arithmetic expansion ($[...]): write it as $((...))"]:
        failures.append("a legacy arithmetic expansion: %r" % legacy)
    declared = A.problems(lexed("declare -i n\nlocal -ri m"), V.Values(lexed("x=1")))
    if [m for _, m in declared] != ["an integer variable (declare -i): every assignment to it is evaluated as arithmetic, and a subscript in a value runs a command"] * 2:
        failures.append("integer variables: %r" % declared)
    for failure in failures:
        print("FAIL: workflow_values: " + failure, file=sys.stderr)
    total = len(NUMBERS) + len(HOSTS) + len(ARITHMETIC) + len(LEGACY) + 2
    print("workflow_values tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
