"""The inline test blocks of Rust source files, for scripts/check-inline-tests.sh.

A test block is a module written inline (`mod name { ... }`) under an
attribute stack holding a `cfg` whose predicate asks for `test`: plain
`#[cfg(test)]`, and every form that includes it, such as
`#[cfg(all(test, feature = "x"))]` or `#[cfg(any(test, feature = "testing"))]`.
A predicate that names `test` only under `not(...)` asks for the opposite and
is not one. The attribute may stand on the `mod` line or above it, other
attributes may stand between, the module may be `pub` or `pub(...)`, and it
may sit at any depth, inside another module.

A block's size is the count of lines between the line of its opening brace
and the line of its closing one. The braces are matched on the code alone:
comments are dropped and string and char literals blanked first
(scripts/lib/rust_source.py), so a brace inside one is not counted.

Run with `python3 -I`: run as a script it puts its own directory on
sys.path; a caller that imports it puts the directory there first.
"""

import os
import re
import sys

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rust_source import blanked_lines  # noqa: E402 - after the path above

ITEM = re.compile(r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*([{;])")


def _parse(tokens, i):
    """The predicate starting at tokens[i] as (node, next index): an atom is
    ("atom", name), a `key = "value"` pair ("pair", key), and `all`, `any` and
    `not` are (name, [children])."""
    name = tokens[i]
    i += 1
    if i < len(tokens) and tokens[i] == "=":
        return ("pair", name), i + 2
    if i < len(tokens) and tokens[i] == "(" and name in ("all", "any", "not"):
        i += 1
        children = []
        while i < len(tokens) and tokens[i] != ")":
            child, i = _parse(tokens, i)
            children.append(child)
            if i < len(tokens) and tokens[i] == ",":
                i += 1
        return (name, children), i + 1
    return ("atom", name), i


def _asks_for_test(node, negated=False):
    """Whether `test` stands in the predicate other than under an odd count of `not`."""
    kind = node[0]
    if kind == "atom":
        return node[1] == "test" and not negated
    if kind == "pair":
        return False
    flip = not negated if kind == "not" else negated
    return any(_asks_for_test(child, flip) for child in node[1])


def test_cfg(attribute):
    """Whether an attribute's text (`#[...]`, literals blanked) is a `cfg`
    whose predicate asks for `test`."""
    m = re.fullmatch(r"#\[\s*cfg\s*\((.*)\)\s*\]", attribute, re.S)
    if not m:
        return False
    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|""|[(),=]', m.group(1))
    if not tokens:
        return False
    try:
        node, _ = _parse(tokens, 0)
    except IndexError:
        return False
    return _asks_for_test(node)


def _attribute_end(code, i):
    """The index after the `]` closing the attribute that opens at code[i]."""
    depth = 0
    for j in range(i + 1, len(code)):
        if code[j] == "[":
            depth += 1
        elif code[j] == "]":
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def _close(code, i):
    """The index of the `}` matching the `{` at code[i], or None."""
    depth = 0
    for j in range(i, len(code)):
        if code[j] == "{":
            depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    return None


def blocks(text):
    """(name, line of `{`, line of `}`) for each inline test block in `text`.

    A block inside another test block is part of it and is not listed again.
    """
    code = "\n".join(blanked_lines(text))
    found = []
    i = 0
    n = len(code)
    while i < n:
        if not code.startswith("#[", i):
            i += 1
            continue
        test = False
        j = i
        while code.startswith("#[", j):
            end = _attribute_end(code, j)
            if end is None:
                return found
            test = test or test_cfg(code[j:end])
            j = end
            while j < n and code[j].isspace():
                j += 1
        if not test:
            i = j if j > i else i + 1
            continue
        m = ITEM.match(code, j)
        if not m or m.group(2) == ";":
            i = j
            continue
        brace = m.end() - 1
        close = _close(code, brace)
        if close is None:
            return found
        found.append((m.group(1), code.count("\n", 0, brace) + 1, code.count("\n", 0, close) + 1))
        i = close + 1
    return found


def main(threshold, paths):
    """Print each block over `threshold` lines and the count read; 1 on a finding."""
    checked = 0
    over = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for name, start, end in blocks(text):
            checked += 1
            size = max(end - start - 1, 0)
            if size > threshold:
                over.append("  %5d lines  %s::%s" % (size, path, name))
    print("CHECKED=%d" % checked)
    for line in over:
        print(line)
    return 1 if over else 0


if __name__ == "__main__":
    # A finding is exit 1; anything that stops the reading is exit 2, so the
    # gate never takes a crash for a report.
    try:
        status = main(int(sys.argv[1]), sys.argv[2:])
    except Exception as exc:  # noqa: BLE001 - every failure is reported, none passes
        print("ERROR: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        status = 2
    sys.exit(status)
