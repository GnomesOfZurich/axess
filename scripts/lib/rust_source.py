"""The production lines of a Rust source file, for the source-rule scripts.

Shared by scripts/check-clock-usage.sh and scripts/check-rsa-sites.sh, which
both ask the same question of a file: which lines are compiled into the
library? The clock check also reads integration tests (`integration_test`),
where every line of code counts (`code_lines`). A comment is not; a
string literal names nothing; an item under `#[cfg(test)]` is compiled for
tests only. scripts/check-prose-style.sh asks the opposite question, which
text is a comment (`comments`), with the same lexer. The attribute covers one item,
read character by character: the attributes stacked after it, then the item
up to the `;` or the closing `}` that ends it at its own depth, whether it
stands on the attribute's line, the next line or over many. Everything after
that item is production code again, the rest of the line it ends on
included, so a test module in the middle of a file exempts its own body and
nothing below it, and a test item that shares a line with a production item
exempts only itself.

The brace depth is read from the code alone. A brace inside a char literal
(`'{'`), a string, a raw string (`r#"{"#`) or a comment is text, so the
lexer in `_blanked_lines` takes literals and comments out before anything
is counted or matched; otherwise one `'{'` in a test module would open a
depth that never closes and exempt the rest of the file. A quote is read as
rustc's lexer reads it (`_quote_end`): a char or byte literal with any
escape (`'\\''`, `'\\\\'`, `'\\u{7B}'`, `b'\\x7b'`), or a lifetime or a label
(`'a`, `'static`, `'r#a`), which is code and holds no literal; strings and
raw strings take the prefixes `b`, `c`, `r`, `br` and `cr`, and block
comments nest.

Run with `python3 -I`; the caller puts this directory on sys.path.
"""

import os
import re

OPEN = "{[("
CLOSE = "}])"


def _token_start(text, i):
    """Whether a token may start at `text[i]`: no identifier character
    stands right before it, so a prefix there (`r`, `b`, `c`) is one."""
    return i == 0 or not ("a" + text[i - 1]).isidentifier()


def _id_start(c):
    return c == "_" or c.isidentifier()


def _id_continue(c):
    return bool(c) and ("a" + c).isidentifier()


def declared_for_tests(path):
    """Whether the file's parent module declares it as `#[cfg(test)] mod name;`.

    A test fake or a test-only helper may live in its own file beside the
    module that uses it; the attribute then stands on the `mod` line in the
    parent (`a/b.rs` or `a/b/mod.rs` for `a/b/name.rs`), not in the file.
    """
    directory, filename = os.path.split(path)
    name, ext = os.path.splitext(filename)
    if ext != ".rs" or not directory or name in ("mod", "lib", "main"):
        return False
    parents = [directory + ".rs", os.path.join(directory, "mod.rs")]
    declaration = re.compile(
        r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+"
        + re.escape(name)
        + r"\s*;"
    )
    for parent in parents:
        try:
            with open(parent, encoding="utf-8") as f:
                code = "\n".join(_blanked_lines(f.read()))
        except FileNotFoundError:
            continue
        if declaration.search(code):
            return True
    return False


def integration_test(path):
    """Whether `path` is a crate's integration test: a file under the `tests/`
    directory beside the crate's `src/`, not a test module inside `src/`."""
    parts = path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part == "src":
            return False
        if part == "tests":
            return i > 0
    return False


def exempt(path, roots):
    """Whether `path` is compiled for tests only, or lives in a crate in `roots`."""
    parts = path.split("/")
    if parts[0] in roots or "src" not in parts:
        return True
    name = parts[-1]
    if name in ("tests.rs", "testing.rs") or name.endswith("_tests.rs"):
        return True
    if any(p in ("tests", "testing", "benches") for p in parts):
        return True
    return declared_for_tests(path)


def _raw_string_end(text, i):
    """The index after the raw string that starts at `text[i]` (`r`, `br` or `cr`).

    Returns None if `text[i:]` does not start a raw string.
    """
    j = i + 1 if text[i] == "r" else i + 2
    if text[i] in "bc" and text[i + 1 : i + 2] != "r":
        return None
    hashes = 0
    while text[j : j + 1] == "#":
        hashes += 1
        j += 1
    if text[j : j + 1] != '"':
        return None
    close = text.find('"' + "#" * hashes, j + 1)
    return len(text) if close < 0 else close + 1 + hashes


def _string_end(text, i):
    """The index after the string literal whose opening quote is `text[i]`."""
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
        elif text[j] == '"':
            return j + 1
        else:
            j += 1
    return len(text)


def _single_quoted_end(text, j):
    """The index after a char or byte literal whose opening quote stands
    right before `text[j]`, as rustc's lexer ends it: one character and a
    quote, or up to the quote that closes it with each escape (`\\'`, `\\\\`)
    taken as one; where rustc's lexer stops an unclosed literal, at a `/` or
    a line break, the literal ends there."""
    if text[j + 1 : j + 2] == "'" and text[j : j + 1] != "\\":
        return j + 2
    n = len(text)
    while j < n:
        c = text[j]
        if c == "'":
            return j + 1
        if c == "/" or (c == "\n" and text[j + 1 : j + 2] != "'"):
            return j
        j += 2 if c == "\\" else 1
    return n


def _quote_end(text, i):
    """(end, literal) for the quote at `text[i]`, as rustc's lexer reads it:
    the index after the char literal, lifetime or label it opens, and
    whether it is a literal. A quote followed by an identifier's first
    character (or a digit) and no quote right after that character opens a
    lifetime or a label (`'a`, `'static`, raw `'r#a`), unless a quote closes
    the identifier (`'ab'`, read as a literal); anything else opens a char
    literal (`'{'`, `'\\''`, `'\\u{7B}'`)."""
    first, second = text[i + 1 : i + 2], text[i + 2 : i + 3]
    if second == "'" or not (_id_start(first) or "0" <= first <= "9"):
        return _single_quoted_end(text, i + 1), True
    if first == "r" and second == "#" and _id_start(text[i + 3 : i + 4]):
        j = i + 4
        while _id_continue(text[j : j + 1]):
            j += 1
        return j, False
    j = i + 2
    while _id_continue(text[j : j + 1]):
        j += 1
    if text[j : j + 1] == "'":
        return j + 1, True
    return j, False


def _block_comment_end(text, i):
    """The index after the (nesting) block comment that opens at `text[i]`."""
    depth = 0
    j = i
    while j < len(text):
        if text.startswith("/*", j):
            depth += 1
            j += 2
        elif text.startswith("*/", j):
            depth -= 1
            j += 2
            if depth == 0:
                return j
        else:
            j += 1
    return len(text)


def _blanked_lines(text, string=lambda literal: '""'):
    """Each line of `text` with its comments dropped and its literals blanked.

    A string literal becomes `""` and a char literal `' '`, so no pattern
    matches inside one and no brace inside one is counted. A string, a raw
    string or a block comment may run over several lines; the lines it
    covers come out blank. A caller that has to tell one string literal
    from another passes `string`, which is given the literal as written
    (quotes, prefix and hashes included) and answers what stands for it.
    """
    lines = []
    line = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            lines.append("".join(line))
            line = []
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = _block_comment_end(text, i)
            lines.extend([""] * text.count("\n", i, end))
            line.append(" ")
            i = end
        elif c == '"':
            end = _string_end(text, i)
            lines.extend([""] * text.count("\n", i, end))
            line.append(string(text[i:end]))
            i = end
        elif c in "rbc" and _token_start(text, i) and (end := _raw_string_end(text, i)):
            lines.extend([""] * text.count("\n", i, end))
            line.append(string(text[i:end]))
            i = end
        elif c == "b" and text[i + 1 : i + 2] == "'" and _token_start(text, i):
            end = _single_quoted_end(text, i + 2)
            lines.extend([""] * text.count("\n", i, end))
            line.append("b' '")
            i = end
        elif c == "'":
            end, literal = _quote_end(text, i)
            lines.extend([""] * text.count("\n", i, end))
            line.append("' '" if literal else text[i:end])
            i = end
        else:
            line.append(c)
            i += 1
    lines.append("".join(line))
    return lines


def blanked_lines(text, string=lambda literal: '""'):
    """Each line of `text` with its comments dropped and its literals blanked
    (`_blanked_lines`), for a caller that reads code text of its own."""
    return _blanked_lines(text, string)


def comments(text):
    """(line, text) of each comment in `text`, for the rules about how a
    comment is written: a line or doc comment from its `//` to the end of
    its line, a block comment one entry per line it covers. The literals are
    skipped as `_blanked_lines` skips them, so a `//` or a `/*` inside a
    string or a char literal opens no comment and a string's text is never
    read as one."""
    found = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            found.append((line, text[i:end]))
            i = end
        elif text.startswith("/*", i):
            end = _block_comment_end(text, i)
            for k, part in enumerate(text[i:end].split("\n")):
                found.append((line + k, part))
            line += text.count("\n", i, end)
            i = end
        elif c == '"' or (c in "rbc" and _token_start(text, i) and _raw_string_end(text, i)):
            end = _string_end(text, i) if c == '"' else _raw_string_end(text, i)
            line += text.count("\n", i, end)
            i = end
        elif c == "b" and text[i + 1 : i + 2] == "'" and _token_start(text, i):
            end = _single_quoted_end(text, i + 2)
            line += text.count("\n", i, end)
            i = end
        elif c == "'":
            end = _quote_end(text, i)[0]
            line += text.count("\n", i, end)
            i = end
        else:
            i += 1
    return found


def _attribute_end(code, i):
    """The index after the `]` that closes the attribute opening at `code[i]`."""
    depth = 0
    for j in range(i + 1, len(code)):
        if code[j] == "[":
            depth += 1
        elif code[j] == "]":
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def _test_only(attribute):
    """Whether an attribute's text (`#[...]`) compiles its item for tests only."""
    body = re.sub(r"\s+", "", attribute[2:-1])
    if body == "cfg(test)":
        return True
    m = re.fullmatch(r"cfg\(all\((.*)\)\)", body)
    if not m:
        return False
    depth = 0
    part = ""
    for ch in m.group(1) + ",":
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            if part == "test":
                return True
            part = ""
        else:
            part += ch
    return False


class _Reader:
    """The state of production_lines across lines: inside an attribute, waiting
    for the item a test attribute covers, or inside that item."""

    def __init__(self):
        self.state = "code"
        self.depth = 0
        self.held = ""
        self.resume = "code"

    def line(self, code):
        """The production text of one blanked line."""
        kept = []
        i = 0
        while i < len(code):
            if self.state == "attribute":
                self.held += code[i]
                if code[i] == "[":
                    self.depth += 1
                elif code[i] == "]":
                    self.depth -= 1
                    if self.depth == 0:
                        test = _test_only(self.held)
                        if self.resume == "code" and not test:
                            kept.append(self.held)
                        self.state = "pending" if test else self.resume
                i += 1
                continue
            if self.state == "item":
                ch = code[i]
                if ch in OPEN:
                    self.depth += 1
                elif ch in CLOSE:
                    self.depth -= 1
                    if self.depth == 0 and ch == "}":
                        self.state = "code"
                elif ch == ";" and self.depth == 0:
                    self.state = "code"
                i += 1
                continue
            if code.startswith("#[", i):
                end = _attribute_end(code, i)
                if end is None:
                    self.resume = "pending" if self.state == "pending" else "code"
                    self.state, self.depth, self.held = "attribute", 0, ""
                    continue
                if _test_only(code[i:end]):
                    self.state = "pending"
                elif self.state == "code":
                    kept.append(code[i:end])
                i = end
                continue
            if self.state == "pending":
                if code[i] in " \t":
                    i += 1
                    continue
                self.state, self.depth = "item", 0
                continue
            kept.append(code[i])
            i += 1
        return "".join(kept)


def production_lines(text):
    """(line number, code) for each line with code outside comments and cfg(test) items.

    Comments are dropped and string and char literals blanked first
    (`_blanked_lines`), so a pattern cannot match inside one and a brace
    inside one does not count. The code of a line is what remains of it once
    every cfg(test) item on it is taken out.
    """
    reader = _Reader()
    out = []
    for no, code in enumerate(_blanked_lines(text), 1):
        kept = reader.line(code)
        if kept.strip():
            out.append((no, kept))
    return out


def code_lines(text):
    """(line number, code) for each line with code outside comments.

    For a file compiled for tests only, where every line counts: string and
    char literals are blanked as in `production_lines`, and no item is
    exempt.
    """
    return [(no, code) for no, code in enumerate(_blanked_lines(text), 1) if code.strip()]
