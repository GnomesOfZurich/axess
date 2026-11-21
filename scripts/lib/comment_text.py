"""The comments of a source file, for the rules about how a comment is written.

scripts/check-prose-style.sh refuses a regression marker and a citation of
a source line by its number in a comment. It reads comments alone, because
a string is data: the crafted cases of a gate hold such text in strings, as
the output they expect. `comments(path, text)` answers (line, text) for each
comment of a file, by its kind:

- Rust: line, block and doc comments, read by the lexer of rust_source.py,
  which skips string, raw string and char literals whole.
- Shell: the comments the shell skips, read by shell_words.py, and the
  comments of a Python program a here-document hands to `python3`.
- Python: the comment tokens of `tokenize`.
- Anything else the gate reads (Markdown, TOML, YAML): every line, since
  the whole text is prose or configuration a reader takes as written.

A text its reader cannot read whole (a shell script the lexer reports a
problem in, a Python program `tokenize` refuses) answers every one of its
lines, so a rule over it fails closed rather than passing over the part it
could not read.

Run with `python3 -I`; the caller puts this directory on sys.path.
"""

import io
import os
import tokenize

import rust_source
import shell_words

PYTHONS = ("python3", "python")


def every_line(text, first=1):
    return [(first + k, line) for k, line in enumerate(text.split("\n"))]


def python_comments(text, first=1):
    """(line, text) of each comment token of a Python program."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError):
        return every_line(text, first)
    return [(first - 1 + t.start[0], t.string) for t in tokens if t.type == tokenize.COMMENT]


def line_reader(text):
    """The line of each offset of `text`, counted from 1."""
    starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]

    def line_of(offset):
        lo, hi = 0, len(starts)
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if starts[mid] <= offset:
                lo = mid
            else:
                hi = mid
        return lo + 1

    return line_of


def shell_comments(text):
    """(line, text) of each comment of a shell script and of each Python
    program one of its here-documents hands to `python3`."""
    line_of = line_reader(text)
    lexed = shell_words.lex(text, line_of)
    if lexed.problems:
        return every_line(text)
    found = [(line_of(offset), comment) for offset, comment in lexed.comments]
    for command in lexed.commands:
        words = shell_words.opened(command.words)
        program = words[0].bare() if words else None
        if program is None or os.path.basename(program) not in PYTHONS:
            continue
        for body, offset in lexed.bodies_of(command):
            found.extend(python_comments(body, line_of(offset)))
    return found


def comments(path, text):
    """(line, text) of each comment of the file at `path`, by its kind."""
    if path.endswith(".rs"):
        return rust_source.comments(text)
    if path.endswith(".sh"):
        return shell_comments(text)
    if path.endswith(".py"):
        return python_comments(text)
    return every_line(text)
