"""The YAML of a GitHub workflow, read as the runner reads it.

Used by scripts/check-workflow-pins.sh. The reader takes the YAML a workflow
is written in: block mappings and sequences at any indentation, mappings and
sequences in flow style (`[a, b]`, `{a: b}`), plain, single-quoted and
double-quoted scalars on one line or folded over several, literal (`|`) and
folded (`>`) block scalars with their indicators, comments, anchors and
aliases. A double-quoted scalar's escapes are decoded and every scalar is
folded the way YAML folds it, so a rule reads the value the runner reads:
`"c\\x61rgo"` is `cargo`, and a plain or folded scalar over two lines is one
line of text.

A form the reader does not take is refused by name, with its line, rather
than read some other way: a tag (`!!str`), an explicit key (`? key`), a
merge key (`<<`), a key that is not a scalar, a duplicate key, a directive,
more than one document, a tab in the indentation, and anything that is not
YAML. So a rule never judges a workflow it read differently from the runner.

Each scalar keeps the file line every stretch of its text came from
(`Scalar.line_at`), and a block-style scalar the comment that ends its line,
which holds an action's version (`uses: owner/repo@<sha> # v1.2.3`).
"""

import re

ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n",
    "v": "\v", "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"',
    "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": "\u2028",
    "P": "\u2029",
}
HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}
ANCHOR = re.compile(r"[^\s,\[\]{}]+")


class Refusal(Exception):
    """A form the reader does not take, at a 1-based line."""

    def __init__(self, line, message):
        super().__init__(message)
        self.line = line
        self.message = message


class Scalar:
    """A scalar's decoded text, the lines it came from and its comment."""

    def __init__(self, value, line, style, breaks=None, comment=None):
        self.value = value
        self.line = line
        self.style = style
        self.breaks = breaks or [(0, line)]
        self.comment = comment

    def line_at(self, offset):
        """The file line the character at `offset` of the value came from."""
        found = self.breaks[0][1]
        for start, line in self.breaks:
            if start > offset:
                break
            found = line
        return found


class Mapping:
    """A mapping's (key, value) pairs in file order."""

    def __init__(self, line, flow=False):
        self.pairs = []
        self.line = line
        self.flow = flow

    def get(self, name):
        for key, value in self.pairs:
            if key.value == name:
                return value
        return None

    def key(self, name):
        for key, _ in self.pairs:
            if key.value == name:
                return key
        return None


class Sequence:
    """A sequence's items in file order."""

    def __init__(self, line, flow=False):
        self.items = []
        self.line = line
        self.flow = flow


def null(line):
    return Scalar("", line, "null")


def walk(node, seen=None):
    """Every node under `node`, keys included, each once."""
    seen = set() if seen is None else seen
    if id(node) in seen:
        return
    seen.add(id(node))
    yield node
    if isinstance(node, Mapping):
        for key, value in node.pairs:
            yield key
            yield from walk(value, seen)
    elif isinstance(node, Sequence):
        for item in node.items:
            yield from walk(item, seen)


def read(text):
    """The document `text` holds, or Refusal."""
    return Reader(text).document()


class Reader:
    """A recursive-descent reader over the lines of one document."""

    def __init__(self, text):
        if text.startswith("\ufeff"):
            text = text[1:]
        self.lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
        self.anchors = {}

    # Lines and indentation.

    def blank(self, r):
        stripped = self.lines[r].strip(" \t")
        return stripped == "" or stripped.startswith("#")

    def skip(self, r):
        while r < len(self.lines) and self.blank(r):
            r += 1
        return r

    def indent(self, r):
        line = self.lines[r]
        n = len(line) - len(line.lstrip(" "))
        if line[n:n + 1] == "\t":
            raise Refusal(r + 1, "a tab in the indentation")
        return n

    def seq_marker(self, r, c):
        text = self.lines[r][c:]
        return text == "-" or text.startswith("- ") or text.startswith("-\t")

    def rest_is_comment(self, r, i, what):
        rest = self.lines[r][i:].strip(" \t")
        if rest and not rest.startswith("#"):
            raise Refusal(r + 1, "text after %s: %s" % (what, rest))
        return rest[1:].strip() if rest else None

    # The document.

    def document(self):
        r = self.skip(0)
        if r < len(self.lines) and self.lines[r].startswith("%"):
            raise Refusal(r + 1, "a YAML directive")
        marker = re.match(r"---(?=\s|$)", self.lines[r]) if r < len(self.lines) else None
        if marker:
            self.rest_is_comment(r, marker.end(), "the document marker")
            r = self.skip(r + 1)
        if r >= len(self.lines):
            return Mapping(1)
        node, r = self.block(r, self.indent(r), -1)
        r = self.skip(r)
        if r < len(self.lines):
            if re.match(r"(---|\.\.\.)(\s|$)", self.lines[r]):
                raise Refusal(r + 1, "more than one YAML document")
            raise Refusal(r + 1, "a line outside the structure above it")
        return node

    def block(self, r, c, parent):
        """The block node whose text starts at line r, column c."""
        text = self.lines[r][c:]
        if self.seq_marker(r, c):
            return self.sequence(r, c)
        if text == "?" or text.startswith("? ") or text.startswith("?\t"):
            raise Refusal(r + 1, "an explicit key (`? key`): write the key before its colon")
        if self.key_at(r, c) is not None:
            return self.mapping(r, c)
        return self.value(r, c, parent)

    def key_at(self, r, c):
        """(key scalar, column after its colon) for an implicit key at r, c."""
        line = self.lines[r]
        text = line[c:]
        if text[0] in "#|>%@`!":
            return None
        if text[0] == "&":
            name, j = self.anchor(r, c)
            if j < len(line) and self.key_at(r, j) is not None:
                raise Refusal(r + 1, "an anchor on a key")
            return None
        if text[0] == "*":
            if re.match(r"\*[^\s,\[\]{}]+[ \t]*:(\s|$)", text):
                raise Refusal(r + 1, "an alias as a key")
            return None
        if text[0] in "[{":
            saved = dict(self.anchors)
            try:
                flow = FlowReader(self, r, c)
                flow.node()
                after = self.lines[flow.r][flow.i:].lstrip(" \t") if flow.r == r else ""
            except Refusal:
                after = ""
            self.anchors = saved
            if re.match(r":(\s|$)", after):
                raise Refusal(r + 1, "a key that is not a scalar")
            return None
        if text[0] in "\"'":
            try:
                key, end_r, end = self.quoted(r, c)
            except Refusal:
                return None
            if end_r != r:
                return None
            j = end
            while j < len(line) and line[j] in " \t":
                j += 1
            if line[j:j + 1] == ":" and (j + 1 == len(line) or line[j + 1] in " \t"):
                return key, j + 1
            return None
        j = c
        while j < len(line):
            ch = line[j]
            if ch == "#" and line[j - 1] in " \t":
                return None
            if ch == ":" and (j + 1 == len(line) or line[j + 1] in " \t"):
                name = line[c:j].rstrip(" \t")
                if not name or (name[0] in "-?:" and name[1:2] in ("", " ", "\t")):
                    return None
                return Scalar(name, r + 1, "plain"), j + 1
            j += 1
        return None

    def mapping(self, r, c):
        node = Mapping(r + 1)
        while True:
            found = self.key_at(r, c)
            if found is None:
                raise Refusal(r + 1, "a line in a mapping that is not a key")
            key, after = found
            if key.style == "plain" and key.value == "<<":
                raise Refusal(r + 1, "a merge key (`<<`)")
            if node.key(key.value) is not None:
                raise Refusal(r + 1, "the key %s twice in one mapping" % key.value)
            value, r = self.after_key(r, after, c)
            node.pairs.append((key, value))
            r = self.skip(r)
            if r >= len(self.lines):
                return node, r
            ind = self.indent(r)
            if ind < c or (ind == c and self.seq_marker(r, c)):
                return node, r
            if ind == 0 and re.match(r"(---|\.\.\.)(\s|$)", self.lines[r]):
                return node, r
            if ind > c:
                raise Refusal(r + 1, "indentation that matches no key above it")

    def after_key(self, r, i, c):
        """The value after a key's colon at column i of line r, in a mapping at c."""
        line = self.lines[r]
        while i < len(line) and line[i] in " \t":
            i += 1
        anchor = None
        if line[i:i + 1] == "&":
            anchor, i = self.anchor(r, i)
        rest = line[i:]
        if rest == "" or rest.startswith("#"):
            nxt = self.skip(r + 1)
            if nxt < len(self.lines) and self.indent(nxt) > c:
                node, r = self.block(nxt, self.indent(nxt), c)
            elif nxt < len(self.lines) and self.indent(nxt) == c and self.seq_marker(nxt, c):
                node, r = self.sequence(nxt, c)
            else:
                node, r = null(r + 1), r + 1
        else:
            node, r = self.value(r, i, c)
        if anchor:
            self.anchors[anchor] = node
        return node, r

    def anchor(self, r, i):
        m = ANCHOR.match(self.lines[r], i + 1)
        if not m:
            raise Refusal(r + 1, "an anchor with no name")
        j = m.end()
        while j < len(self.lines[r]) and self.lines[r][j] in " \t":
            j += 1
        return m.group(0), j

    def sequence(self, r, c):
        node = Sequence(r + 1)
        while True:
            j = c + 1
            line = self.lines[r]
            while j < len(line) and line[j] in " \t":
                j += 1
            rest = line[j:]
            if rest == "" or rest.startswith("#"):
                nxt = self.skip(r + 1)
                if nxt < len(self.lines) and self.indent(nxt) > c:
                    item, r = self.block(nxt, self.indent(nxt), c)
                else:
                    item, r = null(r + 1), r + 1
            else:
                item, r = self.block(r, j, c)
            node.items.append(item)
            r = self.skip(r)
            if r >= len(self.lines):
                return node, r
            ind = self.indent(r)
            if ind == c and self.seq_marker(r, c):
                continue
            if ind > c:
                raise Refusal(r + 1, "indentation that matches no item above it")
            return node, r

    def value(self, r, i, parent):
        """A scalar, a flow collection or an alias at line r, column i."""
        ch = self.lines[r][i]
        if ch == "*":
            m = ANCHOR.match(self.lines[r], i + 1)
            name = m.group(0) if m else ""
            if name not in self.anchors:
                raise Refusal(r + 1, "an alias to no anchor above it: *%s" % name)
            self.rest_is_comment(r, m.end(), "an alias")
            return self.anchors[name], r + 1
        if ch == "&":
            name, j = self.anchor(r, i)
            rest = self.lines[r][j:]
            if rest == "" or rest.startswith("#"):
                nxt = self.skip(r + 1)
                if nxt < len(self.lines) and self.indent(nxt) > parent:
                    node, end = self.block(nxt, self.indent(nxt), parent)
                else:
                    node, end = null(r + 1), r + 1
            else:
                node, end = self.block(r, j, parent)
            self.anchors[name] = node
            return node, end
        if ch == "!":
            raise Refusal(r + 1, "a YAML tag")
        if ch in "|>":
            return self.block_scalar(r, i, parent)
        if ch in "[{":
            return self.flow_top(r, i)
        if ch in "\"'":
            node, end_r, end_i = self.quoted(r, i)
            node.comment = self.rest_is_comment(end_r, end_i, "a quoted value")
            return node, end_r + 1
        if ch in "%@`" or (ch in "?:-" and self.lines[r][i + 1:i + 2] in ("", " ", "\t")):
            raise Refusal(r + 1, "a value that starts with the indicator %s" % ch)
        return self.plain(r, i, parent)

    def plain(self, r, i, parent):
        text, comment = self.plain_line(r, i)
        value = text
        breaks = [(0, r + 1)]
        end = r + 1
        nxt = r + 1
        empty = 0
        while comment is None and nxt < len(self.lines):
            stripped = self.lines[nxt].strip(" \t")
            if stripped == "":
                empty += 1
                nxt += 1
                continue
            if self.indent(nxt) <= parent or stripped.startswith("#"):
                break
            part, comment = self.plain_line(nxt, self.indent(nxt))
            value += "\n" * empty if empty else " "
            breaks.append((len(value), nxt + 1))
            value += part
            empty = 0
            end = nxt + 1
            nxt += 1
        return Scalar(value, r + 1, "plain", breaks, comment), end

    def plain_line(self, r, i):
        """A plain scalar's text on line r from column i, and the comment after it."""
        line = self.lines[r]
        j = i
        while j < len(line):
            if line[j] == "#" and j > i and line[j - 1] in " \t":
                return line[i:j].rstrip(" \t"), line[j + 1:].strip()
            if line[j] == ":" and (j + 1 == len(line) or line[j + 1] in " \t"):
                raise Refusal(r + 1, "a colon and a space inside a plain value: quote the value")
            j += 1
        return line[i:].rstrip(" \t"), None

    def quoted(self, r, i):
        """(scalar, end line, end column) for the quoted scalar opening at r, i."""
        quote = self.lines[r][i]
        out = []
        breaks = [(0, r + 1)]
        j = i + 1
        start = r
        while True:
            line = self.lines[r]
            while j < len(line):
                ch = line[j]
                if quote == "'" and ch == "'":
                    if line[j + 1:j + 2] == "'":
                        out.append("'")
                        j += 2
                        continue
                    style = "single"
                    return Scalar("".join(out), start + 1, style, breaks), r, j + 1
                if quote == '"' and ch == '"':
                    return Scalar("".join(out), start + 1, "double", breaks), r, j + 1
                if quote == '"' and ch == "\\":
                    if j + 1 == len(line):
                        break
                    j = self.escape(r, j, out)
                    continue
                out.append(ch)
                j += 1
            escaped_break = quote == '"' and line.endswith("\\") and j + 1 == len(line)
            if not escaped_break:
                while out and out[-1] in " \t":
                    out.pop()
            r += 1
            empty = 0
            while r < len(self.lines) and self.lines[r].strip(" \t") == "":
                empty += 1
                r += 1
            if r >= len(self.lines):
                raise Refusal(start + 1, "a quoted value that does not close")
            if not escaped_break:
                out.append("\n" * empty if empty else " ")
            line = self.lines[r]
            j = len(line) - len(line.lstrip(" \t"))
            breaks.append((len("".join(out)), r + 1))

    def escape(self, r, j, out):
        """Decode the escape at column j of line r into `out`; the column after it."""
        line = self.lines[r]
        code = line[j + 1]
        if code in ESCAPES:
            out.append(ESCAPES[code])
            return j + 2
        if code in HEX_ESCAPES:
            width = HEX_ESCAPES[code]
            digits = line[j + 2:j + 2 + width]
            if len(digits) != width or not re.fullmatch(r"[0-9A-Fa-f]+", digits):
                raise Refusal(r + 1, "an escape that is not YAML: \\%s%s" % (code, digits))
            out.append(chr(int(digits, 16)))
            return j + 2 + width
        raise Refusal(r + 1, "an escape that is not YAML: \\%s" % code)

    def block_scalar(self, r, i, parent):
        """A literal (`|`) or folded (`>`) block scalar whose header is at r, i."""
        line = self.lines[r]
        m = re.match(r"([|>])([+-]?)([1-9]?)([+-]?)", line[i:])
        if not m or (m.group(2) and m.group(4)):
            raise Refusal(r + 1, "a block scalar header that is not YAML")
        style = "literal" if m.group(1) == "|" else "folded"
        chomp = m.group(2) or m.group(4)
        self.rest_is_comment(r, i + m.end(), "a block scalar header")
        base = max(parent, 0)
        content = base + int(m.group(3)) if m.group(3) else None
        rows = []
        nxt = r + 1
        while nxt < len(self.lines):
            text = self.lines[nxt]
            if text.strip(" ") == "":
                rows.append((nxt, ""))
                nxt += 1
                continue
            ind = len(text) - len(text.lstrip(" "))
            if content is None:
                if ind <= parent:
                    break
                content = ind
            if ind < content:
                break
            rows.append((nxt, text[content:]))
            nxt += 1
        while rows and rows[-1][1] == "":
            rows.pop()
        end = rows[-1][0] + 1 if rows else r + 1
        value, breaks = self.fold(rows) if style == "folded" else self.literal(rows)
        if rows and chomp != "-":
            value += "\n"
        return Scalar(value, rows[0][0] + 1 if rows else r + 1, style, breaks or None), end

    @staticmethod
    def literal(rows):
        value = ""
        breaks = []
        for k, (row, text) in enumerate(rows):
            if k:
                value += "\n"
            breaks.append((len(value), row + 1))
            value += text
        return value, breaks

    @staticmethod
    def fold(rows):
        value = ""
        breaks = []
        previous = None
        empty = 0
        for row, text in rows:
            if text == "":
                empty += 1
                continue
            kind = "more" if text[0] in " \t" else "normal"
            if previous is None:
                value += "\n" * empty
            elif previous == "normal" and kind == "normal":
                value += "\n" * empty if empty else " "
            else:
                value += "\n" * (empty + 1)
            breaks.append((len(value), row + 1))
            value += text
            previous = kind
            empty = 0
        return value, breaks

    # Flow style.

    def flow_top(self, r, i):
        reader = FlowReader(self, r, i)
        node = reader.node()
        self.rest_is_comment(reader.r, reader.i, "a value in brackets")
        return node, reader.r + 1


class FlowReader:
    """A flow collection, read across lines from line r, column i."""

    def __init__(self, reader, r, i):
        self.reader = reader
        self.lines = reader.lines
        self.r = r
        self.i = i

    def peek(self):
        self.space()
        line = self.lines[self.r]
        return line[self.i] if self.i < len(line) else ""

    def space(self):
        while True:
            line = self.lines[self.r]
            while self.i < len(line) and line[self.i] in " \t":
                self.i += 1
            if self.i < len(line) and line[self.i] == "#" and (self.i == 0 or line[self.i - 1] in " \t"):
                self.i = len(line)
            if self.i < len(line):
                return
            if self.r + 1 >= len(self.lines):
                raise Refusal(self.r + 1, "a value in brackets that does not close")
            self.r += 1
            self.i = 0

    def expect(self, chars):
        ch = self.peek()
        if ch not in chars:
            raise Refusal(self.r + 1, "a value in brackets that is not YAML near %r" % ch)
        self.i += 1
        return ch

    def node(self):
        ch = self.peek()
        if ch == "[":
            return self.sequence()
        if ch == "{":
            return self.mapping()
        if ch == "!":
            raise Refusal(self.r + 1, "a YAML tag")
        if ch == "*":
            m = ANCHOR.match(self.lines[self.r], self.i + 1)
            name = m.group(0) if m else ""
            if name not in self.reader.anchors:
                raise Refusal(self.r + 1, "an alias to no anchor above it: *%s" % name)
            self.i = m.end()
            return self.reader.anchors[name]
        if ch == "&":
            m = ANCHOR.match(self.lines[self.r], self.i + 1)
            if not m:
                raise Refusal(self.r + 1, "an anchor with no name")
            self.i = m.end()
            node = self.node()
            self.reader.anchors[m.group(0)] = node
            return node
        return self.scalar()

    def sequence(self):
        node = Sequence(self.r + 1, flow=True)
        self.expect("[")
        while self.peek() != "]":
            item = self.node()
            if self.peek() == ":":
                raise Refusal(self.r + 1, "a key inside a sequence in brackets")
            node.items.append(item)
            if self.expect(",]") == "]":
                return node
        self.i += 1
        return node

    def mapping(self):
        node = Mapping(self.r + 1, flow=True)
        self.expect("{")
        while self.peek() != "}":
            if self.peek() == "?":
                raise Refusal(self.r + 1, "an explicit key (`? key`): write the key before its colon")
            key = self.node()
            if not isinstance(key, Scalar):
                raise Refusal(self.r + 1, "a key that is not a scalar")
            if node.key(key.value) is not None:
                raise Refusal(self.r + 1, "the key %s twice in one mapping" % key.value)
            if self.peek() == ":":
                self.i += 1
                value = self.node() if self.peek() not in ",}" else null(self.r + 1)
            else:
                value = null(self.r + 1)
            node.pairs.append((key, value))
            if self.expect(",}") == "}":
                return node
        self.i += 1
        return node

    def scalar(self):
        line = self.lines[self.r]
        if line[self.i] in "\"'":
            node, self.r, self.i = self.reader.quoted(self.r, self.i)
            return node
        start = self.i
        j = self.i
        while j < len(line):
            ch = line[j]
            if ch in ",[]{}":
                break
            if ch == ":" and (j + 1 == len(line) or line[j + 1] in " \t,[]{}"):
                break
            if ch == "#" and line[j - 1] in " \t":
                break
            j += 1
        text = line[start:j].rstrip(" \t")
        if not text:
            raise Refusal(self.r + 1, "a value in brackets that is not YAML")
        self.i = j
        if j == len(line) and self.r + 1 < len(self.lines):
            nxt = self.lines[self.r + 1].strip(" \t")
            if nxt and nxt[0] not in ",]}:#":
                raise Refusal(self.r + 1, "a value in brackets continued on the next line")
        return Scalar(text, self.r + 1, "plain")
