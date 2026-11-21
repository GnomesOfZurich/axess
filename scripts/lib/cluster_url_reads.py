"""The environment reads of VALKEY_CLUSTER_URL in Rust sources, for
scripts/check-cluster-url-reads.sh, whose header states the rule.

A read is the variable's name as a whole string literal (`"..."`,
`r"..."`, `r#"..."#`), the whole first argument (an `&` before it
allowed), passed to one of std's environment readers: the functions
`std::env::var` and `std::env::var_os` (a turbofish allowed) and the
macros `env!` and `option_env!`, bare or under `std::` or `core::`. A
reader is written out or reached through a name a `use` of `std` or
`core` binds: `use std::env;` then `env::var`, `use std::env::var as
get;` then `get`, `use std::option_env as oe;` then `oe!`. Comments are
not code and string literals name nothing (rust_source.blanked_lines),
and the tokens of an attribute, a macro invocation or a `macro_rules!`
definition are not read as code either: the macro decides what they
become (`stringify!` makes text of them), and a definition's names are
resolved where it is expanded. An item is read as written under its
attributes, derives included, and a macro of another crate is taken to
add no name where it is expanded.

Every read this finds is one, so a tree that reads the variable only
where the rule allows is never refused. A name is taken for std's only
where nothing else can bind it:
  - a name a `use` of std or core binds (`env`, `var`, `get`) where that
    `use` is in scope at the call: in the call's block or one around it,
    across no module but one that glob-imports its parent (`use
    super::*`), with no glob import in a block between, which could
    shadow it, and with no attribute on the `use` and no macro around it,
    either of which could leave it out; and only where nothing else in the
    file binds the name, every other occurrence of it in the code being a
    path's first segment, a call or a macro (`bound_otherwise`), and no
    file the check reads defines an item of that name, which a macro could
    expand beside the call;
  - `std` and `core` as a path's first segment where, beside that, no
    file the check reads defines or imports an item of that name
    (`::std` always names the crate);
  - the bare `env!` and `option_env!` where no file the check reads
    defines or imports a macro of that name and none holds `#[macro_use]`.
A file whose braces do not balance in its code has no scope to read;
there a name a `use` binds is not taken for std's. A glob import from
another crate is taken to bring no item named `std` or `core`.

Run with `python3 -I`; the caller puts this directory on sys.path.
"""

import re

from rust_source import blanked_lines

VARIABLE = "VALKEY_CLUSTER_URL"
HELPER = "axess-core/src/testing/valkey_cluster.rs"
# What a literal of the variable's name stands for in the blanked code.
HIT = '"@"'

CRATES = ("std", "core")
FUNCTIONS = {("std", "env", "var"), ("std", "env", "var_os")}
MACROS = {("std", "env"), ("core", "env"), ("std", "option_env"), ("core", "option_env")}
# What each name a file may leave unbound stands for when nothing binds it.
NATURAL = {"std": {("std",)}, "core": {("core",)},
           "env": {("std", "env"), ("core", "env")},
           "option_env": {("std", "option_env"), ("core", "option_env")}}

NOT_AFTER = r"(?<![\w$'#.:])"
IDENT = r"(?:r#)?[A-Za-z_]\w*"
PATH = rf"(?:::\s*)?{IDENT}(?:\s*::\s*{IDENT})*"
TURBOFISH = r"(?:\s*::\s*<(?:[^<>()]|<[^<>()]*>)*>)?"
ARGUMENT = r'\s*(?:&\s*)*"@"\s*[,)\]}]'
CALL = re.compile(rf"{NOT_AFTER}({PATH}){TURBOFISH}\s*\({ARGUMENT}")
MACRO = re.compile(rf"{NOT_AFTER}({PATH})\s*!\s*[(\[{{]{ARGUMENT}")
USE = re.compile(rf"{NOT_AFTER}use\s+((?:[^;{{}}]|\{{[^;]*\}})*);")
# A macro invocation's or definition's opening delimiter; a keyword before
# a `!` negates what follows it.
INVOCATION = re.compile(rf"{NOT_AFTER}(?:macro_rules\s*!\s*{IDENT}|({PATH})\s*!)\s*([(\[{{])")
KEYWORDS = {"return", "if", "while", "match", "in", "else", "break", "yield", "loop", "move",
            "mut", "ref", "as", "where", "for", "unsafe", "async", "await", "dyn", "impl", "let"}
ITEM = re.compile(
    rf"{NOT_AFTER}(?:mod|fn|struct|enum|union|trait|type|const|static)"
    rf'\s+(?:(?:mut|fn|unsafe|async|extern\s*""|extern)\s+)*({IDENT})'
    rf"|{NOT_AFTER}macro_rules\s*!\s*({IDENT})"
    rf"|{NOT_AFTER}extern\s+crate\s+({IDENT})(?:\s+as\s+({IDENT}))?"
)
MACRO_USE = re.compile(r"#\s*!?\s*\[\s*macro_use\b")
ATTRIBUTE = re.compile(r"#\s*!?\s*\[")
DEFINES = re.compile(
    r"(?:(?<![\w$'#])(?:fn|mod|struct|enum|union|trait|type|const|static|let|mut|ref|crate)"
    r"|macro_rules\s*!)\s*$"
)
# The statement `cluster_url` opens with: it panics for a test named
# outside `valkey_cluster` before anything after it runs.
GUARD = re.compile(
    rf"\{{\s*if\s+let\s+Some\s*\(\s*{IDENT}\s*\)\s*=\s*partition_refusal\s*\(\s*std\s*::\s*thread"
    r"\s*::\s*current\s*\(\s*\)\s*\.\s*name\s*\(\s*\)\s*\)\s*(\{)\s*panic\s*!\s*[(\[{]"
)


def _literal(text):
    """What stands for a string literal: HIT for the variable's name."""
    raw = re.fullmatch(r'r(#*)"(.*)"\1', text, re.S)
    body = raw.group(2) if raw else text[1:-1] if text[:1] == '"' else None
    return HIT if body == VARIABLE else '""'


def _ident(token):
    return token[2:] if token.startswith("r#") else token


def use_entries(tree):
    """(path, name) for each name a use tree binds, name "*" for a glob."""
    tokens = re.findall(r"::|[{},*]|(?:r#)?\w+", tree)
    out = []

    def read(i, prefix):
        path = list(prefix)
        while i < len(tokens):
            token = tokens[i]
            if token == "::":
                i += 1
            elif token == "{":
                i += 1
                while i < len(tokens) and tokens[i] != "}":
                    i = read(i, path)
                    if i < len(tokens) and tokens[i] == ",":
                        i += 1
                return i + 1
            elif token == "*":
                out.append((tuple(path), "*"))
                return i + 1
            elif token in (",", "}"):
                return i
            else:
                path.append(_ident(token))
                i += 1
                if tokens[i : i + 1] == ["::"]:
                    continue
                name = path[-1]
                if tokens[i : i + 1] == ["as"] and i + 1 < len(tokens):
                    name, i = _ident(tokens[i + 1]), i + 2
                if path[-1] == "self":
                    path.pop()
                    if name == "self":
                        name = path[-1] if path else "self"
                out.append((tuple(path), name))
                return i
        return i

    read(0, [])
    return out


def _close(code, i):
    """The index of the delimiter that closes the one at `code[i]`."""
    depth = 0
    for j in range(i, len(code)):
        if code[j] in "([{":
            depth += 1
        elif code[j] in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return len(code)


class Source:
    """One file's code, its `use` declarations, macro invocations and blocks."""

    def __init__(self, path, text):
        self.path = path
        self.code = "\n".join(blanked_lines(text, _literal))
        self.uses = []  # (path, name, position, attributed)
        self.use_spans = []
        for m in USE.finditer(self.code):
            head = re.sub(r"\bpub\s*(?:\([^)]*\))?\s*$", "", self.code[max(0, m.start() - 64) : m.start()])
            self.use_spans.append((m.start(), m.end()))
            for path, name in use_entries(m.group(1)):
                self.uses.append((path, name, m.start(), head.rstrip().endswith("]")))
        self._blocks = self._macros = False

    @property
    def macros(self):
        """(start, end) of the tokens of each attribute, macro invocation
        and macro definition."""
        if self._macros is False:
            self._macros = [(m.end(2), _close(self.code, m.start(2)))
                            for m in INVOCATION.finditer(self.code) if m.group(1) not in KEYWORDS]
            self._macros += [(m.end(), _close(self.code, m.end() - 1)) for m in ATTRIBUTE.finditer(self.code)]
        return self._macros

    def in_macro(self, pos):
        return any(start <= pos < end for start, end in self.macros)

    @property
    def blocks(self):
        """(open, close, parent, is_module) of each brace block, the file
        itself first; None when the braces do not balance."""
        if self._blocks is False:
            self._blocks = self._read_blocks()
        return self._blocks

    def _read_blocks(self):
        found, stack = [[-1, len(self.code), None, True]], [0]
        for i, ch in enumerate(self.code):
            if ch == "{":
                module = re.search(rf"{NOT_AFTER}mod\s+{IDENT}\s*$", self.code[max(0, i - 128) : i])
                found.append([i, None, stack[-1], bool(module)])
                stack.append(len(found) - 1)
            elif ch == "}":
                if len(stack) == 1:
                    return None
                found[stack.pop()][1] = i
        return found if len(stack) == 1 else None

    def block_at(self, pos):
        best = 0
        for k, (start, end, _, _) in enumerate(self.blocks):
            if start < pos < end and start > self.blocks[best][0]:
                best = k
        return best

    def line(self, pos):
        return self.code.count("\n", 0, pos) + 1

    def items(self):
        """The names this file defines as items, macro bodies included, and
        the names of NATURAL it imports from elsewhere than what they name
        when unbound."""
        names = set()
        for m in ITEM.finditer(self.code):
            item, macro, crate, alias = (_ident(g) if g else g for g in m.groups())
            if not (crate and not alias and crate in CRATES):
                names.add(item or macro or alias or crate)
        for path, name, _, _ in self.uses:
            if name in NATURAL and path not in NATURAL[name]:
                names.add(name)
        return names

    def bound_otherwise(self, name):
        """Whether anything in this file but a `use` of std or core binds
        `name`, or may: an import of it from elsewhere, or an occurrence of
        it in the code that is not a path's first segment, a call or a
        macro, or that a keyword which defines a name stands before."""
        if any(n == name and path[:1] not in (("std",), ("core",)) for path, n, _, _ in self.uses):
            return True
        for m in re.finditer(rf"(?<![\w$'#])(?:r#)?{re.escape(name)}(?!\w)", self.code):
            p = m.start()
            if any(start <= p < end for start, end in self.use_spans):
                continue
            before = self.code[max(0, p - 64) : p].rstrip()
            after = self.code[m.end() : m.end() + 64]
            if before.endswith(("::", ".")):
                continue
            if name in CRATES and re.search(r"\bextern\s+crate$", before) and after.lstrip()[:1] == ";":
                continue
            if re.match(r"\s*(?:::|!|\()", after) and not DEFINES.search(before):
                continue
            return True
        return False

    def in_scope(self, use_pos, pos):
        """Whether a `use` at `use_pos` binds its names at `pos`."""
        top, k, chain = self.block_at(use_pos), self.block_at(pos), []
        while k != top:
            if k == 0:
                return False
            chain.append(k)
            k = self.blocks[k][2]
        for k in chain:
            globs = [(path, attributed) for path, name, at, attributed in self.uses
                     if name == "*" and self.block_at(at) == k]
            if self.blocks[k][3]:
                parent = self.blocks[k][2]
                if (("super",), False) not in globs or not self.blocks[parent][3]:
                    return False
            elif globs:
                return False
        return True

    def bound(self, name, pos):
        """The std or core path a `use` in scope binds `name` to at `pos`."""
        if self.blocks is None or self.bound_otherwise(name):
            return None
        best = None
        for path, n, at, attributed in self.uses:
            if n == name and not attributed and not self.in_macro(at) and self.in_scope(at, pos):
                block = self.block_at(at)
                if best is None or self.blocks[block][0] > self.blocks[best[1]][0]:
                    best = (path, block)
        return best[0] if best else None

    def allowed(self):
        """(start, end) of what `cluster_url` runs after its guard, when
        this file defines it at its root and the guard opens it."""
        if self.blocks is None:
            return None
        for m in re.finditer(rf"{NOT_AFTER}fn\s+cluster_url\s*\(", self.code):
            body = self.code.find("{", m.end())
            for start, end, parent, _ in self.blocks:
                if start == body and parent == 0:
                    guard = GUARD.match(self.code, body)
                    if guard:
                        close = next(b[1] for b in self.blocks if b[0] == guard.start(1))
                        return close, end
        return None


def reads(source, shadowed, macro_use):
    """(position, text) of each read in `source`. A name after `::` is a
    path's later segment and one after `.` a method, whatever space or
    comment stands between, and neither is read."""
    found = []
    for pattern, macro in ((CALL, False), (MACRO, True)):
        for m in pattern.finditer(source.code):
            start = m.start(1)
            if source.code[max(0, start - 64) : start].rstrip().endswith(("::", ".")) or source.in_macro(start):
                continue
            rooted = m.group(1).startswith("::")
            segments = [_ident(s) for s in re.split(r"\s*::\s*", m.group(1).lstrip(":").strip())]
            head, rest = segments[0], tuple(segments[1:])
            if rooted:
                base = (head,) if head in CRATES else None
            else:
                local = head in shadowed or source.bound_otherwise(head)
                base = None if local else source.bound(head, start)
                if base is None and head in CRATES and not local:
                    base = (head,)
                if (base is None and macro and not rest and head in ("env", "option_env")
                        and not local and not macro_use):
                    base = ("std", head)
            if base is not None and base + rest in (MACROS if macro else FUNCTIONS):
                text = " ".join(m.group(0).split()).replace(HIT, f'"{VARIABLE}"')
                found.append((start, text))
    return sorted(found)


def check(files):
    """(allowed reads, refusals, files read) over (path, text) pairs."""
    sources = [Source(path, text) for path, text in files]
    shadowed = set().union(*(s.items() for s in sources))
    macro_use = any(MACRO_USE.search(s.code) for s in sources)
    allowed, refused = 0, []
    for source in sources:
        if HIT not in source.code:
            continue
        span = source.allowed() if source.path == HELPER else None
        for pos, text in reads(source, shadowed, macro_use):
            if span and span[0] < pos < span[1]:
                allowed += 1
                continue
            where = " (no cluster_url here opens with its guard)" if source.path == HELPER and not span else ""
            refused.append(f"{source.path}:{source.line(pos)}: {text}{where}")
    return allowed, refused, len(sources)
