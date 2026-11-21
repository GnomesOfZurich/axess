"""The rule of scripts/check-live-sweeps.sh: every live Valkey test holds a sweep.

A live Valkey test is a function with an `ignore` attribute whose reason
names Valkey (`requires a running Valkey (VALKEY_URL)`, `requires a Valkey
cluster (VALKEY_CLUSTER_URL)`, or any other reason that holds the word):
the reason is what sends a test to a live server, since only the ignored
tests run against one. Such a test holds a sweep when its body calls a
sweep source:

  - a function or method whose declared return type names a sweep type;
  - a function that takes a closure and whose body calls a sweep source
    (it holds the sweep while the closure runs, as `swept(|run| ...)`
    does).

The sweep types are `KeySweep` and `Swept`, and every struct, tuple struct
or type alias of the files read whose fields or definition name a sweep
type, to a fixed point; a method that returns `Self` in an `impl` of a
sweep type is a source too.

A call is resolved by its name, read from the code alone (comments are
dropped and literals blanked, scripts/lib/rust_source.py). `name(` is a
free function: those of the test's own file when it declares one, else
those of every file read. `Type::name(` is a method of an `impl Type`
block. `module::name(` is a free function of the files that module names
(`module.rs`, `module/mod.rs`), else of every file read. A call is a
source only when the name has a declaration there and every declaration
of it is a source: a name the rule cannot place, or one two declarations
answer differently, is not taken as a sweep, so the rule fails closed.
A method call (`value.name(`) is never a source: the value came from
somewhere, and that call is the one read.

What the rule cannot see: whether every key a test writes holds its
sweep's prefix. A key's name is a value the test builds at run time
(`format!` of a prefix it was handed, a constant, a default prefix), and
following it is data flow no text rule decides. The run's token check
(scripts/live-keys-left.sh) finds a swept key left behind; a key outside
every sweep is what this rule keeps from being written by a test that
holds none.
"""

import os
import re

from rust_source import blanked_lines

SWEEP_TYPES = ("KeySweep", "Swept")
VALKEY_REASON = '"valkey"'
WORD = r"[A-Za-z_][A-Za-z0-9_]*"
CLOSURE = re.compile(r"\b(?:FnOnce|FnMut|Fn)\s*\(")
# What may stand between a test's attributes and its `fn`: blanks, more
# attributes, a visibility and the qualifiers of a function.
QUALIFIERS = r"(?:\s|#\s*\[[^\]]*\]|\bpub\b(?:\s*\([^)]*\))?|\basync\b|\bunsafe\b|\bconst\b)*"
KEYWORDS = {"if", "while", "match", "for", "return", "loop", "in", "as", "move", "async", "await"}


def _literal(text):
    """What stands for a string literal: a marker for one that names Valkey."""
    return VALKEY_REASON if "valkey" in text.lower() else '""'


def _close(code, i, opening, closing):
    """The index after the bracket that closes the one opening at `code[i]`."""
    depth = 0
    for j in range(i, len(code)):
        if code[j] == opening:
            depth += 1
        elif code[j] == closing:
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def _angle_close(code, i):
    """The index after the `>` that closes the `<` at `code[i]`; `->` is not one."""
    depth = 0
    j = i
    while j < len(code):
        if code.startswith("->", j):
            j += 2
            continue
        if code[j] == "<":
            depth += 1
        elif code[j] == ">":
            depth -= 1
            if depth == 0:
                return j + 1
        elif code[j] in "{;":
            return None
        j += 1
    return None


class Fn:
    """One function: where it is, what it declares, and its body."""

    def __init__(self, path, name, owner, signature, ret, body, line, offset):
        self.path = path
        self.offset = offset
        self.name = name
        self.owner = owner
        self.signature = signature
        self.ret = ret
        self.body = body
        self.line = line


class Source:
    """The functions, impls and types of one file, read from its code."""

    def __init__(self, path, text):
        self.path = path
        self.code = "\n".join(blanked_lines(text, _literal))
        self.fns = []
        self.types = {}
        self.unreadable = []
        self._read()

    def _line(self, offset):
        return self.code.count("\n", 0, offset) + 1

    def _impls(self):
        """(start, end, type) of each `impl` block."""
        spans = []
        for m in re.finditer(r"\bimpl\b", self.code):
            opening = self.code.find("{", m.end())
            stop = self.code.find(";", m.end())
            if opening < 0 or 0 <= stop < opening:
                continue
            header = self.code[m.end() : opening]
            header = re.split(r"\bwhere\b", header)[0]
            if re.search(r"\bfor\b", header):
                header = re.split(r"\bfor\b", header)[-1]
            names = re.findall(WORD, re.sub(r"<.*", "", header.strip(), flags=re.S))
            end = _close(self.code, opening, "{", "}")
            if names and end:
                spans.append((opening, end, names[-1]))
        return spans

    def _read(self):
        code = self.code
        for m in re.finditer(rf"\b(struct|type)\s+({WORD})", code):
            kind, name = m.groups()
            if kind == "type":
                end = code.find(";", m.end())
                self.types[name] = code[m.end() : end if end >= 0 else len(code)]
                continue
            j = m.end()
            if j < len(code) and code[j] == "<":
                j = _angle_close(code, j) or j
            rest = code[j:]
            brace, paren, semi = rest.find("{"), rest.find("("), rest.find(";")
            firsts = [k for k in (brace, paren, semi) if k >= 0]
            if not firsts:
                continue
            first = min(firsts)
            if first == brace:
                end = _close(code, j + brace, "{", "}")
            elif first == paren:
                end = _close(code, j + paren, "(", ")")
            else:
                end = j + semi
            self.types[name] = code[j : end or len(code)]
        impls = self._impls()
        for m in re.finditer(rf"\bfn\s+({WORD})", code):
            j = m.end()
            if j < len(code) and code[j] == "<":
                j = _angle_close(code, j)
                if j is None:
                    self.unreadable.append(self._line(m.start()))
                    continue
            k = code.find("(", j)
            if k < 0 or code[j:k].strip():
                continue
            params_end = _close(code, k, "(", ")")
            if params_end is None:
                self.unreadable.append(self._line(m.start()))
                continue
            opening, stop = code.find("{", params_end), code.find(";", params_end)
            if opening < 0 or 0 <= stop < opening:
                continue
            tail = code[params_end:opening]
            ret = re.split(r"\bwhere\b", tail)[0]
            ret = ret.split("->", 1)[1].strip() if "->" in ret else ""
            end = _close(code, opening, "{", "}")
            if end is None:
                self.unreadable.append(self._line(m.start()))
                continue
            owner = None
            for start, stop_, name in impls:
                if start < m.start() < stop_:
                    owner = name
            self.fns.append(
                Fn(self.path, m.group(1), owner, code[m.start() : opening], ret, code[opening:end],
                   self._line(m.start()), m.start())
            )

    def live_tests(self):
        """(line, name or None, body) of each function whose ignore reason names Valkey.

        The name is None where the attribute is not followed by a function
        the rule can read (a macro's `fn $name`, anything but attributes and
        qualifiers between them).
        """
        found = []
        for m in re.finditer(r"#\s*\[\s*ignore\s*=\s*" + re.escape(VALKEY_REASON) + r"\s*\]", self.code):
            head = re.compile(QUALIFIERS + r"(fn)\s+" + WORD).match(self.code, m.end())
            fn = None
            if head:
                fn = next((f for f in self.fns if f.offset == head.start(1)), None)
            if fn is None:
                found.append((self._line(m.start()), None, ""))
                continue
            found.append((self._line(m.start()), fn.name, fn.body))
        return found


def calls(body):
    """(qualifier, name) of each call in `body` that is not a method call or a macro."""
    pattern = re.compile(rf"(?<![\w.:])((?:{WORD}\s*::\s*)*)({WORD})\s*(?:::\s*<)?")
    out = []
    for m in pattern.finditer(body):
        after = m.end()
        if body[after - 1 : after] == "<":
            close = _angle_close(body, after - 1)
            if close is None:
                continue
            after = close
        while after < len(body) and body[after] in " \t\n":
            after += 1
        if after >= len(body) or body[after] != "(":
            continue
        before = body[: m.start()].rstrip()
        if before.endswith("fn") or m.group(2) in KEYWORDS:
            continue
        path = [p.strip() for p in m.group(1).split("::") if p.strip()]
        path = [p for p in path if p not in ("crate", "super", "self")]
        out.append((path[-1] if path else "", m.group(2)))
    return out


class Rule:
    """The sweep types, the sources and the resolution of calls over every file read."""

    def __init__(self, sources):
        self.sources = sources
        self.fns = [f for s in sources for f in s.fns]
        types = {}
        for s in sources:
            for name, text in s.types.items():
                types.setdefault(name, []).append(text)
        sweep = set(SWEEP_TYPES)
        changed = True
        while changed:
            changed = False
            for name, texts in types.items():
                if name not in sweep and any(_names(t, sweep) for t in texts):
                    sweep.add(name)
                    changed = True
        self.sweep_types = sweep
        self.source = {id(f): self._returns_sweep(f) for f in self.fns}
        changed = True
        while changed:
            changed = False
            for f in self.fns:
                if not self.source[id(f)] and CLOSURE.search(f.signature) and self.holds(f.path, f.body):
                    self.source[id(f)] = True
                    changed = True

    def _returns_sweep(self, f):
        if _names(f.ret, self.sweep_types):
            return True
        return bool(re.search(r"\bSelf\b", f.ret)) and f.owner in self.sweep_types

    def candidates(self, path, qualifier, name):
        if qualifier and qualifier[0].isupper():
            return [f for f in self.fns if f.name == name and f.owner == qualifier]
        free = [f for f in self.fns if f.name == name and f.owner is None]
        if qualifier:
            module = [f for f in free if _module(f.path) == qualifier]
            return module or free
        local = [f for f in free if f.path == path]
        return local or free

    def holds(self, path, body):
        """Whether `body`, in the file `path`, calls a sweep source."""
        for qualifier, name in calls(body):
            found = self.candidates(path, qualifier, name)
            if found and all(self.source[id(f)] for f in found):
                return True
        return False


def _names(text, words):
    return any(re.search(rf"\b{re.escape(w)}\b", text) for w in words)


def _module(path):
    """The module a file declares: its stem, or its directory's name for `mod.rs`."""
    directory, filename = os.path.split(path)
    stem = os.path.splitext(filename)[0]
    return os.path.basename(directory) if stem == "mod" else stem


def read_exemptions(path):
    """{(file, test): line} of the exemption list, and the errors in it.

    The list holds `test<TAB>FILE<TAB>NAME` lines, each under a comment that
    gives its reason; a blank line ends a reason. An entry with no reason
    above it, a line of another shape and an entry named twice are errors.
    """
    entries, errors = {}, []
    reason = False
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().split("\n")
    except OSError as err:
        return entries, [f"{path}: cannot be read ({err.strerror})"]
    for no, line in enumerate(lines, 1):
        if not line.strip():
            reason = False
            continue
        if line.startswith("#"):
            reason = True
            continue
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "test" or not fields[1] or not re.fullmatch(WORD, fields[2]):
            errors.append(f"{path}:{no}: a line is a comment or `test<TAB>FILE<TAB>NAME`")
            continue
        if not reason:
            errors.append(f"{path}:{no}: an exemption with no comment above it that gives its reason")
            continue
        key = (fields[1], fields[2])
        if key in entries:
            errors.append(f"{path}:{no}: {fields[1]} {fields[2]} is listed twice")
            continue
        entries[key] = no
    return entries, errors
