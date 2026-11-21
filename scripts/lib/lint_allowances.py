"""Lint allowances in Rust source and in cargo's configuration, for
scripts/check-lint-allowances.sh.

The repository's rule is that a warning is fixed, not silenced. A lint is
silenced in these ways; this reads all but the last, which
scripts/check-member-lints.sh reads:

- an `allow` or `expect` attribute, outer (`#[allow(..)]`) or inner
  (`#![allow(..)]`), on any lint (rustc, clippy, rustdoc), standing alone
  or in the attribute list of a `cfg_attr`, in the code or in a doc
  example rustdoc compiles;
- an attribute a macro builds from a metavariable, whose expansion the
  source does not show;
- a rustc flag that allows a lint, caps the levels or adds a crate
  attribute (`-A`, `--allow`, `--cap-lints`, `-Z crate-attr`), in a cargo
  configuration, in a flags variable a workflow or a script sets, or on a
  compiler's command line;
- a lint set to `allow` or `expect` in a manifest's lint table.

The attribute reading is a construction, not a list of forms seen. Comments
are dropped and literals blanked first (`rust_source.blanked_lines`), so
text that only looks like an attribute, in a comment, a doc comment or a
string, is not code. Then every attribute (`#`, an optional `!`, then a
bracket group, with any blanks between) is read whole, over as many lines
as it spans:

1. The identifier `allow` or `expect` (a raw `r#allow` too) followed by a
   parenthesised group anywhere in the attribute's body, at any depth, is
   refused. At the top it is the lint attribute itself; in a `cfg_attr`
   list, at any nesting, it is one the build switches on; inside any other
   attribute it is an argument a procedural macro may turn into one. A
   rule that read only the first two would hold only for macros it knows.
2. A `$` in an attribute's body is a metavariable (`$crate` is a path, and
   is read as `crate`), and a `#` there is an interpolation of `quote!`
   (with literals blanked and raw identifiers read without their `r#`, no
   other `#` stands inside an attribute). Its expansion is whatever a
   caller passed, so the attribute is refused, with two shapes that are
   sound by construction: `#[$name:meta]`, which is a matcher (a fragment
   specifier stands in a matcher only), and `#[$name]` in the transcriber
   of a `macro_rules` arm whose matcher binds `$name` as `#[$name:meta]`.
   The caller of such an arm writes the whole attribute, `#` and brackets
   included, where it calls the macro, so rule 1 reads it at that call
   site.

An entry of the exemption file names a file and a lint (rule 1 only); it
exempts that lint in that file. Each entry gives its reason, and an entry
that exempts nothing is refused, so the file cannot hold a line the tree
no longer needs.
"""

import os
import re

from rust_source import blanked_lines

WORD = re.compile(r"(?<![A-Za-z0-9_$])(?:r#)?(allow|expect)\s*\(")
ATTRIBUTE = re.compile(r"#\s*(!?)\s*\[")
META_MATCHER = re.compile(r"\$\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*meta")
META_BOUND = re.compile(r"#\s*!?\s*\[\s*\$\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*meta\s*\]")
MACRO_RULES = re.compile(r"(?<![A-Za-z0-9_])macro_rules\s*!\s*(?:r#)?[A-Za-z_][A-Za-z0-9_]*\s*")
OPENERS = {"(": ")", "[": "]", "{": "}"}


def group_end(code, i):
    """The index after the bracket group that opens at `code[i]`, or None.

    Every kind of bracket counts toward the depth: in code with its literals
    blanked, brackets nest properly.
    """
    depth = 0
    for j in range(i, len(code)):
        ch = code[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def split_top(body):
    """The comma-separated parts of `body` at its own depth, stripped."""
    out, depth, part = [], 0, ""
    for ch in body + ",":
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            if part.strip():
                out.append(part.strip())
            part = ""
        else:
            part += ch
    return out


def transcribers(code):
    """(start, end, bound) of each `macro_rules` arm's transcriber in `code`.

    `bound` is the set of metavariables the arm's matcher binds as
    `#[$name:meta]`. A definition this cannot read gives no range, so an
    attribute in it is judged as outside any transcriber, which refuses more.
    """
    out = []
    for m in MACRO_RULES.finditer(code):
        i = m.end()
        if i >= len(code) or code[i] not in OPENERS:
            continue
        end = group_end(code, i)
        if end is None:
            continue
        j = i + 1
        stop = end - 1
        while j < stop:
            while j < stop and (code[j].isspace() or code[j] == ";"):
                j += 1
            if j >= stop or code[j] not in OPENERS:
                break
            matcher_end = group_end(code, j)
            if matcher_end is None:
                break
            matcher = code[j:matcher_end]
            k = matcher_end
            while k < stop and code[k].isspace():
                k += 1
            if not code.startswith("=>", k):
                break
            k += 2
            while k < stop and code[k].isspace():
                k += 1
            if k >= stop or code[k] not in OPENERS:
                break
            body_end = group_end(code, k)
            if body_end is None:
                break
            out.append((k, body_end, set(META_BOUND.findall(matcher))))
            j = body_end
    return out


def lints_of(code, i):
    """The lint names in the parenthesised group that opens at `code[i]`."""
    end = group_end(code, i)
    if end is None:
        return ["(unclosed)"]
    names = []
    for part in split_top(code[i + 1 : end - 1]):
        if re.match(r"reason\s*=", part):
            continue
        names.append(re.sub(r"\s+", "", part))
    return names or ["(none)"]


def attributes(code):
    """(offset, inner, body offset, body) of each attribute in `code`."""
    for m in ATTRIBUTE.finditer(code):
        start = m.end() - 1
        end = group_end(code, start)
        if end is None:
            continue
        yield m.start(), m.group(1) == "!", start + 1, code[start + 1 : end - 1]


def findings(path, text):
    """(line, kind, detail) for each allowance in one file's text.

    kind is "lint" (rule 1, detail the lint name) or "macro" (rule 2,
    detail the attribute as read).
    """
    code = "\n".join(blanked_lines(text))
    arms = None
    out = []
    for offset, inner, body_at, body in attributes(code):
        line = code.count("\n", 0, offset) + 1
        for w in WORD.finditer(body):
            paren = body_at + w.end() - 1
            for lint in lints_of(code, paren):
                out.append((line, "lint", ("#![" if inner else "#[") + w.group(1) + "(" + lint + ")]"))
        plain = re.sub(r"\$\s*crate\b", "crate", body)
        plain = re.sub(r"(?<![A-Za-z0-9_])r#(?=[A-Za-z_])", "", plain)
        if "$" not in plain and "#" not in plain:
            continue
        stripped = plain.strip()
        if re.fullmatch(META_MATCHER.pattern, stripped):
            continue
        name = re.fullmatch(r"\$\s*([A-Za-z_][A-Za-z0-9_]*)", stripped)
        if name:
            if arms is None:
                arms = transcribers(code)
            inside = [a for a in arms if a[0] <= offset < a[1]]
            if inside and name.group(1) in min(inside, key=lambda a: a[1] - a[0])[2]:
                continue
        shown = re.sub(r"\s+", " ", body.strip())
        out.append((line, "macro", ("#![" if inner else "#[") + shown + "]"))
    return out


def read_exemptions(path):
    """(entries, errors): entries maps (file, lint) to its line in `path`."""
    entries, errors = {}, []
    if not os.path.exists(path):
        return entries, [f"{path}: the exemption file is missing"]
    with open(path, encoding="utf-8") as f:
        for no, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 3 or not all(parts):
                errors.append(f"{path}:{no}: an entry is `file | lint | reason`, each part given")
                continue
            if not re.search(r"[^\W\d_]", parts[2]):
                errors.append(f"{path}:{no}: the reason holds no word")
                continue
            entries[(parts[0], parts[1])] = no
    return entries, errors


FLAG = re.compile(r"^(-A.*|--allow(=.*)?|--cap-lints(=.*)?)$")
FLAG_KEYS = ("rustflags", "rustdocflags")
FLAG_ENV = ("RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS")


def flag_words(value):
    """The words of a flags value: a list of strings, a string, or an env table."""
    if isinstance(value, dict):
        value = value.get("value", "")
    if isinstance(value, list):
        return [str(v) for v in value]
    text = str(value)
    return text.split("\x1f") if "\x1f" in text else text.split()


def config_findings(rel, doc):
    """(where, flag) for each flag in a cargo configuration that silences lints."""
    out = []

    def walk(node, here):
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            at = here + [key]
            is_flags = key in FLAG_KEYS or (here[-1:] == ["env"] and key in FLAG_ENV)
            if is_flags:
                words = flag_words(value)
                for word in words:
                    if FLAG.match(word) or "crate-attr" in word:
                        out.append((rel + ": " + ".".join(at), word))
            else:
                walk(value, at)

    walk(doc, [])
    return out


# Doc examples. rustdoc compiles the Rust code blocks of every doc comment
# as a test, so an allowance written there switches a lint off in code the
# repository builds. The docs of an item are its `///` or `//!` lines, its
# `/** */` or `/*! */` comments, its `doc = "..."` attributes (under a
# `cfg_attr` too) and the files `doc = include_str!(...)` names. A run of
# them is read as rustdoc reads it: a fenced block is Rust when its info
# string is empty, names `rust`, or holds only rustdoc's own words, and a
# block indented four spaces is Rust; hidden lines (`# `) are code. The
# alternatives of adjacent `cfg_attr` doc attributes are one line, a fence
# when any of them is one, and Rust when any of them is. Each Rust block is
# then read as a file of its own, by the rules above.

DOC_LINE = re.compile(r"\s*(?://!|///(?!/))(.*)")
DOC_ATTR = re.compile(r'\s*#\s*!?\s*\[\s*(cfg_attr\s*\(.*,\s*)?doc\s*=\s*"((?:[^"\\]|\\.)*)"\s*\)?\s*\]\s*$')
DOC_INCLUDE = re.compile(r'doc\s*=\s*include_str!\s*\(\s*"([^"]+)"\s*\)')
FENCE = re.compile(r"\s*(`{3,}|~{3,})\s*(.*)")
RUSTDOC_WORDS = {"rust", "should_panic", "no_run", "ignore", "test_harness", "compile_fail",
                 "standalone_crate", "standalone-crate"}


def rust_info(info):
    words = [w for w in re.split(r"[\s,{}]+", info) if w and not w.startswith(".")]
    known = all(w in RUSTDOC_WORDS or w.startswith(("edition", "ignore-")) or re.fullmatch(r"E\d{4}", w)
                for w in words)
    return not words or "rust" in words or known


def doc_string(raw):
    """The text of a doc attribute's string literal, line by line."""
    escapes = {"n": "\n", "t": "\t", "r": "", "0": "", "\\": "\\", '"': '"', "'": "'"}
    text = re.sub(r"\\(.)", lambda m: escapes.get(m.group(1), m.group(1)), raw)
    return text.split("\n")


def doc_runs(text):
    """Runs of doc lines: lists of (file line, [text of each alternative])."""
    runs, run, block, last_cfg = [], [], False, None
    for no, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if block:
            end = stripped.endswith("*/")
            body = stripped[:-2] if end else stripped
            run.append((no, [re.sub(r"^\*\s?", "", body)]))
            block = not end
            continue
        m = DOC_LINE.match(line)
        a = DOC_ATTR.match(line)
        if m:
            run.append((no, [m.group(1)[1:] if m.group(1).startswith(" ") else m.group(1)]))
            last_cfg = None
        elif a:
            values = doc_string(a.group(2))
            if a.group(1) and last_cfg == no - 1 and run:
                # An alternative of the line before: the same doc line in
                # another build.
                run[-1][1].append(values[0])
                run.extend((no, [v]) for v in values[1:])
            else:
                run.extend((no, [v]) for v in values)
            last_cfg = no if a.group(1) else None
        elif re.match(r"/\*[*!](?![*/])", stripped):
            body = stripped[3:]
            end = body.endswith("*/")
            run.append((no, [body[:-2] if end else body]))
            block = not end
            last_cfg = None
        elif stripped.startswith("#") and "[" in stripped:
            # Another attribute between doc lines does not end their run.
            last_cfg = None
        else:
            if run:
                runs.append(run)
            run, last_cfg = [], None
    if run:
        runs.append(run)
    return runs


def doc_code(lines):
    """(file line, code) of every line of a Rust block in a run of doc
    lines given as (file line, [alternatives])."""
    texts = [alts[0] for _, alts in lines]
    indents = [len(t) - len(t.lstrip()) for t in texts if t.strip()]
    cut = min(indents) if indents else 0
    out, fence, rust = [], None, False
    for no, alts in lines:
        fences = [FENCE.match(a[cut:] if a[:cut].strip() == "" else a) for a in alts]
        opened = [f for f in fences if f]
        if fence is None and opened:
            fence = opened[0].group(1)[0]
            rust = any(rust_info(f.group(2)) for f in opened)
            continue
        if fence is not None:
            if any(f and f.group(1)[0] == fence and not f.group(2).strip() for f in fences):
                fence = None
                continue
            if rust:
                code = alts[0][cut:] if alts[0][:cut].strip() == "" else alts[0]
                code = code.lstrip(" ")
                if code.startswith("##"):
                    code = code[1:]
                elif code.startswith("# ") or code == "#":
                    code = code[2:]
                out.append((no, code))
            continue
        body = alts[0][cut:] if alts[0][:cut].strip() == "" else alts[0]
        if body.startswith("    ") or body.startswith("\t"):
            out.append((no, body.strip()))
    return out


def doc_findings(path, text, read=None):
    """(line, kind, detail) for each allowance in the Rust code of the doc
    examples of one file, and of the files its docs include. Lines of an
    included file are given as `file:line` in the detail."""
    out = []
    sources = [(None, text)]
    for m in DOC_INCLUDE.finditer("\n".join(blanked_lines(text, string=lambda literal: literal))):
        included = os.path.normpath(os.path.join(os.path.dirname(path), m.group(1)))
        try:
            with (read or open)(included, encoding="utf-8") as f:
                sources.append((included, "\n".join("/// " + l for l in f.read().split("\n"))))
        except OSError:
            out.append((code_line(text, m.start()), "doc", "an included doc file that cannot be read: %s" % included))
    for where, source in sources:
        for run in doc_runs(source):
            code = doc_code(run)
            if not code:
                continue
            lines = [no for no, _ in code]
            for k, kind, detail in findings(path, "\n".join(c for _, c in code)):
                line = lines[k - 1]
                if where is not None:
                    out.append((1, kind, "%s (in a doc example of %s:%d)" % (detail, where, line)))
                else:
                    out.append((line, kind, detail + " (in a doc example)"))
    return out


def code_line(text, offset):
    return text.count("\n", 0, offset) + 1


# Lint flags set in the environment of a build: in a workflow (an `env:` map
# or an action's input at any level), and in a shell script or a run step
# (an assignment, `export`, `env`, a line written by `echo` or `printf`, and
# the words after `--` of cargo, rustc and rustdoc). A flags variable is any
# whose name ends in RUSTFLAGS or RUSTDOCFLAGS, which covers every variable
# cargo reads flags from. A value the check cannot read (an expression, a
# variable other than the one being extended) is refused with the flags it
# may hold.

FLAGS_NAME = re.compile(r"[A-Za-z0-9_]*RUST(?:DOC)?FLAGS", re.IGNORECASE)
ASSIGNED = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")


def silencing(words):
    return [w for w in words if FLAG.match(w) or "crate-attr" in w]


def flag_tokens(text):
    return [t for t in re.split(r"[\s\x1f]+", text.strip()) if t]


def value_findings(name, parts):
    """The silencing flags of a flags variable's value given as word parts;
    a part filled in by an expansion other than the variable itself is one."""
    out = []
    for kind, text in parts:
        if kind == "lit":
            out.extend(silencing(flag_tokens(text)))
        elif not re.fullmatch(r"\$(\{%s(:?[-=+][^}]*)?\}|%s)" % (name, name), text):
            out.append("%s from %s, which the check cannot read" % (name, text))
    return out


def merged(parts):
    """A word's parts with adjacent literal pieces joined."""
    out = []
    for kind, text in parts:
        if out and kind == "lit" and out[-1][0] == "lit":
            out[-1] = ("lit", out[-1][1] + text)
        else:
            out.append((kind, text))
    return out


def word_value(word):
    """(name, the parts of the value) of an assignment word, or None."""
    parts = merged(word.parts)
    if not parts or parts[0][0] != "lit":
        return None
    m = ASSIGNED.match(parts[0][1])
    if not m or not FLAGS_NAME.fullmatch(m.group(1)):
        return None
    return m.group(1), [("lit", parts[0][1][m.end():])] + parts[1:]


def script_flag_findings(text, line_of, shell_words):
    """(line, flag) of each silencing flag a shell script sets."""
    lexed = shell_words.lex(text, line_of)
    out = []
    for command in lexed.commands:
        words = shell_words.opened(command.words)
        k = 0
        while k < len(words) and ASSIGNED.match(words[k].raw):
            found = word_value(words[k])
            if found:
                out.extend((command.line, f) for f in value_findings(*found))
            k += 1
        if k >= len(words):
            continue
        name = (words[k].literal() or "").rsplit("/", 1)[-1]
        args = words[k + 1:]
        if name in ("export", "declare", "typeset", "local", "readonly", "env"):
            for w in args:
                found = word_value(w)
                if found:
                    out.extend((command.line, f) for f in value_findings(*found))
        elif name in ("echo", "printf"):
            for w in args:
                literal = "".join(t for kind, t in w.parts if kind == "lit")
                for m in re.finditer(r"(%s)=(\S*(?:\s+\S+)*)" % FLAGS_NAME.pattern, literal, re.IGNORECASE):
                    out.extend((command.line, f) for f in silencing(flag_tokens(m.group(2))))
        elif name in ("rustc", "rustdoc", "clippy-driver"):
            out.extend((command.line, f) for f in compiler_words(name, args))
        elif name in ("cargo", "cargo-clippy"):
            sub, rest = cargo_subcommand(args) if name == "cargo" else ("clippy", args)
            for w in args:
                literal = w.literal()
                if literal is not None and re.search(r"rust(doc)?flags", literal, re.IGNORECASE):
                    if re.search(r"-A|--allow|--cap-lints|crate-attr", literal):
                        out.append((command.line, "%s --config sets flags that silence lints: %s" % (name, literal)))
            if "--" in [w.literal() for w in rest]:
                after = rest[[w.literal() for w in rest].index("--") + 1:]
                if sub in CARGO_TO_COMPILER:
                    out.extend((command.line, f) for f in compiler_words("cargo " + sub, after))
                elif sub is None:
                    out.append((command.line, "cargo runs a subcommand the check cannot read, with words after --"))
    return out


# The cargo subcommands that hand the words after `--` to the compiler;
# `cargo test -- ...` and `cargo run -- ...` hand them to the program built.
CARGO_TO_COMPILER = ("rustc", "rustdoc", "clippy")
CARGO_OPTION_ARGS = ("--manifest-path", "--config", "-C", "-Z", "--color", "--target-dir", "--explain")


def cargo_subcommand(args):
    """(the subcommand cargo runs, or None when it cannot be read; the words after it)."""
    k = 0
    while k < len(args):
        literal = args[k].literal()
        if literal is None:
            return None, args[k + 1:]
        if literal in CARGO_OPTION_ARGS:
            k += 2
            continue
        if literal.startswith(("-", "+")):
            k += 1
            continue
        return literal, args[k + 1:]
    return None, []


def compiler_words(name, words):
    """The silencing flags among words a compiler reads; a word the check
    cannot read is one."""
    out = []
    for w in words:
        literal = w.literal()
        if literal is None:
            out.append("%s reads %s, which the check cannot read" % (name, w.raw))
        else:
            out.extend(silencing([literal]))
    return out


def workflow_flag_findings(doc, yaml):
    """(line, flag) of each silencing flag a workflow's maps set, at any
    level (`env:`, an action's `with:`)."""
    out = []
    for node in yaml.walk(doc):
        if not isinstance(node, yaml.Mapping):
            continue
        for key, value in node.pairs:
            if not FLAGS_NAME.fullmatch(key.value):
                continue
            if not isinstance(value, yaml.Scalar):
                out.append((key.line, "%s that is not a single value" % key.value))
                continue
            if "${{" in value.value:
                out.append((key.line, "%s from an expression, which the check cannot read" % key.value))
                continue
            out.extend((key.line, f) for f in silencing(flag_tokens(value.value)))
    return out
