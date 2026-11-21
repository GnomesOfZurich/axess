"""Cargo's own configuration, for scripts/check-workflow-pins.sh.

A cargo setting can change what cargo builds or runs without a word of it
in the command: an alias turns `cargo tools` into `cargo install foo`, a
source or a registry serves other crates under the same names, an `include`
loads another file, and a program cargo runs in place of rustc or a runner
runs whatever it holds. So the settings cargo reads from a configuration
file in the repository (`.cargo/config.toml`, `.cargo/config`) or from
`--config KEY=VALUE` are held to a list of those that change none of it:
how cargo builds (`build.jobs`, `build.rustflags`, `build.target`, ...),
the profiles, the terminal, the network's retries, the flags of a target,
and the environment of the programs cargo runs. Every other setting, a
`--config` that names a file, and a line of a file this reader does not
take are refused by name. The variables of the environment that set what
cargo installs, where it reads its configuration or which programs it runs
in place of rustc are refused by name too. The flags cargo hands to rustc
(`build.rustflags`, `RUSTFLAGS`, ...) are allowed, and read: one that
names a program rustc runs in place of the linker, or code it loads (a
codegen backend, a plugin, another sysroot, a library path), is refused.
"""

import re

# Settings that change neither what cargo fetches nor which programs it runs.
# The minimum publish age only narrows what the resolver takes from the
# registry it already uses; every other `registry.` key names a registry, a
# token or a program that hands one out, and stays refused.
ALLOWED = re.compile(
    r"""(build\.(jobs|rustflags|rustdocflags|target|target-dir|incremental|dep-info-basedir)
       | profile\..+
       | term\..+
       | net\.(retry|offline)
       | http\.(timeout|low-speed-limit|multiplexing|debug)
       | target\.[^.]+\.(rustflags|rustdocflags)
       | env\..+
       | future-incompat-report\..+
       | cargo-new\..+
       | resolver\..+
       | registry\.global-min-publish-age)""",
    re.VERBOSE,
)
# The variables of the environment that set what cargo installs, where it
# reads its configuration, which program it runs in place of rustc, which
# registry it sends a token to, which program it asks for one, and which
# proxy and certificates it trusts.
ENV = re.compile(
    r"""CARGO_(ALIAS_.+|SOURCE_.+|REGISTRY_(DEFAULT|INDEX|CREDENTIAL_PROVIDER|GLOBAL_CREDENTIAL_PROVIDERS)
             |REGISTRIES_.+|CREDENTIAL_PROVIDER.*|HTTP_(PROXY|CAINFO|CHECK_REVOKE|SSL_VERSION.*)|HOME|UNSTABLE_.+
             |BUILD_RUSTC(_WRAPPER|_WORKSPACE_WRAPPER)?|BUILD_RUSTDOC|TARGET_[A-Z0-9_]+_(RUNNER|LINKER))
     | RUSTC(_WRAPPER|_WORKSPACE_WRAPPER)? | RUSTDOC | RUSTFMT""",
    re.VERBOSE,
)
# The variables that hold flags for rustc or rustdoc, and the settings that do.
FLAGS_ENV = re.compile(r"(CARGO_ENCODED_)?RUST(DOC)?FLAGS|CARGO_BUILD_RUST(DOC)?FLAGS|CARGO_TARGET_[A-Z0-9_]+_RUST(DOC)?FLAGS")
FLAGS_KEY = re.compile(r"(build|target\.[^.]+)\.(rustflags|rustdocflags)")
# A flag through which rustc runs a program or loads code the build did not name.
FLAG_RUNS = re.compile(r"linker|link-args?|codegen-backend|llvm-plugins|llvm-args|sysroot|--extern|(?<![A-Za-z0-9-])-L")
KEY = re.compile(r"""\s*((?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*'))*)\s*=""")
HEADER = re.compile(r"""\s*\[(\[)?\s*((?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*'))*)\s*\](?(1)\])\s*(\#.*)?$""")


def segments(text):
    """The parts of a dotted key, quotes removed."""
    parts = re.findall(r"""[A-Za-z0-9_-]+|"[^"]*"|'[^']*'""", text)
    return [p[1:-1] if p[:1] in "\"'" else p for p in parts]


def dotted(parts):
    """The key as one string; a dot inside a quoted part does not split it."""
    return ".".join(p.replace(".", "\u2024") for p in parts)


def allowed(key):
    if key.startswith("env.") and ENV.fullmatch(key[4:]):
        return False
    return ALLOWED.fullmatch(key) is not None


def flags_problem(name, value):
    """Why the flags a variable hands to rustc are not read: `value` is the
    text of the variable `name`, or None when an expansion fills it in.
    None for any other variable and for flags that run and load nothing."""
    if not FLAGS_ENV.fullmatch(name):
        return None
    if value is None:
        return "%s from a variable or an expression is not read: write the flags out" % name
    m = FLAG_RUNS.search(value)
    if m:
        return "%s names a program rustc runs or code it loads (%s), which is not read" % (name, m.group(0))
    return None


def setting_problem(text):
    """Why a `--config` value is not read, or None for an allowed KEY=VALUE."""
    m = KEY.match(text)
    if not m:
        return "a --config that names a file is not read: %s (name the setting as key=value)" % text
    key = dotted(segments(m.group(1)))
    if not allowed(key):
        return "a --config that sets %s is not read: %s (an alias, a source, a registry or a program cargo runs)" % (key, text)
    if FLAGS_KEY.fullmatch(key) and FLAG_RUNS.search(text[m.end():]):
        return "a --config whose %s names a program rustc runs or code it loads is not read: %s" % (key, text)
    return None


def value_end(text, i, state):
    """Scan a value from i; `state` carries the brackets and braces left open
    and a multi-line string across lines. A value holds no key this reader
    judges: an inline table sits under the key it is the value of."""
    depth, string = state
    while i < len(text):
        if string:
            close = text.find(string, i)
            if close == -1:
                return depth, string
            i = close + len(string)
            string = None
            continue
        c = text[i]
        if c == "#":
            break
        if text.startswith('"""', i) or text.startswith("'''", i):
            string = text[i:i + 3]
            i += 3
        elif c in "\"'":
            string = c
            i += 1
            close = text.find(c, i)
            while close > 0 and c == '"' and text[close - 1] == "\\":
                close = text.find(c, close + 1)
            if close == -1:
                return depth, None
            i = close + 1
            string = None
        elif c in "[{":
            depth += 1
            i += 1
        elif c in "]}":
            depth -= 1
            i += 1
        else:
            i += 1
    return depth, string


def file_problems(text):
    """(line, message) for each setting of a cargo configuration file the
    check does not allow, and each line it cannot read."""
    problems = []
    table = []
    state = (0, None)
    flags = None
    for number, line in enumerate(text.split("\n"), 1):
        if state != (0, None):
            if flags and FLAG_RUNS.search(line):
                problems.append((number, "flags that name a program rustc runs or code it loads are not read: %s" % flags))
            state = value_end(line, 0, state)
            continue
        if not line.strip() or line.strip().startswith("#"):
            continue
        header = HEADER.match(line)
        if header:
            table = segments(header.group(2))
            continue
        m = KEY.match(line)
        if not m:
            problems.append((number, "a line the check cannot read: %s" % line.strip()))
            continue
        key = dotted(table + segments(m.group(1)))
        if not allowed(key):
            problems.append((number, "a setting that changes what cargo fetches or runs is not read: %s" % key))
        flags = key if FLAGS_KEY.fullmatch(key) else None
        if flags and FLAG_RUNS.search(line[m.end():]):
            problems.append((number, "flags that name a program rustc runs or code it loads are not read: %s" % flags))
        state = value_end(line, m.end(), (0, None))
    if state != (0, None):
        problems.append((len(text.split("\n")), "a value that does not close"))
    return problems
