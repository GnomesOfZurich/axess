"""The rules of scripts/check-clock-usage.sh: which code may read which clock.

A file is library code, an example's own code, test code, or not scanned
(`scope`). Library code (each crate's `src/`, the `testing` fixtures
adopters' tests use included) reads the time through an injected `Clock`;
its `#[cfg(test)]` items are test code. Test code is an integration test, a
test module file inside `src/`, a `#[cfg(test)]` item, or a file its parent
declares under `#[cfg(test)]`. An example's own code is not scanned, but its
test modules are. Benches (which time real work by design) and fuzz targets
are not scanned. `axess-clock` holds the clock (`scope` calls its library
code `clock`): it is held to the library rule with one read admitted,
`SystemTime::now` in the body of `SystemClock`'s `now`, the read every other
crate reaches through `Clock::now` (`clock_crate_reads`), and one renaming
of a clock declared, its mock under the public name `DeterministicClock`
(`DECLARED_ALIAS`); its own tests,
which drive `SystemClock` and `MockClock::now` by name, are not scanned. The
code of a doc example (a fenced block
in a `///` or `//!` comment, which `cargo test` compiles and runs) is held
to the library rule wherever it stands, since it teaches what an adopter
copies into production.

What counts in library code (`LIBRARY_READ`): a read of the wall clock or of
std's monotonic clock by name (`Utc::now`, `Local::now`, chrono's `today`, `SystemTime::now`,
`Instant::now` unless spelled `tokio::time::Instant::now`, the time
crate's `UtcDateTime::now`, `OffsetDateTime::now_utc` and `now_local`, and
its reads of the local offset, `current_local_offset` and
`local_offset_at`, jiff's `Timestamp::now` and `Zoned::now` and its reads
of the host's time zone, `TimeZone::system` and `TimeZone::try_system`,
`UNIX_EPOCH.elapsed()`, `SystemTime::elapsed`) and the renaming of a clock type (`Instant as
Stopwatch`, `type Wall = Utc;`), which would hide the next read. The one
name a clock has been given, `DeterministicClock` for the mock, is known to
every rule as `MockClock` is, so nothing is hidden behind it: a read
through it, a mock built under it and a renaming of it count as the mock's
own do.

What counts in test code (`test_findings`), on top of that: tokio's
`Instant::now` in any spelling, `MockClock::now` (a mock started at the real
time, also as `DeterministicClock::now`) and `SystemClock` (`TEST_READ`), and a call to a system-clock form no
chain can clock. A test that times real work reads
`axess_testing::stopwatch::Stopwatch`, the one named door to the machine's
monotonic clock. A world test (`world_test`: an integration test, or an
example's tests of its own application) is also held to the forms a chain
can clock, and to one clock per function.

A system-clock form (`forms`) is a function of library or example code that
names `SystemClock`; a constructor of a type a setter clocks whose signature
hands it no clock and nothing that carries one (`MemorySessionStore::new`,
whose body reaches the system clock through another type's constructor); or
a function that hands out what a form built, or a value holding a clock
built from it, without setting its clock. A form whose result a chained setter can still reach
(`MockIdentityStore::new`, `OAuthProviderConfig::discover` through `?`) is
settled by a chain that sets the clock (`.with_clock(...)`) or refuses the
construction (`let Err(e) =`, `.unwrap_err()`); any other form
(`factor_secret_cipher()`, `make_password_service`) is refused, since a
clocked sibling exists for it. The match is by name, so a form reached
through `Default::default()` is not seen, and a renamed clock type is
refused instead.

These are text rules over code with its comments and literals taken out
(scripts/lib/rust_source.py). They see a name, not a type, so a value that
already holds a clock reading (a `SystemTime` constant's `.elapsed()`) is
not seen.
"""

import re

from rust_source import (
    blanked_lines,
    declared_for_tests,
    integration_test,
)

SKIPPED_ROOTS = ("fuzz",)
# The crate that holds the clock, and the one read of the system clock its
# library code may make: this name, in the body of `SystemClock`'s `now`.
CLOCK_CRATE = "axess-clock"
SYSTEM_CLOCK = ("SystemClock", "now")
SYSTEM_CLOCK_READ = "SystemTime::now"

# The mock clock by either of its names: its own, and the public alias
# axess-clock declares for it.
MOCK_CLOCK = r"(?:MockClock|DeterministicClock)"
# The declaration of that alias, the one renaming of a clock that is not a
# finding, and only in axess-clock's library code. Every rule below knows
# the name it gives, so the renaming hides no read.
DECLARED_ALIAS = re.compile(r"\bpub\s+use\s+testing::MockClock\s+as\s+DeterministicClock\s*;")

CLOCK_NAMES = r"(?:Utc|Local|SystemTime|Instant|SystemClock|MockClock|DeterministicClock|OffsetDateTime|UtcDateTime|Timestamp|Zoned|UNIX_EPOCH)"
RENAMED = (
    r"\b" + CLOCK_NAMES + r"\s+as\s+\w+"
    r"|\btype\s+\w+\s*=\s*(?:[\w]+::)*" + CLOCK_NAMES + r"\s*;"
)
WALL = (
    r"\b(?:Utc|Local|SystemTime|UtcDateTime|Timestamp|Zoned)::now\b"
    r"|\b(?:Utc|Local)::today\b"
    r"|\bnow_(?:utc|local)\b"
    r"|\b(?:current_local_offset|local_offset_at)\b"
    r"|\bTimeZone::(?:try_)?system\b"
    r"|\bUNIX_EPOCH\s*\.\s*elapsed\b"
    r"|\bSystemTime::elapsed\b"
)
LIBRARY_READ = re.compile(WALL + r"|(?<!tokio::time::)\bInstant::now\b|" + RENAMED)
TEST_READ = re.compile(
    WALL + r"|\bInstant::now\b|\b" + MOCK_CLOCK + r"::now\b|\bSystemClock\b|" + RENAMED
)
# A clock built: a mock, or a helper of the tests that hands out a new one
# (`test_clock()`, `frozen_clock()`).
CLOCK_BUILT = re.compile(
    r"(?<![\w.])(?<!fn )(?:\w+_)?clock\s*\(\s*\)|\b" + MOCK_CLOCK + r"::at(?:_reference)?\s*\("
)

FN = re.compile(r"\bfn\s+(\w+)")
IMPL = re.compile(r"\bimpl\b")


def test_source(path):
    """Whether every line of a file inside `src/` is compiled for tests only."""
    parts = path.split("/")
    name = parts[-1]
    if name == "tests.rs" or name.endswith("_tests.rs"):
        return True
    if "tests" in parts[parts.index("src") :]:
        return True
    return declared_for_tests(path)


def scope(path):
    """`library`, `clock` (the library code of axess-clock), `example` (an
    example's own code), `test`, or None (not scanned)."""
    parts = path.split("/")
    if parts[0] in SKIPPED_ROOTS or "benches" in parts:
        return None
    if parts[0] == CLOCK_CRATE:
        if "src" not in parts or integration_test(path) or test_source(path):
            return None
        return "clock"
    if integration_test(path):
        return "test"
    if "src" not in parts:
        return None
    if test_source(path):
        return "test"
    return "example" if parts[0] == "examples" else "library"


def crate_of(path):
    """The crate directory a path belongs to (`axess-core`, `examples/sqlite`)."""
    parts = path.split("/")
    return "/".join(parts[:2]) if parts[0] == "examples" else parts[0]


def doc_example_lines(text):
    """(line number, code) for each line of a fenced block in a doc comment.

    A block whose info string names another language (`text`, `toml`, `sh`)
    is not Rust and is skipped. Comments and literals are blanked as in code.
    """
    out = []
    fence = None
    for no, line in enumerate(text.split("\n"), 1):
        m = re.match(r"\s*//[/!]\s?(.*)$", line)
        if not m:
            fence = None
            continue
        body = m.group(1)
        if body.lstrip().startswith("```"):
            if fence is None:
                info = body.lstrip()[3:].strip()
                words = [w for w in re.split(r"[,\s]+", info) if w]
                rust = not words or any(
                    w in ("rust", "no_run", "ignore", "should_panic", "compile_fail")
                    or w.startswith("edition")
                    for w in words
                )
                fence = "rust" if rust else "other"
            else:
                fence = None
            continue
        if fence == "rust":
            code = re.sub(r"^\s*#\s", " ", body)
            blanked = blanked_lines(code)[0]
            if blanked.strip():
                out.append((no, blanked))
    return out


def clock_crate_reads(numbered, total):
    """The reads in a library file of axess-clock, as (line number, read),
    less the one it may make: the first `SystemTime::now` in the body of
    `SystemClock`'s `now`, on a line that holds no other read. A second
    read there, another clock's read there, and any read in another
    function are findings.

    The declared alias of the mock (`DECLARED_ALIAS`) is no finding either,
    on a line that holds nothing else the rule counts. Any other renaming
    of a clock in the crate is one, and so is that declaration made twice.

    `numbered` is the file's production code as (line number, code) pairs
    and `total` its number of lines.
    """
    hits = [(no, m.group(0).strip()) for no, code in numbered if (m := LIBRARY_READ.search(code))]
    code_of = dict(numbered)
    for i, (no, _read) in enumerate(hits):
        if DECLARED_ALIAS.search(code_of[no]) and len(LIBRARY_READ.findall(code_of[no])) == 1:
            hits = hits[:i] + hits[i + 1 :]
            break
    text = full_text(numbered, total)
    for owner, name, _self, start, end, _params, _returns in functions(text):
        if (owner, name) != SYSTEM_CLOCK:
            continue
        first, last = text.count("\n", 0, start) + 1, text.count("\n", 0, end) + 1
        for i, (no, read) in enumerate(hits):
            if (
                first <= no <= last
                and read == SYSTEM_CLOCK_READ
                and len(LIBRARY_READ.findall(code_of[no])) == 1
            ):
                return hits[:i] + hits[i + 1 :]
        break
    return hits


def _matching(text, i, open_ch="{", close_ch="}"):
    """The index of the bracket that closes the one at `text[i]`."""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == open_ch:
            depth += 1
        elif text[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j
    return len(text)


def _impl_type(header):
    """The type an `impl` header names: `Foo` in `impl<T> Trait for a::Foo<T> where ...`."""
    header = header.strip()
    if header.startswith("<"):
        depth = 0
        for k, ch in enumerate(header):
            depth += ch == "<"
            depth -= ch == ">"
            if depth == 0:
                header = header[k + 1 :]
                break
    header = re.split(r"\bwhere\b", header)[0]
    flat, depth = "", 0
    for ch in header:
        depth += ch == "<"
        if depth == 0:
            flat += ch
        depth -= ch == ">"
    target = re.split(r"\bfor\b", flat)[-1]
    names = re.findall(r"\w+", target)
    return names[-1] if names else None


def functions(text):
    """Each function in `text` (blanked code):
    (type, name, has_self, start, end, params, returns).

    `type` is the type of the innermost `impl` block around it, or None for a
    free function; `start` and `end` bound its body; `params` and `returns`
    are the text of its parameter list and return type. A function without a
    body (a trait's required method) is skipped.
    """
    impls = []
    for m in IMPL.finditer(text):
        brace = text.find("{", m.end())
        semi = text.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        impls.append((m.start(), _matching(text, brace), _impl_type(text[m.end() : brace])))
    out = []
    for m in FN.finditer(text):
        paren = text.find("(", m.end())
        if paren < 0:
            continue
        close = _matching(text, paren, "(", ")")
        brace = text.find("{", close)
        semi = text.find(";", close)
        if brace < 0 or (0 <= semi < brace):
            continue
        params = text[paren + 1 : close]
        has_self = re.match(r"\s*(?:&\s*(?:'\w+\s+)?)?(?:mut\s+)?self\b", params) is not None
        around = [im for im in impls if im[0] < m.start() <= im[1]]
        owner = max(around, key=lambda im: im[0])[2] if around else None
        returns = text[close + 1 : brace].split("->", 1)[1] if "->" in text[close + 1 : brace] else ""
        out.append((owner, m.group(1), has_self, brace, _matching(text, brace), params, returns))
    return out


STRUCT = re.compile(r"\bstruct\s+(\w+)")


def clock_holders(text):
    """The types `text` (blanked code) declares with a clock in them: a
    struct whose fields or generic parameters name `Clock`."""
    out = set()
    for m in STRUCT.finditer(text):
        depth, end = 0, None
        for k in range(m.end(), len(text)):
            ch = text[k]
            depth += ch == "<"
            depth -= ch == ">" and text[k - 1] != "-"
            if depth == 0 and ch in ";{(":
                end = k
                break
        if end is None:
            continue
        close = end if text[end] == ";" else _matching(text, end, text[end], "}" if text[end] == "{" else ")")
        if re.search(r"\bClock\b", text[m.end() : close + 1]):
            out.add(m.group(1))
    return out


def returned_type(returns):
    """The type a return type hands out, for a chained call: `Foo` in
    `a::Foo<T>`, in `Result<Foo, E>` and in `Option<Foo>` (a `?` or an
    `expect` reaches it), but `Arc` in `Arc<Foo>`, whose value a consuming
    setter cannot take."""
    text = returns.strip()
    while True:
        m = re.match(r"(?:\w+\s*::\s*)*(\w+)\s*(<)?", text)
        if not m:
            return None
        if m.group(1) in ("Result", "Option") and m.group(2):
            text = text[m.end() :]
            continue
        return m.group(1)


def _innermost(fns, pos):
    inside = [f for f in fns if f[3] <= pos <= f[4]]
    return max(inside, key=lambda f: f[3]) if inside else None


def full_text(numbered, total):
    """Rebuild a text of `total` lines from (line number, code) pairs."""
    lines = [""] * (total + 1)
    for no, code in numbered:
        lines[no] = code
    return "\n".join(lines[1:])


def forms(sources):
    """The system-clock forms of library and example code, and the clock setters.

    A type holds a clock when a setter sets one (`with_clock`) or its
    declaration names `Clock` (`clock_holders`). A constructor of a type a
    setter clocks, taking no `self`, no clock and nothing that holds one,
    is a form whatever its body calls: its signature leaves the clock to
    the default.

    `sources` maps a path to its library text (blanked, test items out).
    Returns ({(crate, type or None, name): (has_self, path, settable)},
    setters), where `settable` says the form returns a value whose clock a
    chained setter can still set, and `setters` names every method that takes
    a `Clock` and returns `Self` (`with_clock`, `clock`).
    """
    found = {}
    bodies = []
    settable_types = set()
    setters = set()
    clocked_types = set()
    for path, text in sources.items():
        fns = functions(text)
        for owner, name, has_self, _, _, params, returns in fns:
            if owner and has_self and "Clock" in params and "Self" in returns:
                settable_types.add(owner)
                setters.add(name)
        clocked_types |= clock_holders(text)
        for f in fns:
            bodies.append((path, f, text[f[3] : f[4] + 1]))
        for m in re.finditer(r"\bSystemClock\b", text):
            f = _innermost(fns, m.start())
            if f and f[1] not in setters:
                found[(crate_of(path), f[0], f[1])] = (f, path)
    clocked_types |= settable_types

    def made(f):
        outer = returned_type(f[6])
        return f[0] if outer == "Self" else outer

    def settable(f):
        return made(f) in settable_types

    # A constructor of a type whose clock a setter sets, handed no clock and
    # nothing that carries one, builds it on the default clock, whatever its
    # body calls to get there: the signature says so.
    for path, f, _ in bodies:
        owner, name, has_self, params = f[0], f[1], f[2], f[5]
        if has_self or name in setters or not settable(f):
            continue
        if re.search(r"\b[Cc]lock\b", params) or set(re.findall(r"\w+", params)) & clocked_types:
            continue
        found.setdefault((crate_of(path), owner, name), (f, path))

    # A function that hands out what a form built is a form too: it takes no
    # `self`, calls a type's form (from a library crate, or its own crate)
    # and returns that type or a clocked one (a builder of it), or calls a
    # free form of its own file and returns what it does, and the chain on
    # the call does not set the clock.
    changed = True
    while changed:
        changed = False
        for path, f, body in bodies:
            owner, name = f[0], f[1]
            key = (crate_of(path), owner, name)
            if key in found or name in setters or f[2]:
                continue
            for (crate, ftype, fname), (form, fpath) in list(found.items()):
                library = not crate.startswith("examples/")
                returned = set(re.findall(r"\w+", f[6]))
                if "Self" in returned and owner:
                    returned.add(owner)
                hands_out = (
                    ftype in returned
                    or (settable(f) and ftype == owner)
                    or made(f) in clocked_types
                )
                if ftype is not None and (library or crate == crate_of(path)) and hands_out:
                    call = r"\b" + ftype + r"\s*::\s*" + fname + r"\s*\("
                    if ftype == owner:
                        call += r"|\bSelf\s*::\s*" + fname + r"\s*\(|\bself\s*\.\s*" + fname + r"\s*\("
                elif (
                    ftype is None
                    and fpath == path
                    and (returned & set(re.findall(r"\w+", form[6])) or made(f) in clocked_types)
                ):
                    call = r"(?<![\w.:])(?<!fn )" + fname + r"\s*\("
                else:
                    continue
                hit = any(
                    not (settable(form) and _clock_set_in_chain(body, m.end() - 1, setters))
                    for m in re.finditer(call, body)
                )
                if hit:
                    found[key] = (f, path)
                    changed = True
                    break

    forms_found = {k: (f[2], path, settable(f)) for k, (f, path) in found.items()}
    return forms_found, setters


def _form_patterns(all_forms, test_path):
    """(regex, label, settable) for each form a test file can reach: a free
    function or a type's function of a library crate from any test, one of an
    example only from that example's own tests."""
    pats = []
    crate = crate_of(test_path)
    for (fcrate, ftype, fname), (has_self, _, settable) in all_forms.items():
        library = not fcrate.startswith("examples/")
        if ftype is None:
            if fcrate != crate and not library:
                continue
            pat = r"(?<![\w.])(?<!fn )" + fname + r"\s*\("
            label = fname
        elif has_self:
            if fcrate != crate:
                continue
            pat = r"\.\s*" + fname + r"\s*\("
            label = f"{ftype}::{fname}"
        else:
            if fcrate != crate and not library:
                continue
            pat = r"\b" + ftype + r"\s*(?:::\s*<[^;{}]*?>\s*)?::\s*" + fname + r"\s*\("
            label = f"{ftype}::{fname}"
        pats.append((re.compile(pat), label, settable))
    return pats


REFUSED = ("unwrap_err", "expect_err", "is_err", "err")


def _clock_set_in_chain(text, i, setters):
    """Whether the expression whose call opens at `text[i]` sets its clock,
    or builds nothing that could run on one.

    Reads on from the call's `(` to the end of the statement (a `;`, or a
    bracket that closes an enclosing one) and looks, at the call's own
    depth, for a clock setter (`.with_clock(`, or one inside the closure of a
    `.map(` on the `Result`), or for the error a refused
    construction returns (`.unwrap_err()`, `.is_err()`): a clock passed to
    an argument does not count. A construction bound by `let Err(e) =` is
    refused too.
    """
    start = max(text.rfind(";", 0, i), text.rfind("{", 0, i), text.rfind("}", 0, i)) + 1
    if re.search(r"\blet\s+Err\s*\(\s*\w+\s*\)\s*=", text[start:i]):
        return True
    depth = 0
    j = i
    while j < len(text):
        ch = text[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return False
        elif ch == ";" and depth == 0:
            return False
        elif depth == 0 and ch == ".":
            m = re.match(r"\.\s*(\w+)\s*\(", text[j : j + 64])
            if m and (m.group(1) in setters or m.group(1) in REFUSED):
                return True
            if m and m.group(1) in ("map", "and_then"):
                # `.map(|b| b.with_clock(..))` on the `Result` sets it too.
                arg = j + m.end() - 1
                inner = text[arg : _matching(text, arg, "(", ")")]
                if any(re.search(r"\.\s*" + name + r"\s*\(", inner) for name in setters):
                    return True
        j += 1
    return False


def world_test(path):
    """Whether a test file builds a world: an integration test, or an
    example's tests of its own application."""
    return integration_test(path) or path.split("/")[0] == "examples"


CLOCK_NAMED = re.compile(r"(?:\w+_)?clock$")


def _helper_call(owner, name, module=None, method=False):
    """The call of a test helper: `name(`, `module::name(` (from the crate
    root or from a sibling, `crate::module::name(` and `super::module::name(`
    too), `Owner::name(`, and for a method, `.name(` on a value."""
    if owner is not None:
        call = r"\b" + owner + r"\s*::\s*" + name + r"\s*\("
        return call + (r"|\.\s*" + name + r"\s*\(" if method else "")
    prefix = r"(?:(?:(?:crate|super)\s*::\s*)?" + module + r"\s*::\s*)?" if module else ""
    return r"(?<![\w.:])(?<!fn )" + prefix + name + r"\s*\("


def _from(pattern, owner, name, caller):
    """`pattern`, the call of helper `owner::name`, as `caller` may spell it:
    inside the helper's own `impl`, `Self::name(` too."""
    if owner is not None and caller[0] == owner:
        return pattern + r"|\bSelf\s*::\s*" + name + r"\s*\("
    return pattern


def _own_clocks(text, fns, f):
    """Where function `f` builds a clock itself, outside its nested functions."""
    nested = [g for g in fns if g is not f and f[3] < g[3] and g[4] <= f[4]]
    return [
        m.start() + f[3]
        for m in CLOCK_BUILT.finditer(text[f[3] : f[4] + 1])
        if not any(g[3] <= m.start() + f[3] <= g[4] for g in nested)
    ], nested


def _handed_clock(f):
    return re.search(r"\bclock\s*:|\bClock\b", f[5]) is not None


def clock_builders(text, outside=()):
    """The helpers of a test file (blanked code) that build a clock they were
    not handed: (owner, name, call pattern) for each function whose body
    builds one, or calls a helper that does (in the file, or one of
    `outside`, the builders of the modules it declares).

    A helper named for its clock (`test_clock`, `frozen_clock`) is counted
    where it is called already (`CLOCK_BUILT`), so it is not listed.
    """
    fns = functions(text)
    found = {}
    known = list(outside)
    changed = True
    while changed:
        changed = False
        for f in fns:
            key = (f[0], f[1])
            if key in found or _handed_clock(f):
                continue
            own, nested = _own_clocks(text, fns, f)
            body = text[f[3] : f[4] + 1]
            calls = any(re.search(_from(pat, o, n, f), body) for o, n, pat in known if (o, n) != key)
            if own or calls:
                pattern = _helper_call(f[0], f[1], method=f[2])
                found[key] = pattern
                known.append((f[0], f[1], pattern))
                changed = True
    return [(o, n, pat) for (o, n), pat in found.items() if not CLOCK_NAMED.match(n)]


def declared_modules(text):
    """The names of the modules a test file declares from other files (`mod common;`)."""
    return re.findall(r"\bmod\s+(\w+)\s*;", text)


def module_builders(module, text):
    """The clock builders of module `module` (blanked code), called from the file that declares it."""
    return [
        (o, n, pat if o is not None else _helper_call(o, n, module))
        for o, n, pat in clock_builders(text)
    ]


def test_findings(numbered, total, system_clock, path, outside=()):
    """(line, what) for each finding in test code given as (line number, code).

    Every test is held to `TEST_READ` and to the forms whose clock cannot
    be set, which read the system clock wherever they run. A world test
    (`world_test`) is also held to the forms whose clock a chain can set,
    and to one clock per function: a clock it builds, or one a helper it
    calls builds (`clock_builders`, with `outside` the builders of the
    modules it declares), past the first, or any when it was handed one.
    """
    out = []
    for no, code in numbered:
        m = TEST_READ.search(code)
        if m:
            out.append((no, m.group(0).strip()))
    world = world_test(path)
    text = full_text(numbered, total)
    starts = [0]
    for line in text.split("\n"):
        starts.append(starts[-1] + len(line) + 1)

    def line_of(pos):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    all_forms, setters = system_clock
    for pat, label, settable in _form_patterns(all_forms, path):
        if settable and not world:
            continue
        if "::" not in label and re.search(r"\bfn\s+" + label + r"\b", text):
            continue  # the test's own function of the same name
        for m in pat.finditer(text):
            if settable and _clock_set_in_chain(text, m.end() - 1, setters):
                continue
            how = "its clock is not set in the chain" if settable else "a system-clock form"
            out.append((line_of(m.start()), f"{label} ({how})"))
    if not world:
        return sorted(set(out))
    fns = functions(text)
    helpers = clock_builders(text, outside) + list(outside)
    for f in fns:
        own, nested = _own_clocks(text, fns, f)
        built = [(pos, "") for pos in own]
        for owner, name, pat in helpers:
            if (owner, name) == (f[0], f[1]):
                continue
            for m in re.finditer(_from(pat, owner, name, f), text[f[3] : f[4] + 1]):
                pos = m.start() + f[3]
                if not any(g[3] <= pos <= g[4] for g in nested):
                    built.append((pos, f", built by {name}"))
        built.sort()
        # A function handed a clock already has its world's one.
        for pos, by in built if _handed_clock(f) else built[1:]:
            out.append((line_of(pos), f"a second clock in fn {f[1]}{by}"))
    return sorted(set(out))
