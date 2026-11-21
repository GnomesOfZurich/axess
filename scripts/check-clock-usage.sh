#!/usr/bin/env bash
# axess: library code reads the clock only through axess-clock, and a test
# reads no clock but its world's.
#
# All non-determinism is injectable (AGENTS.md): library code takes a
# `Clock`, and a test substitutes `MockClock`. A bare `Utc::now()` in library
# code is a read of the wall clock no test can move, which is how a
# time-dependent bug escapes deterministic simulation. The same name passed
# as a function (`unwrap_or_else(Utc::now)`), reached through a re-export
# (`chrono::offset::Utc::now`) or renamed (`Instant as Stopwatch`) is the
# same read, and so are `SystemTime::now`, the time crate's
# `UtcDateTime::now` and `now_utc` and its reads of the local offset
# (`current_local_offset`, `local_offset_at`), jiff's `Timestamp::now` and
# `Zoned::now` and its reads of the host's time zone (`TimeZone::system`,
# `TimeZone::try_system`), and `UNIX_EPOCH.elapsed()`; std's `Instant::now` is a monotonic read no test
# can move either. tokio's `Instant::now`, spelled in full, is the clock a
# paused runtime moves, and library code may read it.
#
# Library code is each crate's `src/`, the `testing` fixtures adopters' tests
# use included, minus its test code; what remains after comments, literals
# and test code are taken out must be listed in
# `scripts/clock-usage-baseline.txt`, one `path:count` per line: the reads
# the gate found when it first ran, which may only shrink.
#
# `axess-clock` holds the clock, and its library code is held to the same
# rule with one read admitted: `SystemTime::now` in the body of
# `SystemClock`'s `now`, the read every other crate reaches through
# `Clock::now`. A second read there, and a read anywhere else in the crate
# (`MockClock::now` starts at `SystemClock`'s reading), is a finding. Its own
# tests drive `SystemClock` and `MockClock::now` by name and are not scanned.
# The crate also gives its mock a second public name, `DeterministicClock`:
# that one declaration is no finding, because every rule here knows the name
# as it knows `MockClock`, so a read through it is seen. Any other renaming
# of a clock, there or elsewhere, still is one.
#
# Test code is every crate's integration tests (`tests/`, the examples'
# included), the test modules and files inside `src/` (an example's too),
# every `#[cfg(test)]` item, and the code of doc examples, which `cargo test`
# runs. There `tokio::time::Instant::now`, `MockClock::now` (a mock started
# at the real time) and `SystemClock` count too, as does a call to a function
# that runs on the system clock with no way to set another (a "system-clock
# form": `factor_secret_cipher()`, `make_password_service`), since its
# clocked sibling exists. A test that times real work (a password hash, a
# slow identity provider) reads `axess_testing::stopwatch::Stopwatch`. A doc
# example teaches what an adopter copies into production, so it is held to
# the library rule and may name `SystemClock`.
#
# A test that builds a world (an integration test, or an example's tests of
# its own application) builds every part on the world's clock: a service,
# store, cipher, layer or provider that would run on the system clock unless
# a chain sets another (`MockIdentityStore::new()`) counts unless its chain
# sets one (`.with_clock(...)`) or the construction is refused (`let
# Err(e) =`, `.unwrap_err()`), and a function counts each clock it builds
# past its first, or every one when it was handed a clock already. A call
# of a helper of the test (in its file, or in a module it declares from
# another file, `mod common;`) that builds a clock it was not handed counts
# as a clock built where it is called, so a world whose parts come from
# helpers with clocks of their own has more than one. Unit tests
# inside `src/` drive one part with the times they state, so they are held
# to the reads and to the forms no chain can clock, not to the chains.
#
# The forms are found in library and example code (scripts/lib/
# clock_usage.py): a function that names `SystemClock`; a constructor of a
# type a setter clocks whose signature takes no clock and nothing that holds
# one, so it falls back to the default whatever its body calls; or a
# function that hands out what one of those built, or a value holding a
# clock built from it, without setting its clock. These are text rules over code
# with comments and literals blanked (scripts/lib/rust_source.py): they see
# names, not types, so `Default::default()` for a clocked type, or the
# `.elapsed()` of a `SystemTime` value held in a variable, is not seen.
# Test findings are counted against `scripts/clock-usage-tests-baseline.txt`,
# which is empty. A new finding fails; a listed file that grew fails; a file
# that shrank or went clean is reported so a baseline only goes down (run
# with `--bless` to rewrite them).
#
# Usage: ./scripts/check-clock-usage.sh [--bless] [--root DIR]
#   --root DIR  scan the Rust files under DIR, with DIR's own baselines
#               (scripts/check-clock-usage-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

MODE="check"
ROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --bless) MODE="bless"; shift ;;
    --root) ROOT="${2:-}"; shift 2 ;;
    *) echo "usage: $0 [--bless] [--root DIR]" >&2; exit 2 ;;
  esac
done

if [ -n "$ROOT" ]; then
  [ -d "$ROOT" ] || { echo "usage: $0 [--bless] [--root DIR]" >&2; exit 2; }
  cd "$ROOT"
  files() { find . -name '*.rs' -type f | sed 's|^\./||' | sort; }
else
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not
  # yet added is checked as well.
  files() { git ls-files --cached --others --exclude-standard --deduplicate '*.rs'; }
fi
BASELINE="scripts/clock-usage-baseline.txt"
TESTS_BASELINE="scripts/clock-usage-tests-baseline.txt"

listed="$(files)"
python3 -I -B -c '
import sys

sys.path.insert(0, sys.argv[1])
from rust_source import code_lines, production_lines
from clock_usage import (
    LIBRARY_READ,
    clock_crate_reads,
    declared_modules,
    doc_example_lines,
    forms,
    full_text,
    module_builders,
    scope,
    test_findings,
    world_test,
)

mode, baseline_path, tests_baseline_path = sys.argv[2], sys.argv[3], sys.argv[4]

texts, library = {}, {}
for path in sys.stdin.read().split():
    kind = scope(path)
    if kind is None:
        continue
    with open(path, encoding="utf-8") as f:
        text = f.read()
    texts[path] = (kind, text)
    if kind in ("library", "example"):
        library[path] = full_text(production_lines(text), text.count("\n") + 1)
system_clock_forms = forms(library)


def outside(path, test_code, total):
    """The clock builders of the modules a world test declares from other
    files. A test binary kept as a directory declares its modules in
    `main.rs`, and each is a sibling of the others: a file of such a binary
    is read with the modules `main.rs` declares, itself left out."""
    if not world_test(path):
        return []
    out = []
    folder = path.rsplit("/", 1)[0]
    declared = declared_modules(full_text(test_code, total))
    main = f"{folder}/main.rs"
    if main in texts and path != main:
        main_text = texts[main][1]
        declared += [
            module
            for module in declared_modules(full_text(code_lines(main_text), main_text.count("\n") + 1))
            if path not in (f"{folder}/{module}.rs", f"{folder}/{module}/mod.rs")
        ]
    for module in declared:
        for candidate in (f"{folder}/{module}/mod.rs", f"{folder}/{module}.rs"):
            if candidate in texts:
                text = texts[candidate][1]
                out += module_builders(module, full_text(code_lines(text), text.count("\n") + 1))
                break
    return out


def reads(numbered):
    return [(no, m.group(0).strip()) for no, code in numbered if (m := LIBRARY_READ.search(code))]


found, tests_found = {}, {}
for path, (kind, text) in texts.items():
    total = text.count("\n") + 1
    if kind == "test":
        test_code = code_lines(text)
    else:
        production = production_lines(text)
        kept = {no for no, _ in production}
        test_code = [(no, code) for no, code in code_lines(text) if no not in kept]
        if kind == "library" and (hits := reads(production)):
            found[path] = hits
        if kind == "clock" and (hits := clock_crate_reads(production, total)):
            found[path] = hits
    if kind == "clock":
        # The crate tests its own clocks by name, so its test code is not
        # held to the test rule; its doc examples are read like any other.
        hits = reads(doc_example_lines(text))
    else:
        hits = test_findings(test_code, total, system_clock_forms, path, outside(path, test_code, total))
        hits += reads(doc_example_lines(text))
    if hits:
        tests_found[path] = sorted(set(hits))


def bless(found, baseline_path):
    with open(baseline_path, "w") as f:
        for path in sorted(found):
            f.write(f"{path}:{len(found[path])}\n")
    print(f"blessed {len(found)} file(s) into {baseline_path}")


def check(found, baseline_path):
    baseline = {}
    try:
        with open(baseline_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    path, _, count = line.rpartition(":")
                    baseline[path] = int(count)
    except FileNotFoundError:
        pass
    failed = False
    for path, hits in sorted(found.items()):
        allowed = baseline.get(path, 0)
        if len(hits) > allowed:
            failed = True
            where = ", ".join(f"{no} ({what})" for no, what in hits)
            print(f"{path}: {len(hits)} clock finding(s) (allowed {allowed}), at line(s) {where}", file=sys.stderr)
    for path, allowed in sorted(baseline.items()):
        if len(found.get(path, [])) < allowed:
            print(f"note: {path} now has {len(found.get(path, []))} (baseline {allowed}); run --bless", file=sys.stderr)
    return failed


if mode == "bless":
    bless(found, baseline_path)
    bless(tests_found, tests_baseline_path)
    sys.exit(0)

failed = check(found, baseline_path)
tests_failed = check(tests_found, tests_baseline_path)
if failed:
    print("Use the injected Clock (axess_clock::Clock) instead of Utc::now, Local::now or SystemTime::now, and tokio::time::Instant::now, spelled in full, instead of the Instant::now of std.", file=sys.stderr)
if tests_failed:
    print("In a test, build the world on one MockClock set by MockClock::at_reference, build every service, store and fixture on it (with_clock, or the clocked form of a helper), read the time from it, and time real work with axess_testing::stopwatch::Stopwatch.", file=sys.stderr)
if failed or tests_failed:
    sys.exit(1)
reads_n = sum(len(h) for h in found.values()) + sum(len(h) for h in tests_found.values())
print(f"ok: scanned library code and test code; {reads_n} baselined clock finding(s) in {len(found) + len(tests_found)} file(s)")
' "$LIB" "$MODE" "$BASELINE" "$TESTS_BASELINE" <<<"$listed"
