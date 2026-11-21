#!/usr/bin/env bash
# axess: every live Valkey test holds a sweep.
#
# The live Valkey servers are shared by every run on a host and by CI's
# jobs. A test that writes to one removes what it wrote through a sweep
# (axess_core::testing::valkey_sweep): a prefix that holds the run's token,
# whose keys are removed when the test ends, also when it fails. After a
# run, scripts/live-keys-left.sh asks the servers for any key that still
# holds the token. A key written outside every sweep holds no token, and
# that check cannot see it; this rule, which needs no server, is what keeps
# a test from writing one.
#
# It refuses, by file and line, a live Valkey test whose body calls no
# sweep source. A live Valkey test is a function whose ignore reason names
# Valkey; a sweep source is a function or method that returns a `KeySweep`,
# a `Swept` or a type that holds one, or a function that takes a closure
# and calls one while it runs. scripts/lib/live_sweeps.py says how a call
# is resolved and why the rule fails closed: a call it cannot place is not
# a sweep. It also refuses an ignore attribute naming Valkey that it
# cannot place on a function.
#
# What it does not see is whether every key a test that holds a sweep
# writes holds the sweep's prefix: a key's name is a value built at run
# time, which no text rule follows.
#
# scripts/live-sweep-exemptions.txt names the live tests that hold no
# sweep on purpose (a test that writes no key), each under a comment that
# gives its reason. An entry with no reason, an entry for a test that is
# not there or is not a live Valkey test, and an entry for a test that
# holds a sweep after all are refused, so the list says why each entry
# exists and holds none that outlived its test. It refuses to report clean
# when it read no live Valkey test.
#
# Usage: ./scripts/check-live-sweeps.sh [--root DIR]
#   --root DIR  check the Rust files under DIR, and
#               DIR/scripts/live-sweep-exemptions.txt, instead of the
#               files git lists in this repository
#               (scripts/check-live-sweeps-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$2"
  files() { find . -name '*.rs' -type f | sed 's|^\./||' | sort; }
else
  [ $# -eq 0 ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not
  # yet added is checked as well.
  files() { git ls-files --cached --others --exclude-standard --deduplicate '*.rs'; }
fi

listed="$(files)"
python3 -I -B -c '
import os, sys

sys.path.insert(0, sys.argv[1])
from live_sweeps import Rule, Source, read_exemptions

EXEMPTIONS = "scripts/live-sweep-exemptions.txt"
exempt, errors = read_exemptions(EXEMPTIONS)
paths = [p for p in sys.stdin.read().split("\n") if p and os.path.isfile(p)]
sources = []
for path in paths:
    with open(path, encoding="utf-8") as f:
        sources.append(Source(path, f.read()))
rule = Rule(sources)

refused = []
seen = live = held = 0
used = set()
tests = set()
for source in sources:
    for line, name, body in source.live_tests():
        seen += 1
        if name is None:
            refused.append(f"{source.path}:{line}: an ignore reason that names Valkey on no function this check can read")
            continue
        live += 1
        tests.add((source.path, name))
        if rule.holds(source.path, body):
            held += 1
            if (source.path, name) in exempt:
                errors.append(f"{EXEMPTIONS}:{exempt[(source.path, name)]}: {source.path} {name} holds a sweep; remove the entry")
            continue
        if (source.path, name) in exempt:
            used.add((source.path, name))
            continue
        refused.append(
            f"{source.path}:{line}: {name} is a live Valkey test that holds no sweep; "
            "write its keys under a KeySweep, or through a helper that returns a Swept"
        )
for key, no in sorted(exempt.items(), key=lambda kv: kv[1]):
    if key not in tests:
        errors.append(f"{EXEMPTIONS}:{no}: {key[0]} {key[1]} is not a live Valkey test; remove the entry")
if seen == 0:
    print("ERROR: no live Valkey test read; nothing was checked.", file=sys.stderr)
    sys.exit(1)
for line in errors + refused:
    print(line, file=sys.stderr)
if errors or refused:
    print(
        f"{len(refused)} live test(s) refused, {len(errors)} error(s) in the exemption list; "
        "see the header of scripts/check-live-sweeps.sh.",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"ok: {held} of {live} live Valkey test(s) hold a sweep, {len(used)} exempted with a reason")
' "$LIB" <<<"$listed"
