#!/usr/bin/env bash
# axess: production code reads the wall clock only through axess-clock.
#
# All non-determinism is injectable (AGENTS.md): production code takes a
# `Clock`, and a test substitutes `MockClock`. A bare `Utc::now()` or
# `Local::now()` in production code is a read of the wall clock no test can
# move, which is how a time-dependent bug escapes deterministic simulation.
#
# This scans each crate's `src/` outside `axess-clock`, ignoring comments and
# doc comments, `#[cfg(test)]` items, and files that are only compiled for
# tests (`tests.rs`, `*_tests.rs`, anything under `tests/` or `testing/`).
# What remains must be listed in `scripts/clock-usage-baseline.txt`, one
# `path:count` per line, written down when the gate was added. A new offender
# fails; a listed file that grew fails; a file that shrank or went clean is
# reported so the baseline only goes down (run with `--bless` to rewrite it).
#
# Usage: ./scripts/check-clock-usage.sh [--bless]

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

BASELINE="scripts/clock-usage-baseline.txt"
MODE="check"
[ "${1:-}" = "--bless" ] && MODE="bless"

git ls-files '*.rs' | python3 -I -c '
import re, sys

mode, baseline_path = sys.argv[1], sys.argv[2]
CALL = re.compile(r"\b(?:Utc|Local)::now\s*\(")

def exempt(path):
    parts = path.split("/")
    if parts[0] in ("axess-clock", "examples", "fuzz"):
        return True
    if "src" not in parts:
        return True
    name = parts[-1]
    if name in ("tests.rs", "testing.rs") or name.endswith("_tests.rs"):
        return True
    return any(p in ("tests", "testing", "benches") for p in parts)

def production_lines(text):
    """Lines outside comments and outside #[cfg(test)] items, with literals blanked."""
    lines = text.split("\n")
    skip_until_depth = None
    depth = 0
    pending_cfg_test = False
    out = []
    for no, raw in enumerate(lines, 1):
        line = re.sub(r"\"(?:[^\"\\\\]|\\\\.)*\"", "\"\"", raw)
        code = line.split("//")[0]
        stripped = code.strip()
        if skip_until_depth is None:
            if re.match(r"#\[cfg\((?:test|all\(test.*)\)\]", stripped):
                pending_cfg_test = True
                continue
            if pending_cfg_test:
                if stripped.startswith("#["):
                    continue
                pending_cfg_test = False
                opens = code.count("{") - code.count("}")
                if opens > 0:
                    skip_until_depth = depth
                    depth += opens
                continue
            depth += code.count("{") - code.count("}")
            if raw.lstrip().startswith("//"):
                continue
            out.append((no, code))
        else:
            depth += code.count("{") - code.count("}")
            if depth <= skip_until_depth:
                skip_until_depth = None
    return out

found = {}
for path in sys.stdin.read().split():
    if exempt(path):
        continue
    with open(path, encoding="utf-8") as f:
        text = f.read()
    hits = [no for no, code in production_lines(text) if CALL.search(code)]
    if hits:
        found[path] = hits

if mode == "bless":
    with open(baseline_path, "w") as f:
        for path in sorted(found):
            f.write(f"{path}:{len(found[path])}\n")
    print(f"blessed {len(found)} file(s) into {baseline_path}")
    sys.exit(0)

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
        lines = ", ".join(str(n) for n in hits)
        print(f"{path}: {len(hits)} wall-clock read(s) (allowed {allowed}), at line(s) {lines}", file=sys.stderr)
for path, allowed in sorted(baseline.items()):
    if len(found.get(path, [])) < allowed:
        print(f"note: {path} now has {len(found.get(path, []))} (baseline {allowed}); run --bless", file=sys.stderr)
if failed:
    print("Use the injected Clock (axess_clock::Clock) instead of Utc::now()/Local::now().", file=sys.stderr)
    sys.exit(1)
print(f"ok: scanned production code; {sum(len(h) for h in found.values())} baselined wall-clock read(s) in {len(found)} file(s)")
' "$MODE" "$BASELINE"
