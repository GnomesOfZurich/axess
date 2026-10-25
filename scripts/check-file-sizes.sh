#!/usr/bin/env bash
# axess: keep production files and functions from growing past a readable size.
#
# Two limits, both measured on PRODUCTION code only:
#   - a file over FILE_MAX_LINES (800) lines, and
#   - a function over FN_MAX_LINES (150) lines.
#
# What is measured
#   - Tracked `.rs` files, so build output under target/ cannot contribute.
#   - Test code is not production: `tests.rs`, anything under `tests/`,
#     `benches/`, `examples/`, `testing/`, `fuzz/`, and every file that is only
#     reached through a `#[cfg(test)] mod name;` declaration (with the files
#     below it) is skipped. An inline `#[cfg(test)] mod name { ... }` block is
#     cut out before counting, for the file length and for any function in it.
#   - A file's length is its line count minus those inline test blocks.
#   - A function's length runs from its `fn` line to its closing brace, so
#     attributes and doc comments above it do not count. Functions are found by
#     indentation, which holds because the tree is rustfmt-formatted.
#
# The ratchet
#   `scripts/file-size-baseline.txt` lists today's offenders with their size.
#   An offender not in the baseline fails the gate; a baselined offender that
#   grew past its recorded size fails it; one that shrank passes and is
#   reported so the baseline can be lowered with `--bless`.
#
# Usage
#   ./scripts/check-file-sizes.sh           check the tree against the baseline
#   ./scripts/check-file-sizes.sh --bless   regenerate the baseline from the
#                                           same counting the check uses
#   FILE_MAX_LINES=N / FN_MAX_LINES=N       override the limits (the baseline
#                                           is then not comparable; used to
#                                           prove the gate can fail)
#
# The gate prints how many files and functions it measured and refuses to
# report clean when it measured none.

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

MODE=check
case "${1:-}" in
  "") ;;
  --bless) MODE=bless ;;
  *) echo "usage: $0 [--bless]" >&2; exit 2 ;;
esac

FILE_MAX_LINES="${FILE_MAX_LINES:-800}"
FN_MAX_LINES="${FN_MAX_LINES:-150}"
BASELINE="scripts/file-size-baseline.txt"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required by $0" >&2
  exit 1
fi

FILE_LIST="$(git ls-files '*.rs')"
if [ -z "$FILE_LIST" ]; then
  echo "ERROR: git ls-files matched no Rust files: the selection is broken, not the tree." >&2
  exit 1
fi
if printf '%s\n' "$FILE_LIST" | grep -q '[[:space:]]'; then
  echo "ERROR: a tracked .rs path contains whitespace; this script cannot scan it." >&2
  exit 1
fi

printf '%s\n' "$FILE_LIST" | python3 -I -c '
import os, re, sys

mode, baseline_path, file_max, fn_max = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
paths = [l for l in sys.stdin.read().split("\n") if l]

EXEMPT_DIRS = ("tests", "benches", "examples", "testing", "fuzz")
CFG_TEST = re.compile(r"^\s*#\[cfg\((?:all\()?test\b")
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;")
INLINE_MOD = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z0-9_]+\s*\{\s*$")
FN_START = re.compile(r"^(\s*)(?:(?:pub(?:\([^)]*\))?|const|async|unsafe|extern\s+\"[^\"]*\")\s+)*fn\s+([A-Za-z0-9_]+)")

def lines_of(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read().split("\n")

def exempt_by_path(p):
    parts = p.split("/")
    if parts[-1] == "tests.rs":
        return True
    return any(d in parts[:-1] for d in EXEMPT_DIRS)

def declared_test_siblings(p, lines):
    # Files reached through `#[cfg(test)] mod name;` from this file.
    base = os.path.basename(p)
    d = os.path.dirname(p)
    child_dir = d if base in ("lib.rs", "main.rs", "mod.rs") else os.path.join(d, base[:-3])
    out = []
    for i, l in enumerate(lines):
        if CFG_TEST.match(l):
            for j in range(i + 1, min(i + 4, len(lines))):
                m = MOD_DECL.match(lines[j])
                if m:
                    out.append(os.path.join(child_dir, m.group(1) + ".rs"))
                    out.append(os.path.join(child_dir, m.group(1), "mod.rs"))
                    break
                if lines[j].strip() and not lines[j].lstrip().startswith("#["):
                    break
    return out

contents = {p: lines_of(p) for p in paths}
test_files = set()
for p in paths:
    for c in declared_test_siblings(p, contents[p]):
        test_files.add(c)
# Everything below a test file directory is test code too.
changed = True
while changed:
    changed = False
    for p in paths:
        if p in test_files:
            for c in declared_test_siblings(p, contents[p]):
                if c not in test_files:
                    test_files.add(c); changed = True

def production_lines(lines):
    # Blank out inline `#[cfg(test)] mod x { ... }` blocks; returns the kept lines.
    keep = [True] * len(lines)
    i = 0
    while i < len(lines):
        if CFG_TEST.match(lines[i]):
            j = i + 1
            while j < len(lines) and lines[j].lstrip().startswith("#["):
                j += 1
            if j < len(lines):
                m = INLINE_MOD.match(lines[j])
                if m:
                    indent = m.group(1)
                    k = j + 1
                    while k < len(lines) and lines[k] != indent + "}":
                        k += 1
                    for x in range(i, min(k, len(lines) - 1) + 1):
                        keep[x] = False
                    i = k + 1
                    continue
        i += 1
    return [l for l, k in zip(lines, keep) if k]

def fn_lengths(lines):
    out = []
    seen = {}
    i = 0
    n = len(lines)
    while i < n:
        m = FN_START.match(lines[i])
        if not m:
            i += 1
            continue
        indent, name = m.group(1), m.group(2)
        j = i
        body = None
        while j < n:
            s = lines[j].rstrip()
            if j == i and s.endswith("}") and "{" in s:
                body = j
                break
            if s.endswith(";") and not s.endswith("{"):
                break
            if s.endswith("{"):
                body = j
                break
            j += 1
        if body is None:
            i += 1
            continue
        end = body
        if not (lines[body].rstrip().endswith("}") and "{" in lines[body] and body == i):
            end = body + 1
            while end < n and lines[end] != indent + "}":
                end += 1
        seen[name] = seen.get(name, 0) + 1
        key = name if seen[name] == 1 else "%s#%d" % (name, seen[name])
        out.append((key, end - i + 1))
        i += 1
    return out

files_measured = 0
fns_measured = 0
found = {}   # key -> size
for p in paths:
    if exempt_by_path(p) or p in test_files:
        continue
    lines = production_lines(contents[p])
    files_measured += 1
    size = len(lines) - (1 if lines and lines[-1] == "" else 0)
    if size > file_max:
        found[("file", p, "")] = size
    for key, ln in fn_lengths(lines):
        fns_measured += 1
        if ln > fn_max:
            found[("fn", p, key)] = ln

print("check-file-sizes: measured %d production files and %d functions (limits: %d lines per file, %d per function)"
      % (files_measured, fns_measured, file_max, fn_max))
if files_measured == 0 or fns_measured == 0:
    print("ERROR: measured nothing (files=%d, fns=%d). The selection or the matcher is broken, not the tree;"
          % (files_measured, fns_measured), file=sys.stderr)
    print("       a pass here would be meaningless.", file=sys.stderr)
    sys.exit(1)

HEADER = """# axess file-size baseline: written by `scripts/check-file-sizes.sh --bless`, not by hand.
# Production files over %d lines and production functions over %d lines that
# already existed when the gate was introduced. The gate fails on any offender
# not listed here and on any listed offender that grew; shrink them and
# re-bless so the numbers only go down.
# format: kind<TAB>lines<TAB>path<TAB>function (functions only)
""" % (file_max, fn_max)

def render(found):
    rows = []
    for (kind, p, key), v in sorted(found.items()):
        rows.append("\t".join([kind, str(v), p] + ([key] if kind == "fn" else [])))
    return "\n".join(rows) + ("\n" if rows else "")

if mode == "bless":
    with open(baseline_path, "w") as f:
        f.write(HEADER + render(found))
    nf = sum(1 for k in found if k[0] == "file")
    print("blessed %s: %d files and %d functions over the limits (population: %d files, %d functions)"
          % (baseline_path, nf, len(found) - nf, files_measured, fns_measured))
    sys.exit(0)

if not os.path.exists(baseline_path):
    print("ERROR: %s is missing; create it with --bless." % baseline_path, file=sys.stderr)
    sys.exit(1)
base = {}
for l in open(baseline_path).read().split("\n"):
    if not l or l.startswith("#"):
        continue
    f = l.split("\t")
    if f[0] == "file" and len(f) == 3:
        base[("file", f[2], "")] = int(f[1])
    elif f[0] == "fn" and len(f) == 4:
        base[("fn", f[2], f[3])] = int(f[1])
    else:
        print("ERROR: unparseable baseline row: %r" % l, file=sys.stderr)
        sys.exit(1)

bad, shrunk = [], []
for k, v in sorted(found.items()):
    what = "%s %s%s" % (k[0], k[1], ("::" + k[2]) if k[2] else "")
    limit = file_max if k[0] == "file" else fn_max
    if k not in base:
        bad.append("  %5d lines  %s (limit %d, not in the baseline)" % (v, what, limit))
    elif v > base[k]:
        bad.append("  %5d lines  %s (grew from %d)" % (v, what, base[k]))
    elif v < base[k]:
        shrunk.append("  %s: %d -> %d" % (what, base[k], v))
gone = [k for k in base if k not in found]

if bad:
    print("ERROR: %d size violation(s):" % len(bad), file=sys.stderr)
    print("\n".join(bad), file=sys.stderr)
    print("", file=sys.stderr)
    print("Split the file or function (moves keep public paths via `pub use`), do not raise the baseline.", file=sys.stderr)
    sys.exit(1)
if shrunk or gone:
    print("note: the baseline can be lowered with --bless (%d shrunk, %d under the limit):" % (len(shrunk), len(gone)))
    print("\n".join(shrunk + ["  %s %s%s: under the limit" % (k[0], k[1], ("::" + k[2]) if k[2] else "") for k in gone]))
print("OK: no new offenders; %d baselined (%d files, %d functions)."
      % (len(found), sum(1 for k in found if k[0] == "file"), sum(1 for k in found if k[0] == "fn")))
' "$MODE" "$BASELINE" "$FILE_MAX_LINES" "$FN_MAX_LINES"
