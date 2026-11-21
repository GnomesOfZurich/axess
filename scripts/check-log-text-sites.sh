#!/usr/bin/env bash
# axess: no new raw log field for text a caller, a tenant or a remote party
# chose.
#
# Such text reaches a log line through the one predicate
# (`axess_identity::log_text::log_safe`) or a helper built on it, so a line
# break cannot forge a line and a bidirectional or zero-width character
# cannot make one read otherwise than it is. This census finds every tracing
# field of production code written `name = %expr`, `name = ?expr`, `%name`
# or `?name` whose name is one of NAMES below and whose expression does not
# start with a call to one of HELPERS, and compares that set of raw sites
# with the recorded census, scripts/log-text-sites-census.txt, where each
# raw site that stays raw stands with its reason. A raw site the census does
# not hold fails, and so does a census entry no site answers to any more,
# both by name: a new site is either routed through a helper or recorded
# with its reason in the same commit.
#
# How the set is keyed, and its limit. The field's name is what the log
# reader sees the value as, and NAMES lists every name under which this
# workspace logs an identifier, a name, an issuer, a subject or another text
# a party outside the process may have chosen. Rust's types are not visible
# to a source scan, so the gate cannot ask whether the value is a validated
# newtype; a census of every Display field (some 550, most of them error
# values) would hold far more than this question needs. The cost of keying
# on names is a field that carries such text under a name not in NAMES: a
# reviewer adding one adds its name here. A typed value logged under a
# listed name (a TenantId as `tenant`) is recorded with its reason rather
# than inferred, so a later change of its type is a census change someone
# reads.
#
# A site is its file, its field name, its sigil and its expression with the
# white space folded: line numbers move with every edit and say nothing
# about the site. Two identical fields in one file are one entry with a
# count, so a third added beside them fails too.
#
# Test code (`tests/`, `testing/`, `tests.rs`, `*_tests.rs`, a
# `#[cfg(test)]` item), the examples, the fuzz targets, the fixture crate
# `axess-testing`, comments and string literals are not read
# (scripts/lib/rust_source.py).
#
# Usage: ./scripts/check-log-text-sites.sh [--root DIR] [--census FILE]
#   --root DIR     check the Rust files under DIR instead of this
#                  repository's files (scripts/check-log-text-sites-tests.sh)
#   --census FILE  compare with FILE instead of the recorded census

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"
CENSUS="$AXESS_DIR/scripts/log-text-sites-census.txt"
ROOT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR] [--census FILE]" >&2; exit 2; }; ROOT="$2"; shift 2 ;;
    --census) [ -f "${2:-}" ] || { echo "usage: $0 [--root DIR] [--census FILE]" >&2; exit 2; }; CENSUS="$2"; shift 2 ;;
    *) echo "usage: $0 [--root DIR] [--census FILE]" >&2; exit 2 ;;
  esac
done

if [ -n "$ROOT" ]; then
  cd "$ROOT"
  files() { find . -name '*.rs' -type f | sed 's|^\./||' | sort; }
else
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not
  # yet added is checked as well.
  files() { git ls-files --cached --others --exclude-standard --deduplicate '*.rs'; }
fi

listed="$(files)"
python3 -I -B -c '
import re, sys
from collections import Counter

sys.path.insert(0, sys.argv[1])
from rust_source import exempt, production_lines

census_path = sys.argv[2]
ROOTS = ("examples", "fuzz", "axess-testing")
NAMES = (
    "identifier", "name", "subject", "sub", "issuer", "iss", "username", "email",
    "client_id", "slug", "provider", "provider_name", "kid", "jti", "typ",
    "audience", "aud", "spiffe_id", "workload_id", "trust_domain", "tenant",
    "realm", "domain", "host", "label", "redirect_uri", "scope", "presented",
    "expected", "value", "method", "path", "uri", "url", "sid", "oidc_sid",
    "evicted_iss", "evicted_oidc_sid", "action", "principal", "resource",
    "reason", "error_code", "route",
)
HELPERS = (
    "log_safe", "logged_request_text", "logged_provider_name", "loggable",
    "echo_jti", "echo_kid",
)
NAME = "(?:" + "|".join(NAMES) + ")"
ASSIGNED = re.compile(r"(?<![A-Za-z0-9_.])(" + NAME + r")\s*=\s*([%?])\s*(.*)")
SHORTHAND = re.compile(r"(?:^|[,(])\s*([%?])(" + NAME + r")\s*(?=[,)]|$)")
THROUGH = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*::)*(?:" + "|".join(HELPERS) + r")\(")


def expression(rest):
    """The field expression at the start of `rest`: up to a comma or a
    closing bracket at its own depth, or the end of the line."""
    depth = 0
    for i, c in enumerate(rest):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return rest[:i]
            depth -= 1
        elif c == "," and depth == 0:
            return rest[:i]
    return rest


def fold(text):
    return " ".join(text.split())


found = Counter()
for path in sys.stdin.read().split():
    if exempt(path, ROOTS):
        continue
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for no, code in production_lines(text):
        for m in ASSIGNED.finditer(code):
            expr = fold(expression(m.group(3)))
            if not THROUGH.match(expr):
                found[(path, m.group(1), m.group(2) + expr)] += 1
        for m in SHORTHAND.finditer(code):
            found[(path, m.group(2), m.group(1) + m.group(2))] += 1

recorded = Counter()
reasons = {}
with open(census_path, encoding="utf-8") as f:
    for no, line in enumerate(f, 1):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 5 or not parts[0].isdigit():
            print(f"{census_path}:{no}: want COUNT<TAB>REASON<TAB>PATH<TAB>NAME<TAB>EXPRESSION", file=sys.stderr)
            sys.exit(2)
        count, reason, path, name, expr = parts
        if not reason.strip():
            print(f"{census_path}:{no}: an entry needs its reason", file=sys.stderr)
            sys.exit(2)
        recorded[(path, name, expr)] += int(count)
        reasons[(path, name, expr)] = reason

bad = []
for site, n in sorted(found.items()):
    if n > recorded.get(site, 0):
        path, name, expr = site
        bad.append(f"raw log field not in the census: {path}: {name} = {expr} ({n} found, {recorded.get(site, 0)} recorded)")
for site, n in sorted(recorded.items()):
    if found.get(site, 0) < n:
        path, name, expr = site
        bad.append(f"census entry with no site: {path}: {name} = {expr} ({n} recorded, {found.get(site, 0)} found)")
if bad:
    for line in bad:
        print(line, file=sys.stderr)
    print("Route the field through log_safe or a helper on it, or record it with its reason in scripts/log-text-sites-census.txt.", file=sys.stderr)
    sys.exit(1)
total = sum(recorded.values())
print(f"ok: every raw log field of caller text is one of the {total} the census records with its reason")
' "$LIB" "$CENSUS" <<<"$listed"
