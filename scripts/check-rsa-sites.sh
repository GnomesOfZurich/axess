#!/usr/bin/env bash
# axess: no new `rsa::` call site in production code.
#
# The `rsa` crate's 0.9 line carries RUSTSEC-2023-0071 (a timing side channel
# on RSA private-key operations, fixed in 0.10.0, which jsonwebtoken and
# openidconnect do not accept yet), which `deny.toml` ignores for the whole
# workspace because cargo-deny cannot scope an ignore to a feature or a file. The ignore is sound only while the crate
# is named where it was reviewed: the one module, compiled with
# `local-idp-rsa` alone, that generates and parses the local IdP's RSA keys
# and bridges the random-number traits key generation asks for. None of that
# is a private-key operation. Signing itself goes through `jsonwebtoken`'s
# backend.
#
# This fails when any other production file under a crate's `src/` names
# `rsa::` or `use rsa`. Test code (`tests/`, `testing/`, `tests.rs`,
# `*_tests.rs`), the fixture crate `axess-testing`, doc comments and the one
# item a `#[cfg(test)]` attribute covers (the block it opens, or the single
# item after it) are exempt; the lines after that item are production code
# again (scripts/lib/rust_source.py). Adding a site to ALLOWED is a claim
# that its use of `rsa` was reviewed against the advisory: say why in the
# commit.
#
# Usage: ./scripts/check-rsa-sites.sh [--root DIR]
#   --root DIR  check the Rust files under DIR instead of this repository's
#               files (scripts/check-rsa-sites-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

ALLOWED=(
  "axess-core/src/local_idp/primitives/rsa_key.rs"
)

if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$2"
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

sys.path.insert(0, sys.argv[1])
from rust_source import exempt, production_lines

allowed = set(sys.argv[2:])
SITE = re.compile(r"(?:^|[^A-Za-z0-9_])(?:use\s+rsa\b|rsa::)")
ROOTS = ("examples", "fuzz", "axess-testing")

bad = []
for path in sys.stdin.read().split():
    if exempt(path, ROOTS) or path in allowed:
        continue
    with open(path, encoding="utf-8") as f:
        text = f.read()
    bad.extend(f"{path}:{no}" for no, code in production_lines(text) if SITE.search(code))
if bad:
    for site in bad:
        print(f"rsa:: used outside the reviewed files: {site}", file=sys.stderr)
    print("See the header of scripts/check-rsa-sites.sh before adding one.", file=sys.stderr)
    sys.exit(1)
print("ok: rsa is named only in the reviewed RSA module of the local IdP")
' "$LIB" "${ALLOWED[@]}" <<<"$listed"
