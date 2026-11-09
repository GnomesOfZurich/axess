#!/usr/bin/env bash
# axess: no new `rsa::` call site in production code.
#
# The `rsa` crate carries RUSTSEC-2023-0071 (a timing side channel on RSA
# private-key operations, no fixed release), which `deny.toml` ignores for
# the whole workspace because cargo-deny cannot scope an ignore to a feature
# or a file. The ignore is sound only while the crate's private-key
# operations stay where they were reviewed: key generation and parsing in the
# local IdP's signing-key primitives, and the random-number adapter it needs.
# Signing itself goes through `jsonwebtoken`'s backend.
#
# This fails when any other production file under a crate's `src/` names
# `rsa::` or `use rsa`. Test code (`tests/`, `testing/`, `tests.rs`,
# `*_tests.rs`), the fixture crate `axess-testing` and doc comments are
# exempt. Adding a site to ALLOWED is a
# claim that its use of `rsa` was reviewed against the advisory: say why in
# the commit.
#
# Usage: ./scripts/check-rsa-sites.sh

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

ALLOWED=(
  "axess-core/src/local_idp/primitives.rs"
  "axess-core/src/local_idp/primitives/rng_adapter.rs"
)

git ls-files '*.rs' | python3 -I -c '
import re, sys

allowed = set(sys.argv[1:])
SITE = re.compile(r"(?:^|[^A-Za-z0-9_])(?:use\s+rsa\b|rsa::)")

def exempt(path):
    parts = path.split("/")
    if parts[0] in ("examples", "fuzz", "axess-testing") or "src" not in parts:
        return True
    name = parts[-1]
    if name in ("tests.rs", "testing.rs") or name.endswith("_tests.rs"):
        return True
    return any(p in ("tests", "testing", "benches") for p in parts)

bad = []
for path in sys.stdin.read().split():
    if exempt(path) or path in allowed:
        continue
    with open(path, encoding="utf-8") as f:
        in_test = False
        for no, raw in enumerate(f, 1):
            line = raw.strip()
            if line.startswith("//"):
                continue
            if re.match(r"#\[cfg\(test\)\]", line):
                in_test = True
            if not in_test and SITE.search(raw.split("//")[0]):
                bad.append(f"{path}:{no}")
if bad:
    for site in bad:
        print(f"rsa:: used outside the reviewed files: {site}", file=sys.stderr)
    print("See the header of scripts/check-rsa-sites.sh before adding one.", file=sys.stderr)
    sys.exit(1)
print("ok: rsa is named only in the reviewed local IdP primitives")
' "${ALLOWED[@]}"
