#!/usr/bin/env bash
# axess: every jsonwebtoken operation that takes the crypto provider goes
# through the boundary in axess_factors::jwt.
#
# jsonwebtoken fixes its crypto provider for the whole process at the first
# operation that signs or verifies. With both backends compiled in, which
# `--all-features` and cargo's feature unification both do, an operation that
# comes before any install fixes jsonwebtoken's fallback, which panics on
# that operation and on every later one, and no install can replace it. A
# test whose first operation came before the settle passed under `cargo
# test`, where another test usually settled the provider first, and failed
# under nextest, which runs each test in a process of its own. So the
# settle is not left to each call site: `axess_factors::jwt::encode`,
# `decode`, `sign` and `verify` (re-exported by `axess::jwt`) call
# `ensure_crypto_provider` and then jsonwebtoken, and this refuses every
# other way to an operation, in production code, tests, examples and fuzz
# targets alike:
#
#   - a path to `jsonwebtoken::encode`, `jsonwebtoken::decode`,
#     `jsonwebtoken::crypto::sign`, `jsonwebtoken::crypto::verify` or
#     anything in `jsonwebtoken::jws`;
#   - a `use` of jsonwebtoken that imports one of those functions, the
#     `crypto` or `jws` module itself, a glob, or the crate under another
#     name (`use jsonwebtoken as jwt`, `extern crate jsonwebtoken as jwt`);
#   - `from_encoding_key`, `from_decoding_key` and `ThumbprintHash`, the JWK
#     operations that take the provider and that the boundary does not
#     cover: code that needs one calls `ensure_crypto_provider` first, and
#     this file is where the reason for it is added to EXEMPT;
#   - a manifest that depends on jsonwebtoken under another name
#     (`package = "jsonwebtoken"`).
#
# `decode_header`, the key constructors and the provider installs take no
# provider and pass. Comments and string literals are not code
# (scripts/lib/rust_source.py blanks them first). The one exempt file is
# the boundary itself. What it does not see: a path written inside a macro
# that pastes the crate name together, and a `use` nested in a group that
# does not start with jsonwebtoken (`use {jsonwebtoken::encode, ...}`).
#
# Usage: ./scripts/check-jwt-provider-sites.sh [--root DIR]
#   --root DIR  check the Rust files and manifests under DIR instead of this
#               repository's files (scripts/check-jwt-provider-sites-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

EXEMPT=(
  "axess-factors/src/jwt.rs"
)

if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$2"
  files() { find . \( -name '*.rs' -o -name 'Cargo.toml' \) -type f | sed 's|^\./||' | sort; }
else
  [ $# -eq 0 ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not
  # yet added is checked as well.
  files() { git ls-files --cached --others --exclude-standard --deduplicate '*.rs' '*Cargo.toml'; }
fi

listed="$(files)"
python3 -I -B -c '
import re, sys

sys.path.insert(0, sys.argv[1])
from rust_source import blanked_lines

exempt = set(sys.argv[2:])
# A path to an operation; `\b` keeps `decode_header` out.
PATH = re.compile(
    r"\bjsonwebtoken\s*::\s*(?:(?:encode|decode)\b|crypto\s*::\s*(?:sign|verify)\b|jws\b)"
)
# The JWK operations the boundary does not cover.
JWK = re.compile(r"\b(?:from_encoding_key|from_decoding_key|ThumbprintHash)\b")
# A `use` rooted at the crate, up to its `;`, over as many lines as it takes.
USE = re.compile(r"\buse\s+(?:::\s*)?jsonwebtoken\b([^;]*);")
# Inside such a use: an imported operation or module, a glob, a rename of
# the crate or of a module. `sign` and `verify` name nothing else there.
IMPORTED = re.compile(
    r"\b(?:encode|decode|sign|verify|jws)\b"
    r"|\bcrypto\b\s*(?=[,}]|$|as\b)"
    r"|\bcrypto\s*::\s*\{[^}]*\bself\b"
    r"|\*"
    r"|^\s*as\b"
)
EXTERN = re.compile(r"\bextern\s+crate\s+jsonwebtoken\b")
RENAMED = re.compile(r"package\s*=\s*" + chr(34) + "jsonwebtoken" + chr(34))

def line_of(text, offset):
    return text.count("\n", 0, offset) + 1

bad = []
read = 0
for path in sys.stdin.read().split():
    read += 1
    if path in exempt:
        continue
    with open(path, encoding="utf-8") as f:
        source = f.read()
    if path.endswith("Cargo.toml"):
        for no, line in enumerate(source.split("\n"), 1):
            if RENAMED.search(line.split("#", 1)[0]):
                bad.append(f"{path}:{no}: jsonwebtoken under another name")
        continue
    code = "\n".join(blanked_lines(source))
    for pattern in (PATH, JWK, EXTERN):
        for m in pattern.finditer(code):
            bad.append(f"{path}:{line_of(code, m.start())}: {m.group(0)}")
    for m in USE.finditer(code):
        tree = m.group(1)
        hit = IMPORTED.search(tree)
        if hit:
            no = line_of(code, m.start(1) + hit.start())
            shown = " ".join(tree.split())
            bad.append(f"{path}:{no}: use jsonwebtoken{shown}")
if read == 0:
    print("read no Rust file or manifest: nothing was checked", file=sys.stderr)
    sys.exit(1)
if bad:
    for site in bad:
        print(f"jsonwebtoken operation outside axess_factors::jwt: {site}", file=sys.stderr)
    print("Call axess_factors::jwt::{encode, decode, sign, verify} (axess::jwt in the examples);"
          " see the header of scripts/check-jwt-provider-sites.sh.", file=sys.stderr)
    sys.exit(1)
print(f"ok: in {read} files, every jsonwebtoken operation that takes the crypto provider"
      " goes through axess_factors::jwt")
' "$LIB" "${EXEMPT[@]}" <<<"$listed"
