#!/usr/bin/env bash
# axess: fail when a doc comment names a method that does not exist.
#
# `cargo doc` already rejects a broken *intra-doc link*, the bracketed
# [`Type::method`] form. It says nothing about a plain backticked
# `Type::method`, and nothing at all about a ```text fence, which is what
# a setup example becomes as soon as it stops compiling. Both are how a
# reader learns which call to make, and both can name a method that was
# never there.
#
# That is not hypothetical. This check, on first run, found:
#
#   - `AuthnService::backchannel_logout_handler`, in a module-level Setup
#     example and again in the struct's own "Construct via" line. No such
#     method; the constructor is `BackChannelLogoutHandler::new`. The
#     example sat in a ```text fence, so nothing compiled it.
#   - `SessionRegistry::revoke_user_sessions`, recommended on the
#     `regenerate` docs as the stronger action to take after a password
#     change. The method is `invalidate_user`, so a reader following the
#     advice for that specific security step found nothing.
#
# Like `check-doc-identifiers.sh` this is deliberately crude: every
# `Type::member` a doc comment writes in backticks must have both halves
# defined somewhere in the workspace. It proves nothing about whether the
# member belongs to that type. It catches the failure that matters most,
# a call a reader cannot make.
#
# Types we do not define live in ALLOW below. Adding one is a claim that
# it comes from a dependency, so name the crate.
#
# Usage: ./scripts/check-rustdoc-identifiers.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - "$ROOT" <<'PY'
import pathlib, re, subprocess, sys

root = pathlib.Path(sys.argv[1])

# Types owned by dependencies, not by this workspace.
ALLOW = {
    "Arc", "Rc", "Box", "String", "Vec", "Option", "Result", "Duration",
    "Instant", "SystemTime", "HashMap", "HashSet", "BTreeMap", "Path",
    "PathBuf", "Ordering", "Cow",                      # std / core / alloc
    "Uuid",                                            # uuid
    "Value", "Number",                                 # serde_json
    "Cookie", "CookieJar",                             # cookie / tower-cookies
    "Entities", "EntityUid", "Schema", "ValidationMode", "PolicySet",
    "Context", "Decision", "Request", "Validator",     # cedar-policy
    "EncodingKey", "DecodingKey", "Algorithm", "Header",  # jsonwebtoken
    "StatusCode", "HeaderMap", "HeaderValue", "Method",   # http
    "Router", "Json", "Form", "State", "Extension",       # axum
    "DateTime", "Utc", "NaiveDateTime", "TimeDelta",      # chrono
    "Pool", "PgPool", "SqlitePool", "MySqlPool",          # sqlx
}

tracked = subprocess.run(
    ["git", "ls-files", "*.rs"], cwd=root, capture_output=True, text=True, check=True
).stdout.split()

blob = "\n".join((root / f).read_text() for f in tracked)
# `fn` gets its own pattern: in `pub const fn from_static` the alternation
# below matches `const` first and captures `fn` as the name.
defined = set(re.findall(r'\bfn\s+(\w+)', blob))
defined |= set(re.findall(r'\b(?:struct|enum|trait|type|const|static|mod)\s+(\w+)', blob))
defined |= set(re.findall(r'^\s*(\w+)\s*(?:\{|\(|,|=)', blob, re.M))   # enum variants
defined |= set(re.findall(r'\b(\w+):', blob))                          # struct fields

bad = {}
for f in tracked:
    p = root / f
    for i, line in enumerate(p.read_text().split("\n"), 1):
        s = line.strip()
        if not (s.startswith("///") or s.startswith("//!")):
            continue
        for ty, member in re.findall(r'`([A-Z]\w+)::(\w+)`', line):
            if ty in ALLOW:
                continue
            if ty not in defined or member not in defined:
                bad.setdefault(f"{ty}::{member}", []).append(f"{f}:{i}")

if bad:
    print(f"ERROR: {len(bad)} name(s) in doc comments do not exist in the workspace:\n")
    for name, where in sorted(bad.items()):
        print(f"  {name}")
        for w in where:
            print(f"      {w}")
    print("\nFix the name, or add the owning type to ALLOW with its crate.")
    sys.exit(1)

count = len(re.findall(r'`[A-Z]\w+::\w+`', blob))
print(f"check-rustdoc-identifiers: {count} documented names, all resolve.")
PY
