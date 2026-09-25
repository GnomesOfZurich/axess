#!/usr/bin/env bash
# axess: fail when the docs import a module the facade does not have.
#
# `check-doc-identifiers.sh` checks that a name exists somewhere in the
# workspace. It says nothing about the path the docs tell an adopter to
# write, so `use axess::factors::mtls::PeerCertChain;` passes: the type is
# real, and `axess::factors` is not a module at all. The import does not
# compile, and nothing compiles it, because the block is ```rust,ignore.
#
# That is not hypothetical. This check, on first run, found:
#
#   - `axess::factors::mtls::PeerCertChain` and
#     `axess::factors::oauth::{FapiConfig, ...}`. Both live under
#     `axess::federation::`; there is no `axess::factors`.
#   - `axess::middleware::ratelimit::*` in CONTRIBUTING.md, in the rule
#     stating that re-export through the facade preserves the import path.
#     The facade flattens instead: the layer is `axess::RateLimitLayer`.
#   - `axess::middleware::*` in `axess/README.md`, which is the crates.io
#     front page, describing the canonical module layout.
#   - `use axess::store::Store;` in the backends chapter, two lines under
#     prose correctly naming `axess_core::store::Store`. `Store` is one of
#     the few things the facade does not re-export.
#
# Only the first segment is checked, and only where a second follows. That
# is the reliable part: a module either appears in `axess/src/lib.rs` as
# `pub mod` or is re-exported by name, and deeper segments may be types,
# associated items or macro paths that this cannot see. A gate with false
# positives teaches people to ignore it.
#
# Usage: ./scripts/check-facade-paths.sh
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - <<'PY'
import pathlib, re, subprocess, sys

lib = pathlib.Path("axess/src/lib.rs").read_text()

# What `axess::<seg>::` may legitimately name.
surface = set(re.findall(r'^\s*pub mod (\w+)\s*[;{]', lib, re.M))
for group in re.findall(r'pub use [\w:]*::\{([^}]*)\}', lib, re.S):
    for n in group.replace("\n", " ").split(","):
        n = n.strip().split(" as ")[-1].strip()
        if n:
            surface.add(n)
surface |= set(re.findall(r'pub use [\w:]*::(\w+);', lib))

tracked = subprocess.run(
    ["git", "ls-files", "*.md"], capture_output=True, text=True, check=True
).stdout.split()

bad = {}
for f in tracked:
    for i, line in enumerate(pathlib.Path(f).read_text().split("\n"), 1):
        # `axess::` exactly: `axess_core::`, `axess_factors::` are other crates.
        for seg in re.findall(r'(?<![\w_])axess::(\w+)::', line):
            if seg not in surface:
                bad.setdefault(f"axess::{seg}", []).append(f"{f}:{i}")

if bad:
    print(f"ERROR: {len(bad)} path(s) the docs write do not exist on the facade:\n")
    for name, sites in sorted(bad.items()):
        print(f"  {name}")
        for s in sites[:4]:
            print(f"      {s}")
        if len(sites) > 4:
            print(f"      ... and {len(sites) - 4} more")
    print("\nCheck `axess/src/lib.rs` for the real module, or name the")
    print("defining crate (`axess_core::…`) where the facade does not re-export it.")
    sys.exit(1)

print(f"check-facade-paths: {len(surface)} facade names, all documented imports resolve.")
PY
