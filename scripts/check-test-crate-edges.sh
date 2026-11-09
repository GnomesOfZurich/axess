#!/usr/bin/env bash
# axess: the test-only crates are reachable from no production edge.
#
# `axess-testing` carries `wiremock` (a mock HTTP server) and an RSA key
# generator; an adopter takes it as a dev-dependency. Cargo feature
# unification means a normal or build dependency edge to either, from any
# crate a release build links, puts the mock server in that build. This walks
# the resolved graph (every feature on) from each workspace member except
# `axess-testing` itself, along normal and build edges only, and fails when it
# reaches `axess-testing` or `wiremock`.
#
# `deny-production.toml` states the same rule for cargo-deny; this script is
# the half that also sees the workspace's own crates as roots.
#
# Usage: ./scripts/check-test-crate-edges.sh

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

cargo metadata --format-version 1 --all-features --locked 2>/dev/null | python3 -I -c '
import json, sys
from collections import deque

meta = json.load(sys.stdin)
BANNED = {"axess-testing", "wiremock"}
nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
names = {p["id"]: p["name"] for p in meta["packages"]}
members = [m for m in meta["workspace_members"] if names[m] != "axess-testing"]

def production_deps(node):
    for dep in node["deps"]:
        kinds = {k["kind"] for k in dep["dep_kinds"]}
        if kinds & {None, "build"}:
            yield dep["pkg"]

failures = []
for root in members:
    seen = {root}
    queue = deque([(root, [names[root]])])
    while queue:
        pkg, path = queue.popleft()
        for dep in production_deps(nodes[pkg]):
            if names[dep] in BANNED:
                failures.append(" -> ".join(path + [names[dep]]))
            if dep not in seen:
                seen.add(dep)
                queue.append((dep, path + [names[dep]]))

if failures:
    for line in sorted(set(failures)):
        print("test-only crate on a production edge: " + line, file=sys.stderr)
    sys.exit(1)
print("ok: axess-testing and wiremock are reachable only from dev-dependency edges")
'
