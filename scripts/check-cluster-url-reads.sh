#!/usr/bin/env bash
# axess: VALKEY_CLUSTER_URL is read from the environment in one place,
# `cluster_url` in axess-core/src/testing/valkey_cluster.rs, after its guard.
#
# A run on one Valkey node leaves the cluster tests out by name: they sit
# under a `valkey_cluster` module (docs/project/contributing.md), the live
# mutation job selects `test(valkey) - test(valkey_cluster)`, and a run
# without a cluster passes `--skip valkey_cluster`. A test that reaches the
# cluster from a module of another name is selected by such a run and
# fails there. `cluster_url` opens with a guard that panics on a test's
# thread whose name holds no `valkey_cluster`, so such a test fails in the
# run that has the cluster as well, but only when it takes the URL from
# `cluster_url`. A test that read the variable itself would reach the
# cluster past the guard.
#
# The rule: no Rust source reads VALKEY_CLUSTER_URL from the environment
# but `cluster_url`, after the statement it opens with (`if let Some(..) =
# partition_refusal(std::thread::current().name()) { panic!(..) }`). This
# refuses every other read in the files git lists, production code, tests,
# examples, build scripts and fuzz targets alike, and a read in
# `cluster_url` when the guard does not open it. A read is the variable's
# name as a whole string literal, the whole first argument of
# `std::env::var`, `std::env::var_os`, `env!` or `option_env!`, written out
# or through a name a `use` of std binds (`use std::env::var as get;`).
# scripts/lib/cluster_url_reads.py says when a name is taken for std's: only
# where nothing else can bind it, so each read refused is one, and a tree
# that keeps the rule is never refused. A mention of the variable in a
# comment, a doc comment, an ignore reason or any other text is no read
# (scripts/lib/rust_source.py blanks comments and string literals first),
# and neither are the tokens of a macro invocation or definition, which
# the macro makes into whatever it makes (`stringify!` makes text). An
# item is read as written under its attributes, derives included, and a
# glob import from another crate is taken to bring no item named `std` or
# `core`.
#
# What it does not see: the name built or held elsewhere (`concat!`, a
# constant, a variable, an escape in the literal), a read in a macro's
# tokens (`println!` among them), a helper of the tree's own that reads a
# name it is given, `std::env::vars`, a glob import of `std::env::*`, a
# call that ends a range (`..var(..)`, read as a method after `.`), and a
# reader whose name the file also binds otherwise or a glob import between
# could shadow.
#
# Usage: ./scripts/check-cluster-url-reads.sh [--root DIR]
#   --root DIR  check the Rust files under DIR instead of this repository's
#               files (scripts/check-cluster-url-reads-tests.sh)

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
import sys

sys.path.insert(0, sys.argv[1])
from cluster_url_reads import HELPER, VARIABLE, check

paths = sys.stdin.read().split()
files = []
for path in paths:
    with open(path, encoding="utf-8") as f:
        files.append((path, f.read()))
if not files:
    print("read no Rust file: nothing was checked", file=sys.stderr)
    sys.exit(1)
allowed, refused, read = check(files)
if refused:
    for site in refused:
        print(f"{VARIABLE} read outside cluster_url after its guard: {site}", file=sys.stderr)
    print(f"Take the URL from cluster_url in {HELPER}, whose guard refuses it to a test named"
          " outside valkey_cluster; see the header of scripts/check-cluster-url-reads.sh.",
          file=sys.stderr)
    sys.exit(1)
print(f"ok: in {read} Rust files, {VARIABLE} is read only in cluster_url, after its guard"
      f" ({allowed} read(s) there)")
' "$LIB" <<<"$listed"
