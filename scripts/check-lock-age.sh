#!/usr/bin/env bash
# axess: no lockfile entry younger than the cooldown, unless an advisory fix.
#
# .cargo/config.toml holds cargo's resolver to crate versions published at
# least `registry.global-min-publish-age` (seven days) ago. A locked version,
# a lockfile written by hand or by a bot, and a cargo older than 1.100 pass
# by the resolver, so this reads the lockfiles themselves: every Cargo.lock
# git tracks, the fuzz crate's included, and every untracked one it does not
# ignore. Each crates.io entry added since the base must have been published
# at least that long ago, by the `pubtime` the crates.io sparse index gives
# (the time cargo's own rule reads), or be admitted by a trailer at the end
# of the message of the commit that adds it:
#
#   Cooldown-Exempt: <advisory id> <crate>
#
# (a RUSTSEC-, GHSA- or CVE- id; one trailer per crate). A message that only
# mentions an advisory admits nothing. scripts/lib/lock_age.py says what
# counts as added and every way an entry is refused: it is refused, never
# passed, whenever its publish time cannot be read, the index unreachable
# included.
#
# The base is the newest `v*` tag that is a strict ancestor of HEAD, the
# release the branch was cut after, as scripts/check-semver.sh takes it (on a
# tag being released, the release before it). With no such tag the check
# refuses: fetch the tags or name the base.
#
# This calls the network (index.crates.io), so the offline gate of the
# integration leaves it out by name; its crafted cases
# (scripts/check-lock-age-tests.sh) run offline, against a local directory
# laid out like the index.
#
# Usage: ./scripts/check-lock-age.sh [--base REF] [--index URL|DIR] [--root DIR] [--cargo-config FILE]
#   --base REF            judge the lockfiles against REF instead of the last tag
#   --index X             read publish times from another https index or from a
#                         directory laid out like one (the crafted cases)
#   --root DIR            the repository to read (default: this one)
#   --cargo-config FILE   read the age from FILE instead of the repository's
#                         .cargo/config.toml (the crafted cases)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE=""
INDEX="https://index.crates.io/"
CONFIG=""

usage() {
  echo "usage: $0 [--base REF] [--index URL|DIR] [--root DIR] [--cargo-config FILE]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --base) [ $# -ge 2 ] || usage; BASE="$2"; shift 2 ;;
    --index) [ $# -ge 2 ] || usage; INDEX="$2"; shift 2 ;;
    --root) [ $# -ge 2 ] || usage; ROOT="$2"; shift 2 ;;
    --cargo-config) [ $# -ge 2 ] || usage; CONFIG="$2"; shift 2 ;;
    *) usage ;;
  esac
done

if ! git -C "$ROOT" rev-parse --verify --quiet HEAD >/dev/null; then
  echo "ERROR: $ROOT is not a git work tree with a commit." >&2
  exit 1
fi
if [ -z "$BASE" ]; then
  BASE="$(git -C "$ROOT" tag --merged HEAD --no-contains HEAD --list 'v[0-9]*' --sort=-v:refname | sed -n 1p)"
  if [ -z "$BASE" ]; then
    echo "ERROR: lock age NOT checked: no release tag v* is an ancestor of HEAD, so there is no base to judge the lockfiles against." >&2
    echo "       Fetch the tags (git fetch --tags, or fetch-depth: 0 in CI), or name the base: $0 --base <commit>." >&2
    exit 1
  fi
fi
if ! git -C "$ROOT" rev-parse --verify --quiet "${BASE}^{commit}" >/dev/null; then
  echo "ERROR: the base '$BASE' is not a commit of this repository." >&2
  exit 1
fi

echo "Lock age base: $BASE ($(git -C "$ROOT" rev-parse --short "${BASE}^{commit}"))"
python3 -I -B "$SCRIPT_DIR/lib/lock_age.py" --repo "$ROOT" --config "${CONFIG:-$ROOT/.cargo/config.toml}" --base "$BASE" --index "$INDEX"
