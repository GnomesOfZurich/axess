#!/usr/bin/env bash
# axess — run `cargo mutants` inside an isolated git worktree.
#
# local-run isolation. Background:
#
# Cargo-mutants edits source files as it probes them — it injects a
# stub body marked `/* ~ changed by cargo-mutants ~ */`, runs the
# test suite, then rolls the change back. If the primary working
# tree is also the mutation target, any concurrent tooling (`cargo
# test`, an editor's `rust-analyzer`, another agent's `clippy`)
# observes whichever transient mutation is in flight. Symptoms we
# burned hours on before this script existed: tests failing
# differently each run, mutation markers landing in commits because
# a crash left the rollback halfway done, and `clippy -D warnings`
# tripping on stub bodies.
#
# This script side-steps the race by running `cargo mutants` inside
# a dedicated `git worktree` rooted at `.mutants-worktree/`. The
# worktree is checked out to the current HEAD on entry (so it
# always probes the code you actually have right now, including
# uncommitted-but-tracked changes that you've staged into the index)
# and is left in place between runs so cargo's `target/` survives.
#
# Usage:
#   ./scripts/mutants.sh                  # full sweep
#   ./scripts/mutants.sh --in-diff origin/main   # PR-style touch-only
#   ./scripts/mutants.sh --file axess-core/src/session/layer.rs
#   ./scripts/mutants.sh --clean          # drop the worktree, then exit
#
# All flags after the script name are forwarded verbatim to
# `cargo mutants` (except `--clean`, which is handled here).
#
# The worktree path is `.gitignore`d. It is safe to delete with
# `git worktree remove .mutants-worktree` at any time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKTREE_DIR="$AXESS_DIR/.mutants-worktree"
WORKTREE_BRANCH="mutants/scratch"

cd "$AXESS_DIR"

if [ "${1:-}" = "--clean" ]; then
  if git worktree list --porcelain | grep -q "worktree $WORKTREE_DIR"; then
    git worktree remove --force "$WORKTREE_DIR"
    echo "Removed mutants worktree at $WORKTREE_DIR"
  else
    echo "No mutants worktree to remove."
  fi
  if git show-ref --verify --quiet "refs/heads/$WORKTREE_BRANCH"; then
    git branch -D "$WORKTREE_BRANCH"
    echo "Deleted scratch branch $WORKTREE_BRANCH."
  fi
  exit 0
fi

# 1. Ensure the worktree exists. We pin it to a private branch
#    (`mutants/scratch`) so the worktree never shares a branch with
#    the primary checkout — running two `git worktree`s on the same
#    branch is rejected by git anyway.
if ! git worktree list --porcelain | grep -q "worktree $WORKTREE_DIR"; then
  echo "Creating mutants worktree at $WORKTREE_DIR (branch: $WORKTREE_BRANCH)..."
  if git show-ref --verify --quiet "refs/heads/$WORKTREE_BRANCH"; then
    git worktree add "$WORKTREE_DIR" "$WORKTREE_BRANCH"
  else
    git worktree add -b "$WORKTREE_BRANCH" "$WORKTREE_DIR" HEAD
  fi
fi

# 2. Sync the worktree to the primary checkout's HEAD. We hard-reset
#    rather than merge so transient state from a previous mutants
#    crash (e.g. a leftover `~ changed by cargo-mutants ~` stub) gets
#    obliterated; `target/` is preserved across runs as it lives
#    outside the git index.
(
  cd "$WORKTREE_DIR"
  git fetch --quiet "$AXESS_DIR" HEAD
  git reset --hard FETCH_HEAD --quiet
  git clean -fdx --quiet -e target/
) >/dev/null

# 3. Run cargo-mutants inside the worktree. `--workspace-jobs` is
#    left to the user / `.cargo/mutants.toml`; flags forwarded as-is.
echo "Running cargo mutants in $WORKTREE_DIR..."
echo "Args: $*"
echo
cd "$WORKTREE_DIR"
exec cargo mutants "$@"
