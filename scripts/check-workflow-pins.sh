#!/usr/bin/env bash
# axess: every action in every workflow is pinned to a full commit SHA, with
# the release it was read from in a trailing comment, and every checkout
# drops the job token from .git/config.
#
# A tag or a branch moves, so an action pinned to one runs whatever its
# owner points it at on the day of the run, with the registry token or the
# OIDC permissions of the job that names it. A commit does not move. The
# comment keeps the pin readable and lets a bump tool tell which release a
# SHA is. Local reusable workflows (`uses: ./...`) are in this repository
# and need no pin.
#
# The same holds for container images: a service image or a `docker run`
# image named by tag alone is whatever the registry serves that day, next to
# the job's secrets, so each `image:` line carries an @sha256 digest.
#
# Usage: ./scripts/check-workflow-pins.sh [WORKFLOW_DIR]   (default: .github/workflows)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${1:-$AXESS_DIR/.github/workflows}"

errors=0

for f in "$DIR"/*.yml; do
  # Every `uses:` that names a remote action: a 40-hex ref, then ` # version`.
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "REFUSED: $f: action not pinned to a full commit SHA with a version comment: $hit" >&2
    errors=$((errors + 1))
  done < <(grep -nE '^[[:space:]]*(- )?uses:[[:space:]]' "$f" \
    | grep -vE 'uses:[[:space:]]+\./' \
    | grep -vE 'uses:[[:space:]]+[A-Za-z0-9._/-]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v?[0-9]|uses:[[:space:]]+[A-Za-z0-9._/-]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*(master|main)[[:space:]]*$' || true)

  # Every service or container image is pinned by digest.
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "REFUSED: $f: image not pinned by an @sha256 digest: $hit" >&2
    errors=$((errors + 1))
  done < <(grep -nE '^[[:space:]]*image:[[:space:]]' "$f" | grep -v '@sha256:[0-9a-f]\{64\}' || true)

  # Every checkout carries persist-credentials: false in its own with: block.
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "REFUSED: $f: checkout at line $line does not set persist-credentials: false" >&2
    errors=$((errors + 1))
  done < <(awk '
    function flush() { if (open && !ok) print start; open = 0; ok = 0 }
    /^[[:space:]]*(- )?uses:[[:space:]]+actions\/checkout@/ { flush(); open = 1; start = NR; ok = 0; next }
    open && /persist-credentials:[[:space:]]*false/ { ok = 1; next }
    open && /^[[:space:]]*- / { flush() }
    END { flush() }' "$f")
done

if [ "$errors" -ne 0 ]; then
  echo "$errors workflow pin problem(s)." >&2
  exit 1
fi
echo "OK: every action is pinned to a commit SHA, every image to a digest, and every checkout drops its credentials."
