#!/usr/bin/env bash
# Run the OpenID Foundation relying-party test plans against examples/oauth.
#
#   scripts/conformance/run-rp.sh                  # all three plans
#   scripts/conformance/run-rp.sh --plans oidcc-client-basic-certification-test-plan
#
# Needs podman (or docker with compose), python3 and a Rust toolchain. It
# starts the suite's containers (axess-conformance-*, loopback port 9080),
# builds examples/oauth, runs the plans through run_rp.py, writes
# scripts/conformance/results.json and rewrites the results section of
# docs/factors/conformance.md, then stops and removes the containers.
# Set KEEP_SUITE=1 to leave them up. CARGO_TARGET_DIR is honoured, and
# CARGO_CMD (default: cargo) names the command to build with, for a wrapper.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${CONFORMANCE_OUT:-$here/out}"
compose=(podman-compose -f "$here/compose.yml")
command -v podman-compose >/dev/null || compose=(podman compose -f "$here/compose.yml")

cleanup() {
    if [ "${KEEP_SUITE:-0}" != "1" ]; then
        "${compose[@]}" down >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

mkdir -p "$out"
cargo_cmd="${CARGO_CMD:-cargo}"
# shellcheck disable=SC2086
(cd "$root" && $cargo_cmd build -p axess-example-oauth)
target="$(cd "$root" && ${CARGO_CMD:-cargo} metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
bin="$target/debug/axess-example-oauth"

"${compose[@]}" up -d
image="$(grep -E '^\s+image: registry' "$here/compose.yml" | head -1 | sed -E 's/.*image: //')"

python3 -I "$here/run_rp.py" \
    --bin "$bin" --out "$out" --image "$image" \
    --results-json "$here/results.json" \
    --splice "$root/docs/factors/conformance.md" "$@"
