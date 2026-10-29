#!/usr/bin/env bash
# The tests behind `--ignored`: every store that needs a running server
# (Valkey, PostgreSQL, MySQL), run the way CI's "Test Suite" job runs them.
#
# A release preflight that skips them certifies nothing about the live
# stores: 0.13.0 shipped with four Valkey device tests red because the
# preflight ran only the in-process suite. So this step refuses to run
# without all three servers rather than passing over an empty run. Start
# them on private ports and name them:
#
#   podman run -d --name axess-valkey-test -p 127.0.0.1:6390:6379 docker.io/valkey/valkey:8-alpine
#   podman run -d --name axess-pg-test -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:5490:5432 docker.io/library/postgres:17-alpine
#   podman run -d --name axess-mysql-test -e MYSQL_ROOT_PASSWORD=mysql -e MYSQL_DATABASE=axess_test -p 127.0.0.1:3390:3306 docker.io/library/mysql:8
#   export VALKEY_URL=redis://127.0.0.1:6390
#   export POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5490/postgres
#   export MYSQL_URL=mysql://root:mysql@127.0.0.1:3390/axess_test
set -euo pipefail
AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

missing=()
for v in VALKEY_URL POSTGRES_URL MYSQL_URL; do
  [ -n "${!v:-}" ] || missing+=("$v")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: live-store tests NOT run: ${missing[*]} unset. This is a refusal, not a pass;" >&2
  echo "       start the three servers (recipe at the top of $0) and export every URL." >&2
  exit 1
fi

log="$(mktemp -t axess-live-stores.XXXXXX)"
set +e
cargo test --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features -- --ignored 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
set -e
passed=$(grep -E '^test result:' "$log" | awk '{p+=$4} END {print p+0}')
failed=$(grep -E '^test result:' "$log" | awk '{f+=$6} END {print f+0}')
lines=$(grep -cE '^test result:' "$log" || true)
rm -f "$log"
if [ "$status" -ne 0 ] || [ "$failed" -ne 0 ]; then
  echo "ERROR: live-store tests: $failed failed, $passed passed over $lines result lines (cargo exit $status)." >&2
  exit 1
fi
if [ "$passed" -eq 0 ]; then
  echo "ERROR: live-store tests measured nothing: 0 passed over $lines result lines." >&2
  exit 1
fi
echo "OK: live-store tests: $passed passed, 0 failed, over $lines result lines (Valkey, PostgreSQL, MySQL)."
