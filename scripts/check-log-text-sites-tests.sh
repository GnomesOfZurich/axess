#!/usr/bin/env bash
# axess: crafted cases for scripts/check-log-text-sites.sh.
#
# Each case writes Rust files and a census under a temporary root, runs the
# check against them with `--root` and `--census`, and asserts the exit
# status and a fragment of the output. The refusals are the contract: a raw
# field of caller text the census does not hold fails, and so does a census
# entry no field answers to.
#
# Usage: ./scripts/check-log-text-sites-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-log-text-sites.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-log-text-sites.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0
TAB="$(printf '\t')"

# case NAME EXPECTED_EXIT FRAGMENT CENSUS [UNWANTED] -- FILE CONTENT [FILE CONTENT...]
# CENSUS is the census's text, one entry per line.
case_() {
  local name="$1" want="$2" fragment="$3" census="$4" unwanted=""
  shift 4
  if [ "$1" != "--" ]; then unwanted="$1"; shift; fi
  shift
  local root="$WORK/$passed-$failed"
  mkdir -p "$root"
  printf '# census\n%s\n' "$census" > "$WORK/census.txt"
  while [ $# -gt 0 ]; do
    mkdir -p "$root/$(dirname "$1")"
    printf '%s\n' "$2" > "$root/$1"
    shift 2
  done
  local out status
  out="$("$CHECK" --root "$root" --census "$WORK/census.txt" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out" "$unwanted"
}

RAW='fn f(name: &str) { tracing::warn!(provider = %name, "refused"); }'
case_ "a new raw field of caller text fails by name" 1 \
  "raw log field not in the census: axess-core/src/a.rs: provider = %name" "" \
  -- axess-core/src/a.rs "$RAW"
case_ "the same field through the helper passes" 0 "ok: every raw log field" "" \
  -- axess-core/src/a.rs 'fn f(name: &str) {
    tracing::warn!(
        provider = %crate::authn::service::log_text::logged_request_text(name),
        "refused"
    );
}'
case_ "a field through log_safe passes" 0 "ok: every raw log field" "" \
  -- axess-factors/src/a.rs 'fn f(name: &str) { tracing::warn!(provider = %crate::log_text::log_safe(name, 128), "x"); }'
case_ "a helper called inside another call is still raw" 1 "provider = %wrap(log_safe(name, 9))" "" \
  -- axess-core/src/a.rs 'fn f(name: &str) { tracing::warn!(provider = %wrap(log_safe(name, 9)), "x"); }'

TYPED='fn f(tenant_id: TenantId) { tracing::warn!(tenant = %tenant_id, "refused"); }'
case_ "a typed id passes by its recorded reason" 0 "the 1 the census records" \
  "1${TAB}typed-id${TAB}axess-core/src/a.rs${TAB}tenant${TAB}%tenant_id" \
  -- axess-core/src/a.rs "$TYPED"
case_ "a recorded site that no longer exists fails until the census is updated" 1 \
  "census entry with no site: axess-core/src/a.rs: tenant = %tenant_id" \
  "1${TAB}typed-id${TAB}axess-core/src/a.rs${TAB}tenant${TAB}%tenant_id" \
  -- axess-core/src/a.rs 'fn f() {}'
case_ "a recorded field in another file is a new site" 1 \
  "raw log field not in the census: axess-core/src/b.rs: tenant = %tenant_id" \
  "1${TAB}typed-id${TAB}axess-core/src/a.rs${TAB}tenant${TAB}%tenant_id" \
  -- axess-core/src/a.rs "$TYPED" axess-core/src/b.rs "$TYPED"
case_ "one more identical field than recorded fails" 1 "(2 found, 1 recorded)" \
  "1${TAB}typed-id${TAB}axess-core/src/a.rs${TAB}tenant${TAB}%tenant_id" \
  -- axess-core/src/a.rs "$TYPED
fn g(tenant_id: TenantId) { tracing::info!(tenant = %tenant_id, \"again\"); }"
case_ "a shorthand field of caller text fails" 1 "axess-core/src/a.rs: tenant = %tenant" "" \
  -- axess-core/src/a.rs 'fn f(tenant: &str) { tracing::warn!(%tenant, "refused"); }'
case_ "a Debug field of caller text fails" 1 "axess-core/src/a.rs: issuer = ?issuer" "" \
  -- axess-core/src/a.rs 'fn f(issuer: &str) { tracing::warn!(issuer = ?issuer, "refused"); }'
case_ "a field of another name is not this census's" 0 "ok: every raw log field" "" \
  -- axess-core/src/a.rs 'fn f(e: &str) { tracing::warn!(error = %e, "refused"); }'
case_ "a field in a test module passes" 0 "ok: every raw log field" "" \
  -- axess-core/src/a.rs 'fn g() {}
#[cfg(test)]
mod tests {
    fn f(name: &str) { tracing::warn!(provider = %name, "x"); }
}'
case_ "a test sibling passes" 0 "ok: every raw log field" "" -- axess-core/src/a/tests.rs "$RAW"
case_ "a field in a string literal passes" 0 "ok: every raw log field" "" \
  -- axess-core/src/a.rs 'const S: &str = "provider = %name";'
case_ "a field in a comment passes" 0 "ok: every raw log field" "" \
  -- axess-core/src/a.rs '// tracing::warn!(provider = %name, "x");
fn g() {}'
case_ "a census entry without its reason is refused" 2 "an entry needs its reason" \
  "1${TAB} ${TAB}axess-core/src/a.rs${TAB}tenant${TAB}%tenant_id" \
  -- axess-core/src/a.rs "$TYPED"
case_ "a census line of another shape is refused" 2 "want COUNT<TAB>REASON" \
  "typed-id axess-core/src/a.rs tenant %tenant_id" \
  -- axess-core/src/a.rs "$TYPED"

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
listed "$CHECK" "an untracked file is read" 1 "raw log field not in the census: axess-core/src/new.rs: provider = %name" "ignored.rs" \
  scripts/log-text-sites-census.txt '# census' axess-core/src/new.rs "$RAW" axess-core/src/ignored.rs "$RAW"
listed "$CHECK" "an ignored file is not read" 0 "ok: every raw log field" "ignored.rs" \
  scripts/log-text-sites-census.txt '# census' axess-core/src/ignored.rs "$RAW"

echo "check-log-text-sites tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
