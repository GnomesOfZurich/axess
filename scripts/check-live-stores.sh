#!/usr/bin/env bash
# The tests behind `--ignored`: every store that needs a running server
# (Valkey, a Valkey cluster, PostgreSQL, MySQL, Keycloak), run the way CI's
# "Test Suite" job runs them.
#
# A release preflight that skips them certifies nothing about the live
# stores: a test red against a real Valkey passes an in-process suite. So
# this step refuses to run without every server rather than passing over an
# empty run. Start
# them on private ports and name them:
#
#   podman run -d --name axess-valkey-test -p 127.0.0.1:6390:6379 docker.io/valkey/valkey:8-alpine
#   podman run -d --name axess-valkey-cluster --network host docker.io/valkey/valkey:8-alpine \
#     sh -c 'for p in 7001 7002 7003; do valkey-server --port $p --bind 127.0.0.1 --cluster-enabled yes --cluster-config-file nodes-$p.conf --save "" --appendonly no --daemonize yes; done; sleep 1; valkey-cli --cluster create 127.0.0.1:7001 127.0.0.1:7002 127.0.0.1:7003 --cluster-replicas 0 --cluster-yes; exec sleep infinity'
#   podman run -d --name axess-pg-test -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:5490:5432 docker.io/library/postgres:17-alpine
#   podman run -d --name axess-mysql-test -e MYSQL_ROOT_PASSWORD=mysql -e MYSQL_DATABASE=axess_test -p 127.0.0.1:3390:3306 docker.io/library/mysql:8
#   export VALKEY_URL=redis://127.0.0.1:6390
#   export VALKEY_CLUSTER_URL=redis-cluster://127.0.0.1:7001
#   export POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5490/postgres
#   export MYSQL_URL=mysql://root:mysql@127.0.0.1:3390/axess_test
#   podman run -d --name axess-keycloak-test -p 127.0.0.1:8090:8080 \
#     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
#     -e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false -e JAVA_OPTS_APPEND=-XX:UseSVE=0 \
#     -v "$PWD/examples/fapi/keycloak/fapi-realm.json:/opt/keycloak/data/import/fapi-realm.json:Z" \
#     quay.io/keycloak/keycloak:26.0 start-dev --import-realm
#   export KEYCLOAK_URL=http://127.0.0.1:8090
#
# After the run, scripts/live-keys-left.sh asks the Valkey servers for any
# key the run left, with valkey-cli or redis-cli on the PATH, or the
# valkey-cli of the container VALKEY_CLI_CONTAINER names (CI names the
# cluster's).
#
# The cluster (three primaries, no replicas) is where the Valkey code is
# shown to work with keys in different slots (the valkey_cluster suites);
# under podman's VM on macOS a host-network container's ports are
# not reachable from the Mac, so run the three `valkey-server` lines there
# directly if the cluster tests cannot connect.
#
# Keycloak joined the list with the private_key_jwt login test
# (axess-core/tests/oauth_keycloak_live.rs, realm `fapi`); the JVM flag is
# what keeps Keycloak alive under podman's VM on Apple silicon (SIGILL
# without it). Wait for `/realms/fapi` to answer before running.
#
# The SPIRE Workload API suite (axess-core/tests/spire_live.rs) is a run of
# its own, `check-live-stores.sh spire`: it needs an agent that attests the
# test process (an agent on the same host, which is a Linux host for the
# releases SPIRE publishes) and somebody who deletes registration entries
# while it runs. scripts/spire-live.sh provides both and calls this script;
# CI's "SPIRE Workload API" job runs it, and the release gate needs that
# job. So the run of the stores leaves the suite out by name and says so,
# and the run of the suite refuses without its agent as the stores' run
# refuses without its servers. The suite is two runs of one test binary:
# every test but the last, then the last by itself, because the last one
# has the agent stop issuing the process any identity.
#
# Usage: ./scripts/check-live-stores.sh          the stores
#        ./scripts/check-live-stores.sh spire    the SPIRE Workload API suite
set -euo pipefail
AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mode="${1:-stores}"
if [ $# -gt 1 ] || { [ "$mode" != stores ] && [ "$mode" != spire ]; }; then
  echo "usage: $0 [spire]" >&2
  exit 2
fi

if [ "$mode" = spire ]; then
  missing=()
  for v in SPIFFE_ENDPOINT_SOCKET SPIFFE_TRUST_DOMAIN; do
    [ -n "${!v:-}" ] || missing+=("$v")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "ERROR: SPIRE Workload API tests NOT run: ${missing[*]} unset. This is a refusal, not a pass;" >&2
    echo "       scripts/spire-live.sh starts a server and an agent and runs them." >&2
    exit 1
  fi
  # The test that ends the identity of the process. Each run is judged
  # from its own log: a second run whose filter matched no test is a
  # refusal, not a pass on the strength of the first.
  last=spire_live::the_last_entry_deleted_is_refused_by_the_agent_and_withdrawn
  log="$(mktemp -t axess-live-spire.XXXXXX)"
  trap 'rm -f "$log"' EXIT
  # One run of the suite's binary, with the test filter given. --nocapture:
  # a test asks for a deletion by a line on its output, which whoever runs
  # the suite reads while the test waits. --test-threads: with one thread
  # the harness writes a test's name before the test runs and its result
  # after, and a line the test prints in between splits the `test ... ok`
  # line the log check counts; with more it writes the two together.
  run_suite() {
    set +e
    cargo test --manifest-path "$AXESS_DIR/Cargo.toml" -p axess-core \
      --features spire,outbound-mtls,jwt-aws-lc --test spire_live \
      -- --ignored --nocapture --test-threads=4 "$@" 2>&1 | tee "$log"
    status=${PIPESTATUS[0]}
    set -e
    "$AXESS_DIR/scripts/check-test-log.sh" "$status" "$log" spire
  }
  run_suite --skip "$last"
  run_suite --exact "$last"
  exit 0
fi

missing=()
for v in VALKEY_URL VALKEY_CLUSTER_URL POSTGRES_URL MYSQL_URL KEYCLOAK_URL; do
  [ -n "${!v:-}" ] || missing+=("$v")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: live-store tests NOT run: ${missing[*]} unset. This is a refusal, not a pass;" >&2
  echo "       start the servers (recipe at the top of $0) and export every URL." >&2
  exit 1
fi

# The run is judged from its log by scripts/check-test-log.sh: cargo's
# status, no failed test, at least one passing test, and for each store at
# least one passing test from its own suite. The cluster is four suites,
# each counted by a name of its own: `session_cluster` (the session store
# and registry), `authz_cluster` (the authorization cache),
# `device_cluster` (the device store) and `lease_cluster` (the lease the
# other three take their turns at the cluster's counters with: a holder
# that fails gives it up at once, and nobody deletes another holder's
# token). Each name is a whole module of its tests' names, as
# check-test-log.sh counts, inside a `valkey_cluster` module (the name a
# run without a cluster skips them by). The shared name is not required
# here: any one suite would satisfy it, and one suite passing says nothing
# about the others, whose code and keys differ. A run in which the only
# passing tests are ones that never reached a store's server (a test that
# returns early when its URL is missing, say) is a refusal for that store,
# not a pass over an empty run.
#
# Every live Valkey test writes under a prefix that holds this run's token
# and removes its keys when it ends, passed or failed. After the run,
# scripts/live-keys-left.sh asks the node and every primary for a key that
# holds the token: one left is a test that wrote outside its sweep, or a
# sweep that did not remove what it should. It runs whatever the tests
# did, so a failing run says what it left too; the run is judged by both.
log="$(mktemp -t axess-live-stores.XXXXXX)"
trap 'rm -f "$log"' EXIT
AXESS_TEST_RUN="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
export AXESS_TEST_RUN
set +e
cargo test --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features -- --ignored --skip spire_live:: 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
"$AXESS_DIR/scripts/live-keys-left.sh" "$AXESS_TEST_RUN"
keys=$?
set -e
"$AXESS_DIR/scripts/check-test-log.sh" "$status" "$log" valkey session_cluster authz_cluster device_cluster lease_cluster postgres mysql keycloak
[ "$keys" -eq 0 ] || exit "$keys"
echo "NOTE: the SPIRE Workload API suite is not part of this run (it needs an agent on this host):"
echo "      scripts/spire-live.sh runs it, in CI's SPIRE Workload API job."
