#!/usr/bin/env bash
# axess: the Workload API client against a SPIRE server and agent of its own.
#
# The suite in axess-core/tests/spire_live.rs needs an agent that issues the
# test process two identities and somebody who deletes a registration entry
# when a test asks for it. This script is both. It starts a server and an
# agent in a directory of their own (a join token, the agent bootstrapped
# with the server's bundle, the `unix` workload attestor), registers
#
#   spiffe://example.org/axess-live/steady     X.509 SVIDs that live two minutes
#   spiffe://example.org/axess-live/withdrawn
#
# for the uid it runs as, waits until the agent serves both, and runs the
# suite through `scripts/check-live-stores.sh spire`. A test that wants an
# entry deleted prints `spire-live: delete the entry of <SPIFFE ID>` and
# waits; the script reads the suite's output as it is written and deletes
# the entry named. The suite asks twice: for `withdrawn` while `steady`
# remains (the agent goes on answering, without that identity), and in its
# last test for `steady` (the agent then refuses the process). A run that
# passed without both deletions is refused.
#
# Usage: ./scripts/spire-live.sh SPIRE_BIN
#   SPIRE_BIN  the directory that holds `spire-server` and `spire-agent`:
#              the `bin` of an unpacked SPIRE release
#
# SPIRE publishes Linux binaries, and the agent attests a workload on its
# own host, so this runs on Linux: CI's "SPIRE Workload API" job runs it
# with the release it pins by digest. The server listens on 127.0.0.1:8081.
set -euo pipefail
AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ $# -ne 1 ]; then
  echo "usage: $0 SPIRE_BIN" >&2
  exit 2
fi
if [ ! -d "$1" ]; then
  echo "ERROR: $1 is not a directory." >&2
  exit 2
fi
# The directory as given: the pin check reads a program run from it as one
# of the release the caller checked against its digest and unpacked there.
bin="$1"
for program in spire-server spire-agent; do
  if [ ! -x "$bin/$program" ]; then
    echo "ERROR: $bin/$program is not a program this user can run." >&2
    exit 2
  fi
done

TRUST_DOMAIN=example.org
PARENT="spiffe://$TRUST_DOMAIN/axess-live/node"
# Under /tmp whatever TMPDIR holds: the two sockets live in it, and a
# socket's path is at most 107 bytes.
dir="$(mktemp -d /tmp/axess-spire-live.XXXXXX)"
server_socket="$dir/server.sock"
agent_socket="$dir/agent.sock"
suite_log="$dir/suite.log"

# Stop what was started and remove the directory; after a failure, show
# the end of both logs first.
pids=()
finish() {
  local code=$? pid name
  for pid in ${pids[@]+"${pids[@]}"}; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [ "$code" -ne 0 ]; then
    for name in server agent; do
      if [ -r "$dir/$name.log" ]; then
        echo "--- the end of the $name's log ---" >&2
        tail -n 40 "$dir/$name.log" >&2
      fi
    done
  fi
  rm -rf "$dir"
  exit "$code"
}
trap finish EXIT

# Run the command given once a second until it succeeds, for at most
# SECONDS_ALLOWED seconds.
wait_for() {
  local what="$1" seconds_allowed="$2" n
  shift 2
  for ((n = 0; n < seconds_allowed; n++)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: $what: not within $seconds_allowed seconds." >&2
  return 1
}

mkdir "$dir/server" "$dir/agent"
cat >"$dir/server.conf" <<CONF
server {
    bind_address = "127.0.0.1"
    bind_port = "8081"
    socket_path = "$server_socket"
    trust_domain = "$TRUST_DOMAIN"
    data_dir = "$dir/server"
    log_level = "INFO"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "$dir/server/datastore.sqlite3"
        }
    }
    NodeAttestor "join_token" {
        plugin_data {
        }
    }
    KeyManager "memory" {
        plugin_data = {}
    }
}
CONF

cat >"$dir/agent.conf" <<CONF
agent {
    data_dir = "$dir/agent"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "8081"
    socket_path = "$agent_socket"
    trust_bundle_path = "$dir/bundle.crt"
    trust_domain = "$TRUST_DOMAIN"
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {
        }
    }
    KeyManager "memory" {
        plugin_data {
        }
    }
    WorkloadAttestor "unix" {
        plugin_data {
        }
    }
}
CONF

"$bin/spire-server" run -config "$dir/server.conf" >"$dir/server.log" 2>&1 &
pids+=("$!")
wait_for "the server" 60 "$bin/spire-server" healthcheck -socketPath "$server_socket"

"$bin/spire-server" bundle show -socketPath "$server_socket" >"$dir/bundle.crt"
token="$("$bin/spire-server" token generate -socketPath "$server_socket" -spiffeID "$PARENT" | sed -n 's/^Token: //p')"
if [ -z "$token" ]; then
  echo "ERROR: the server gave no join token." >&2
  exit 1
fi
"$bin/spire-agent" run -config "$dir/agent.conf" -joinToken "$token" >"$dir/agent.log" 2>&1 &
pids+=("$!")
wait_for "the agent" 60 "$bin/spire-agent" healthcheck -socketPath "$agent_socket"

# One entry for the uid of this process: NAME, then the flags of
# `entry create` that are the entry's own.
register() {
  local name="$1"
  shift
  "$bin/spire-server" entry create -socketPath "$server_socket" \
    -entryID "axess-live-$name" -parentID "$PARENT" \
    -spiffeID "spiffe://$TRUST_DOMAIN/axess-live/$name" \
    -selector "unix:uid:$(id -u)" "$@"
}
# Two minutes: short enough that a rotation comes about a minute in, long
# enough that the SVID a source holds has most of a minute left at any
# instant, more than a deleted entry takes to reach the workload.
register steady -x509SVIDTTL 120
register withdrawn

# An entry reaches the agent at its next reload, a few seconds on.
serves_both() {
  local answer
  answer="$("$bin/spire-agent" api fetch x509 -socketPath "$agent_socket" 2>/dev/null)" || return 1
  grep -qF "spiffe://$TRUST_DOMAIN/axess-live/steady" <<<"$answer" &&
    grep -qF "spiffe://$TRUST_DOMAIN/axess-live/withdrawn" <<<"$answer"
}
wait_for "the two identities at the agent" 90 serves_both

# Delete each entry the suite asks for, once, when its line appears.
delete_when_asked() {
  local name
  while :; do
    for name in withdrawn steady; do
      if [ ! -e "$dir/deleted-$name" ] &&
        grep -qF "spire-live: delete the entry of spiffe://$TRUST_DOMAIN/axess-live/$name" "$suite_log"; then
        : >"$dir/deleted-$name"
        "$bin/spire-server" entry delete -socketPath "$server_socket" -entryID "axess-live-$name"
      fi
    done
    sleep 1
  done
}
: >"$suite_log"
delete_when_asked &
pids+=("$!")

set +e
SPIFFE_ENDPOINT_SOCKET="unix://$agent_socket" SPIFFE_TRUST_DOMAIN="$TRUST_DOMAIN" \
  "$AXESS_DIR/scripts/check-live-stores.sh" spire 2>&1 | tee -a "$suite_log"
status=${PIPESTATUS[0]}
set -e
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
for name in withdrawn steady; do
  if [ ! -e "$dir/deleted-$name" ]; then
    echo "ERROR: the suite passed without asking for the entry of $name to be deleted;" >&2
    echo "       the withdrawal it is there to see did not happen." >&2
    exit 1
  fi
done
echo "OK: the SPIRE Workload API suite passed against a live agent; both entries were deleted on request."
