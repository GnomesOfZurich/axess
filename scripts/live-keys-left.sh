#!/usr/bin/env bash
# axess: a run of the live Valkey tests left no key behind.
#
# Every live Valkey test writes under a prefix that
# axess_core::testing::valkey_sweep makes, and removes every key whose name
# holds that prefix when the test ends, passed or failed. Each prefix holds
# the run's token: `axt_<token>_<test>_<random>`, where the token is
# AXESS_TEST_RUN as the run had it. So after a run, a key whose name holds
# `axt_<token>_` is one that run wrote and did not remove. This asks the
# single node and every primary of the cluster for such keys and refuses
# when there is one, naming the first twenty.
#
# It asks for the run's own token, not for every test prefix: the servers
# are shared, and a run beside this one has keys of its own while it runs.
#
# A server that does not answer is a refusal, not a pass: a check that
# could not ask has not found the keys gone.
#
# Usage: ./scripts/live-keys-left.sh TOKEN
#   TOKEN               the run's AXESS_TEST_RUN: 1 to 32 lowercase letters
#                       and digits
#   VALKEY_URL          the single node, redis://[user[:password]@]host:port
#   VALKEY_CLUSTER_URL  a node of the cluster, redis-cluster://host:port
#   VALKEY_CLI_CONTAINER  a container whose valkey-cli asks, by
#                       `docker exec`; unset, the valkey-cli on the PATH
#                       asks, or redis-cli where only that is installed. CI
#                       names the cluster's container, which runs on the
#                       host network and so reaches every server.
#
# scripts/check-live-stores.sh sets the token, runs the live suites and then
# this. scripts/check-live-keys-left-tests.sh holds its crafted cases.
set -uo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 TOKEN" >&2
  exit 2
fi
token="$1"
if ! [[ "$token" =~ ^[a-z0-9]{1,32}$ ]]; then
  echo "REFUSED: the token is 1 to 32 lowercase letters and digits, not '$token'." >&2
  exit 2
fi

if [ -n "${VALKEY_CLI_CONTAINER:-}" ]; then
  client=container
elif command -v valkey-cli >/dev/null 2>&1; then
  client=valkey-cli
elif command -v redis-cli >/dev/null 2>&1; then
  client=redis-cli
else
  echo "REFUSED: no valkey-cli or redis-cli to ask the servers with; install one, or name a container that has one in VALKEY_CLI_CONTAINER." >&2
  exit 2
fi

# ask ARG...: the client chosen above, with ARG.
ask() {
  case "$client" in
    container) docker exec "$VALKEY_CLI_CONTAINER" valkey-cli "$@" ;;
    valkey-cli) valkey-cli "$@" ;;
    *) redis-cli "$@" ;;
  esac
}

# The host and port of a redis:// or redis-cluster:// URL, as "host port".
host_port() {
  if [[ "$1" =~ ^redis(-cluster)?://([^@/]*@)?([^:/@]+):([0-9]+)(/.*)?$ ]]; then
    echo "${BASH_REMATCH[3]} ${BASH_REMATCH[4]}"
    return 0
  fi
  return 1
}

servers=()
for name in VALKEY_URL VALKEY_CLUSTER_URL; do
  url="${!name:-}"
  if [ -z "$url" ]; then
    echo "REFUSED: $name is unset; every server the run used is asked." >&2
    exit 2
  fi
  if ! hp="$(host_port "$url")"; then
    echo "REFUSED: $name is not a URL of the form scheme://host:port: '$url'." >&2
    exit 2
  fi
  read -r host port <<<"$hp"
  if [ "$(ask -h "$host" -p "$port" ping 2>/dev/null)" != PONG ]; then
    echo "REFUSED: $host:$port ($name) does not answer." >&2
    exit 2
  fi
  if [ "$name" = VALKEY_URL ]; then
    servers+=("$host:$port")
    continue
  fi
  # Every primary of the cluster: the keys of a slot are on its primary.
  nodes="$(ask -h "$host" -p "$port" cluster nodes 2>/dev/null)"
  primaries="$(awk '$3 ~ /master/ { split($2, a, "@"); print a[1] }' <<<"$nodes")"
  if [ -z "$primaries" ]; then
    echo "REFUSED: $host:$port ($name) names no primary in CLUSTER NODES." >&2
    exit 2
  fi
  while IFS= read -r primary; do
    servers+=("$primary")
  done <<<"$primaries"
done

pattern="*axt_${token}_*"
left=0
listed=()
for server in "${servers[@]}"; do
  host="${server%:*}"
  port="${server##*:}"
  if [ "$(ask -h "$host" -p "$port" ping 2>/dev/null)" != PONG ]; then
    echo "REFUSED: $server does not answer." >&2
    exit 2
  fi
  found="$(ask -h "$host" -p "$port" --scan --count 1000 --pattern "$pattern")" || {
    echo "REFUSED: $server did not answer the scan." >&2
    exit 2
  }
  count=0
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    count=$((count + 1))
    [ "${#listed[@]}" -lt 20 ] && listed+=("$server $key")
  done <<<"$found"
  echo "$server: $count key(s) of run $token"
  left=$((left + count))
done

if [ "$left" -ne 0 ]; then
  echo "ERROR: the run $token left $left key(s) on the servers; a live test wrote outside its sweep or its sweep did not remove them:" >&2
  printf '  %s\n' "${listed[@]}" >&2
  exit 1
fi
echo "OK: the run $token left no key on ${#servers[@]} server(s)."
