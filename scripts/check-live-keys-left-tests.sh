#!/usr/bin/env bash
# axess: crafted cases for scripts/live-keys-left.sh.
#
# The check asks real servers; here it asks a stand-in valkey-cli, first on
# the PATH, that answers from files: the keys of each port, the CLUSTER
# NODES reply, and which ports answer at all. Each case lays those files out, runs the
# check with a token and asserts the exit status and a fragment of the
# output.
#
# Usage: ./scripts/check-live-keys-left-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-live-keys.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# The stand-in client: `-h HOST -p PORT ping | cluster nodes | --scan
# --count N --pattern GLOB`, answered from $FAKE_DIR. A port with no file
# `up-PORT` does not answer. The pattern is matched as a shell glob, which
# reads `*` as the server does; the cases' keys hold no other wildcard.
mkdir -p "$WORK/bin"
FAKE="$WORK/bin/valkey-cli"
cat > "$FAKE" <<'EOF'
#!/usr/bin/env bash
set -u
port=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h) shift 2 ;;
    -p) port="$2"; shift 2 ;;
    *) break ;;
  esac
done
[ -e "$FAKE_DIR/up-$port" ] || { echo "Could not connect" >&2; exit 1; }
case "$1" in
  ping) echo PONG ;;
  cluster) cat "$FAKE_DIR/nodes-$port" 2>/dev/null ;;
  --scan)
    pattern="$5"
    [ -e "$FAKE_DIR/keys-$port" ] || exit 0
    while IFS= read -r key; do
      # shellcheck disable=SC2053
      [[ "$key" == $pattern ]] && printf '%s\n' "$key"
    done < "$FAKE_DIR/keys-$port"
    ;;
esac
exit 0
EOF
chmod +x "$FAKE"

NODES='a1 127.0.0.1:7001@17001 myself,master - 0 0 1 connected 0-5460
b2 127.0.0.1:7002@17002 master - 0 0 2 connected 5461-10922
c3 127.0.0.1:7004@17004 slave b2 0 0 2 connected
d4 127.0.0.1:7003@17003 master - 0 0 3 connected 10923-16383'

# case NAME EXPECTED_EXIT FRAGMENT TOKEN [STEP...]: each STEP lays out the
# fresh fake directory, where every server is up and the cluster's nodes
# are listed: `key:PORT:NAME` adds a key (NAME may hold colons),
# `keys:PORT:COUNT:STEM` adds COUNT keys STEM1 to STEMCOUNT, `down:PORT`
# takes a server down, and `nonodes` empties the CLUSTER NODES reply.
case_() {
  local name="$1" want="$2" fragment="$3" token="$4"
  shift 4
  local dir="$WORK/case-$passed-$failed"
  mkdir -p "$dir"
  local p step rest port n
  for p in 6390 7001 7002 7003 7004; do : > "$dir/up-$p"; done
  printf '%s\n' "$NODES" > "$dir/nodes-7001"
  for step in "$@"; do
    case "$step" in
      key:*)
        rest="${step#key:}"; port="${rest%%:*}"
        printf '%s\n' "${rest#*:}" >> "$dir/keys-$port" ;;
      keys:*)
        rest="${step#keys:}"; port="${rest%%:*}"; rest="${rest#*:}"
        for n in $(seq 1 "${rest%%:*}"); do printf '%s%s\n' "${rest#*:}" "$n" >> "$dir/keys-$port"; done ;;
      down:*) rm -f "$dir/up-${step#down:}" ;;
      nonodes) : > "$dir/nodes-7001" ;;
      *) echo "unknown step $step" >&2; exit 2 ;;
    esac
  done
  local out rc
  out="$(FAKE_DIR="$dir" PATH="$WORK/bin:$PATH" VALKEY_URL=redis://127.0.0.1:6390 \
    VALKEY_CLUSTER_URL=redis-cluster://127.0.0.1:7001 \
    "$SCRIPT_DIR/live-keys-left.sh" "$token" 2>"$WORK/stderr")"
  rc=$?
  judge "$name" "$want" "$fragment" "$rc" "$out"
}

case_ "a run that left nothing passes" 0 "OK: the run r1 left no key on 4 server(s)." r1
case_ "a key of the run left on the node is refused" 1 "6390 axt_r1_cas_0f:dev" r1 \
  key:6390:axt_r1_cas_0f:dev
case_ "a key of the run on one primary alone is found: every primary is asked" 1 \
  "127.0.0.1:7003 axt_r1_dc_ab:row" r1 key:7003:axt_r1_dc_ab:row
case_ "a key inside a hash tag is the run's" 1 "{axt_r1_dcl_ab_3}:row" r1 \
  'key:7002:{axt_r1_dcl_ab_3}:row'
case_ "a key with text before the prefix is the run's" 1 "https://idp/{axt_r1_names_ab}" r1 \
  'key:7001:{axess}:v2:sid:22:https://idp/{axt_r1_names_ab}:3:sid'
case_ "the count covers every key, past the twenty named" 1 "left 25 key(s)" r1 \
  keys:6390:25:axt_r1_t_
case_ "another run's keys are left alone" 0 "6390: 0 key(s) of run r1" r1 \
  key:6390:axt_r2_cas_0f:dev key:6390:axt_r12_cas_0f:dev 'key:7001:{axt_r10_dc}:row'
case_ "keys of no run are left alone" 0 "OK: the run r1 left no key" r1 \
  key:6390:axess:sess:x key:6390:axt_cas key:6390:axw_thousand_r1
case_ "a replica is not asked: its keys are its primary's" 0 "OK: the run r1 left no key on 4 server(s)." r1 \
  key:7004:axt_r1_copy
case_ "a node that does not answer is a refusal" 2 "REFUSED: 127.0.0.1:6390 (VALKEY_URL) does not answer." r1 \
  down:6390
case_ "a primary that does not answer is a refusal" 2 "REFUSED: 127.0.0.1:7002 does not answer." r1 \
  down:7002
case_ "a cluster that names no primary is a refusal" 2 "names no primary in CLUSTER NODES" r1 nonodes
case_ "a token with an upper-case letter is refused" 2 "the token is 1 to 32 lowercase letters and digits" R1
case_ "a token with a wildcard is refused" 2 "the token is 1 to 32 lowercase letters and digits" 'r*'
case_ "an empty token is refused" 2 "the token is 1 to 32 lowercase letters and digits" ''

# The URLs: unset, and of another form, are refusals.
: > "$WORK/stderr"
out="$(PATH="$WORK/bin:$PATH" VALKEY_URL='' VALKEY_CLUSTER_URL=redis-cluster://127.0.0.1:7001 \
  "$SCRIPT_DIR/live-keys-left.sh" r1 2>"$WORK/stderr")"
judge "an unset node URL is a refusal" 2 "REFUSED: VALKEY_URL is unset" $? "$out"
out="$(PATH="$WORK/bin:$PATH" VALKEY_URL=valkey.example.org VALKEY_CLUSTER_URL=redis-cluster://127.0.0.1:7001 \
  "$SCRIPT_DIR/live-keys-left.sh" r1 2>"$WORK/stderr")"
judge "a node URL without a scheme is a refusal" 2 "is not a URL of the form" $? "$out"
# With no client on the PATH: the system directories only, where a host
# that keeps one there leaves the case out.
if PATH=/usr/bin:/bin command -v valkey-cli >/dev/null 2>&1 \
  || PATH=/usr/bin:/bin command -v redis-cli >/dev/null 2>&1; then
  echo "note: a client in /usr/bin or /bin; the case of no client is left out"
else
  out="$(PATH=/usr/bin:/bin VALKEY_URL=redis://127.0.0.1:6390 \
    VALKEY_CLUSTER_URL=redis-cluster://127.0.0.1:7001 \
    "$SCRIPT_DIR/live-keys-left.sh" r1 2>"$WORK/stderr")"
  judge "no client to ask with is a refusal" 2 "REFUSED: no valkey-cli or redis-cli" $? "$out"
fi
out="$("$SCRIPT_DIR/live-keys-left.sh" 2>"$WORK/stderr")"
judge "a call without a token is refused" 2 "usage:" $? "$out"

echo "check-live-keys-left tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
