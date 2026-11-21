#!/usr/bin/env bash
# axess: crafted cases for scripts/check-live-sweeps.sh.
#
# Each case writes Rust files (and, where it says so, an exemption list)
# under a temporary root beside a small sweep module of the shape the
# repository's has, runs the check against it with `--root`, and asserts
# the exit status and a fragment of the output. The refusals are the
# contract: a live Valkey test that builds its client and store by hand
# and holds no sweep is named by file, line and test; a test that holds a
# sweep directly, through a helper that returns one, through a type that
# holds one or through a runner that holds one while its closure runs
# passes; a call the check cannot place, a sweep named only in a comment
# or a string, and a helper that drops its sweep before it returns are not
# taken as a sweep; and an exemption list entry with no reason, for a test
# that is not there or for one that holds a sweep is refused.
#
# Usage: ./scripts/check-live-sweeps-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-live-sweeps.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-live-sweeps.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# The sweep module the cases' tests call, in the shape of
# axess-core/src/testing/valkey_sweep.rs.
SWEEP='pub struct KeySweep { prefix: String }
pub struct Swept<T> { held: T, sweep: KeySweep }
impl KeySweep {
    pub fn node(url: &str, tag: &str) -> Self { todo!() }
    pub fn prefix(&self) -> &str { &self.prefix }
    pub fn hold<T>(self, value: T) -> Swept<T> { todo!() }
}
pub fn on_node(tag: &str) -> KeySweep { KeySweep::node("redis://", tag) }'
NODE='#[ignore = "requires a running Valkey (VALKEY_URL)"]'
CLUSTER='#[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]'

# The test the gate exists for: a client and a store built by hand, keys
# written under a prefix no sweep made.
BY_HAND="use fred::prelude::*;
#[tokio::test]
$NODE
async fn writes_without_a_sweep() {
    let client = Client::new(Config::from_url(\"redis://127.0.0.1:6390\").unwrap(), None, None, None);
    client.init().await.unwrap();
    let store = ValkeyStore::new(client).with_prefix(\"axt_mine\");
    store.save(\"k\").await.unwrap();
}"

# case NAME EXPECTED_EXIT FRAGMENT [UNWANTED] -- FILE CONTENT [FILE CONTENT...]
# The exemption list is written with no entry unless a case writes its own.
case_() {
  local name="$1" want="$2" fragment="$3" unwanted=""
  shift 3
  if [ "$1" != "--" ]; then unwanted="$1"; shift; fi
  shift
  local root="$WORK/$passed-$failed"
  mkdir -p "$root/scripts" "$root/a/src/testing"
  printf '# no entries\n' > "$root/scripts/live-sweep-exemptions.txt"
  printf '%s\n' "$SWEEP" > "$root/a/src/testing/valkey_sweep.rs"
  while [ $# -gt 0 ]; do
    mkdir -p "$root/$(dirname "$1")"
    printf '%s\n' "$2" > "$root/$1"
    shift 2
  done
  local out status
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out" "$unwanted"
}

# A test of each reason, holding a sweep the plainest way.
held() {
  printf '#[tokio::test]\n%s\nasync fn %s() {\n    let sweep = KeySweep::node("redis://", "t");\n}\n' "$1" "$2"
}

case_ "a test that builds its client by hand and holds no sweep is refused" 1 \
  "a/src/store/tests.rs:3: writes_without_a_sweep is a live Valkey test that holds no sweep" -- \
  a/src/store/tests.rs "$BY_HAND"
case_ "the refusal counts the tests refused" 1 "1 live test(s) refused, 0 error(s)" -- \
  a/src/store/tests.rs "$BY_HAND"
case_ "a test that makes a sweep passes" 0 "ok: 1 of 1 live Valkey test(s) hold a sweep, 0 exempted" -- \
  a/src/store/tests.rs "$(held "$NODE" one)"
case_ "a cluster test is a live test" 1 "a/src/store/tests.rs:2: on_the_cluster is a live Valkey test" -- \
  a/src/store/tests.rs "#[tokio::test]
$CLUSTER
async fn on_the_cluster() { let c = cluster_client().await; }"
case_ "any reason that names Valkey makes a live test" 1 "needs_a_server is a live Valkey test" -- \
  a/src/store/tests.rs '#[tokio::test]
#[ignore = "needs a valkey server running here"]
async fn needs_a_server() {}'
case_ "a test of another server is not read" 1 "ERROR: no live Valkey test read" -- \
  a/src/store/tests.rs '#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn on_postgres() {}'
case_ "no live test is no pass" 1 "ERROR: no live Valkey test read" -- \
  a/src/lib.rs 'fn a() {}'
case_ "an attribute between the reason and the function is read past" 0 "ok: 1 of 1" -- \
  a/src/store/tests.rs "#[tokio::test]
$NODE
#[serial]
pub(crate) async fn one() { let sweep = crate::testing::valkey_sweep::on_node(\"t\"); }"
case_ "a reason on no function it can read is refused" 1 \
  "a/src/store/tests.rs:3: an ignore reason that names Valkey on no function this check can read" -- \
  a/src/store/tests.rs "macro_rules! live { (\$name:ident) => {
#[tokio::test]
$NODE
async fn \$name() {}
} }"

# The sources of a sweep.
case_ "a module path to the sweep passes" 0 "ok: 1 of 1" -- \
  a/src/store/tests.rs "#[tokio::test]
$NODE
async fn one() { let s = crate::testing::valkey_sweep::on_node(\"t\"); }"
case_ "a helper that returns a Swept passes" 0 "ok: 2 of 2" -- \
  a/src/store/tests.rs "async fn store(tag: &str) -> Swept<ValkeyStore> {
    let sweep = on_node(tag);
    sweep.hold(ValkeyStore::new(client().await).with_prefix(sweep.prefix()))
}
#[tokio::test]
$NODE
async fn one() { let s = store(\"t\").await; }
#[tokio::test]
$NODE
async fn two() { let s = store::<()>(\"t\").await.clone(); }"
case_ "a helper that returns a tuple holding a Swept passes" 0 "ok: 1 of 1" -- \
  a/src/store/tests.rs "async fn seeded(tag: &str) -> (Swept<ValkeyStore>, u8) { todo!() }
#[tokio::test]
$NODE
async fn one() { let (s, n) = seeded(\"t\").await; }"
case_ "a type that holds a Swept, and its constructor returning Self, pass" 0 "ok: 1 of 1" -- \
  a/src/store/tests.rs "struct Sweep { prefix: Swept<String>, cluster: bool }
impl Sweep { fn node(tag: &str) -> Self { todo!() } }
#[tokio::test]
$NODE
async fn one() { contract(Sweep::node(\"t\")).await; }"
case_ "a type alias of a Swept passes" 0 "ok: 1 of 1" -- \
  a/src/store/tests.rs "type Held = Swept<ValkeyStore>;
fn store() -> Held { todo!() }
#[tokio::test]
$NODE
async fn one() { store(); }"
case_ "a runner that holds a sweep while its closure runs passes" 0 "ok: 1 of 1" -- \
  a/tests/live.rs "async fn swept<F, Fut>(body: F)
where
    F: FnOnce(String) -> Fut,
{
    let sweep = KeySweep::node(\"redis://\", \"former\");
    body(sweep.prefix().to_owned()).await;
}
#[tokio::test]
$NODE
async fn one() { swept(|run| async move { write(run).await }).await; }"
case_ "a runner that holds no sweep is not one" 1 "one is a live Valkey test that holds no sweep" -- \
  a/tests/live.rs "async fn with_user<F, Fut>(body: F) where F: FnOnce(Client) -> Fut {
    body(connect().await).await;
}
#[tokio::test]
$NODE
async fn one() { with_user(|c| async move { c.set(\"k\").await }).await; }"
case_ "a helper in another file is found" 0 "ok: 1 of 1" -- \
  a/src/store/live.rs "pub(super) async fn live_store(tag: &str) -> Swept<ValkeyStore> { todo!() }" \
  a/src/store/tests.rs "#[tokio::test]
$NODE
async fn one() { let s = live_store(\"t\").await; }"

# What is not a sweep: the rule fails closed.
case_ "a helper that drops its sweep before it returns is not one" 1 "one is a live Valkey test that holds no sweep" -- \
  a/src/store/tests.rs "async fn store(tag: &str) -> ValkeyStore {
    let sweep = on_node(tag);
    ValkeyStore::new(client().await).with_prefix(sweep.prefix())
}
#[tokio::test]
$NODE
async fn one() { let s = store(\"t\").await; }"
case_ "a constructor returning Self of a type that holds no sweep is not one" 1 "one is a live Valkey test that holds no sweep" -- \
  a/src/store/tests.rs "struct Store { prefix: String }
impl Store { fn new() -> Self { todo!() } }
#[tokio::test]
$NODE
async fn one() { let s = Store::new(); }"
case_ "a method call is not a source" 1 "one is a live Valkey test that holds no sweep" -- \
  a/src/store/tests.rs "#[tokio::test]
$NODE
async fn one() { let s = maker.on_node(\"t\"); }"
case_ "a sweep named in a comment or a string is not one" 1 "one is a live Valkey test that holds no sweep" -- \
  a/src/store/tests.rs "#[tokio::test]
$NODE
async fn one() {
    // let sweep = on_node(\"t\");
    let text = \"on_node(x)\";
}"
case_ "the test's own file decides a name it declares" 1 "one is a live Valkey test that holds no sweep" -- \
  a/src/other.rs "pub fn store() -> Swept<ValkeyStore> { todo!() }" \
  a/src/store/tests.rs "fn store() -> ValkeyStore { todo!() }
#[tokio::test]
$NODE
async fn one() { store(); }"
case_ "a sweep the test's own file declares is its, whatever another file declares" 0 "ok: 1 of 1" -- \
  a/src/other.rs "pub fn store() -> ValkeyStore { todo!() }" \
  a/src/store/tests.rs "fn store() -> Swept<ValkeyStore> { todo!() }
#[tokio::test]
$NODE
async fn one() { store(); }"
case_ "a name two other files answer differently is not placed" 1 "one is a live Valkey test that holds no sweep" -- \
  a/src/first.rs "pub fn store() -> Swept<ValkeyStore> { todo!() }" \
  a/src/second.rs "pub fn store() -> ValkeyStore { todo!() }" \
  a/src/store/tests.rs "#[tokio::test]
$NODE
async fn one() { store(); }"
case_ "a module path to a file without the sweep is not one" 1 "one is a live Valkey test that holds no sweep" -- \
  a/src/other.rs "pub fn on_node(tag: &str) -> Client { todo!() }" \
  a/src/store/tests.rs "#[tokio::test]
$NODE
async fn one() { other::on_node(\"t\"); }"
case_ "a call no declaration answers is not one" 1 "one is a live Valkey test that holds no sweep" -- \
  a/src/store/tests.rs "#[tokio::test]
$NODE
async fn one() { let s = sweep_from_nowhere(\"t\"); }"

# The exemption list.
EXEMPT="# Publishes on channels of its own run and writes no key.
test	a/src/store/tests.rs	writes_without_a_sweep"
case_ "an exempted test with a reason passes" 0 "ok: 0 of 1 live Valkey test(s) hold a sweep, 1 exempted with a reason" -- \
  a/src/store/tests.rs "$BY_HAND" scripts/live-sweep-exemptions.txt "$EXEMPT"
case_ "an entry with no reason is refused" 1 \
  "scripts/live-sweep-exemptions.txt:1: an exemption with no comment above it that gives its reason" -- \
  a/src/store/tests.rs "$BY_HAND" scripts/live-sweep-exemptions.txt "test	a/src/store/tests.rs	writes_without_a_sweep"
case_ "a blank line ends a reason" 1 "scripts/live-sweep-exemptions.txt:3: an exemption with no comment above it" -- \
  a/src/store/tests.rs "$BY_HAND" scripts/live-sweep-exemptions.txt "# A reason for nothing below.

test	a/src/store/tests.rs	writes_without_a_sweep"
case_ "an entry for a test that is not there is refused" 1 \
  "scripts/live-sweep-exemptions.txt:2: a/src/store/tests.rs gone is not a live Valkey test; remove the entry" -- \
  a/src/store/tests.rs "$(held "$NODE" one)" scripts/live-sweep-exemptions.txt "# A test that was removed.
test	a/src/store/tests.rs	gone"
case_ "an entry for a test that holds a sweep is refused" 1 \
  "scripts/live-sweep-exemptions.txt:2: a/src/store/tests.rs one holds a sweep; remove the entry" -- \
  a/src/store/tests.rs "$(held "$NODE" one)" scripts/live-sweep-exemptions.txt "# It held no sweep once.
test	a/src/store/tests.rs	one"
case_ "an entry named twice is refused" 1 "scripts/live-sweep-exemptions.txt:3: a/src/store/tests.rs writes_without_a_sweep is listed twice" -- \
  a/src/store/tests.rs "$BY_HAND" scripts/live-sweep-exemptions.txt "$EXEMPT
test	a/src/store/tests.rs	writes_without_a_sweep"
case_ "a line of another shape is refused" 1 "scripts/live-sweep-exemptions.txt:2: a line is a comment or" -- \
  a/src/store/tests.rs "$(held "$NODE" one)" scripts/live-sweep-exemptions.txt "# A reason.
allow	a/src/store/tests.rs	one"

if [ "$failed" -gt 0 ]; then
  echo "$failed of $((passed + failed)) case(s) failed." >&2
  exit 1
fi
echo "ok: $passed case(s)"
