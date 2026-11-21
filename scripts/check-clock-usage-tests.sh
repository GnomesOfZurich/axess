#!/usr/bin/env bash
# axess: crafted cases for scripts/check-clock-usage.sh.
#
# Each case writes Rust files, and sometimes a baseline, under a temporary
# root, runs the check against it with `--root`, and asserts the exit status
# and a fragment of the output. The refusals are the contract: every way of
# reading the wall clock or the monotonic clock that the gate names is a
# finding, in library code, in test code and in doc examples, with one read
# admitted: `SystemTime::now` in the body of `SystemClock`'s `now` in
# axess-clock; a test that builds a world builds every part on its clock,
# one clock per function.
#
# Usage: ./scripts/check-clock-usage-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-clock-usage.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-clock-usage.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case NAME EXPECTED_EXIT FRAGMENT -- FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3"
  shift 4
  local root="$WORK/$passed-$failed"
  while [ $# -gt 0 ]; do
    mkdir -p "$root/$(dirname "$1")"
    printf '%s\n' "$2" > "$root/$1"
    shift 2
  done
  local out status
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

refused() { # refused NAME LINE: one library line that must be a finding
  case_ "$1" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 2" -- \
    axess-core/src/a.rs "fn f() {
    let _ = $2;
}"
}
refused "a chrono Utc::now call is refused" "chrono::Utc::now()"
refused "a Local::now call is refused" "Local::now()"
refused "chrono's today is refused" "chrono::Utc::today()"
refused "Utc::now passed as a function is refused" "stamp.unwrap_or_else(Utc::now)"
refused "Utc::now through chrono::offset is refused" "chrono::offset::Utc::now()"
refused "SystemTime::now is refused" "std::time::SystemTime::now()"
refused "Instant::now is refused" "Instant::now()"
refused "std's Instant::now spelled in full is refused" "std::time::Instant::now()"
refused "Instant::now from a tokio import is refused" "time::Instant::now()"
refused "the time crate's now_utc is refused" "time::OffsetDateTime::now_utc()"
refused "the time crate's now_local is refused" "OffsetDateTime::now_local()"
refused "the time crate's UtcDateTime::now is refused" "time::UtcDateTime::now()"
refused "UtcDateTime::now imported by name is refused" "UtcDateTime::now()"
refused "UtcDateTime::now passed as a function is refused" "stamp.unwrap_or_else(UtcDateTime::now)"
refused "the time crate's Timestamp::now is refused" "time::Timestamp::now()"
refused "jiff's Timestamp::now is refused" "jiff::Timestamp::now()"
refused "jiff's Zoned::now is refused" "jiff::Zoned::now()"
refused "Zoned::now imported by name is refused" "Zoned::now()"
refused "jiff's read of the host's time zone is refused" "jiff::tz::TimeZone::system()"
refused "jiff's fallible read of the host's time zone is refused" "TimeZone::try_system()"
refused "the host's time zone passed as a function is refused" "zone.unwrap_or_else(TimeZone::system)"
refused "the time crate's current local offset is refused" "time::UtcOffset::current_local_offset()"
refused "the time crate's local offset at an instant is refused" "UtcOffset::local_offset_at(at)"
refused "the elapsed time since the epoch is refused" "UNIX_EPOCH.elapsed()"
refused "the epoch through SystemTime is refused" "SystemTime::UNIX_EPOCH.elapsed()"
refused "SystemTime::elapsed called as a function is refused" "SystemTime::elapsed(&t)"
case_ "a renamed Instant is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (Instant as Stopwatch)" -- \
  axess-core/src/a.rs 'use std::time::Instant as Stopwatch;
fn f() { let _ = Stopwatch::now(); }'
case_ "a type alias of a clock is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 1" -- \
  axess-core/src/a.rs 'type Wall = chrono::Utc;
fn f() { let _ = Wall::now(); }'
case_ "a type alias of a date passes" 0 "ok: scanned library code and test code" -- \
  axess-core/src/a.rs 'type Stamp = DateTime<Utc>;'
case_ "a renamed Zoned is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (Zoned as Here)" -- \
  axess-core/src/a.rs 'use jiff::Zoned as Here;
fn f() { let _ = Here::now(); }'
case_ "a renamed UtcDateTime is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (UtcDateTime as Wall)" -- \
  axess-core/src/a.rs 'use time::UtcDateTime as Wall;
fn f() { let _ = Wall::now(); }'
case_ "a time zone that is named or fixed passes" 0 "ok: scanned library code" -- \
  axess-core/src/a.rs 'fn f() {
    let _ = jiff::tz::TimeZone::UTC;
    let _ = jiff::tz::TimeZone::fixed(offset);
    let _ = jiff::tz::TimeZone::get(name);
}'
case_ "an instant built from its parts passes" 0 "ok: scanned library code" -- \
  axess-core/src/a.rs 'fn f() {
    let _ = time::UtcDateTime::new(date, time::Time::MIDNIGHT);
    let _ = time::UtcDateTime::from_unix_timestamp(0);
}'
# tokio's Instant is the monotonic clock a paused runtime moves
# (`tokio::time::pause`, `advance`): spelled in full, library code may read
# it. Imported by name it reads like std's.
case_ "tokio's Instant::now spelled in full passes in library code" 0 "ok: scanned library code" -- \
  axess-core/src/a.rs 'fn f() {
    let _ = tokio::time::Instant::now();
}'
case_ "a read in a string or a comment passes" 0 "ok: scanned library code" -- \
  axess-core/src/a.rs 'fn f() { let _ = "Utc::now()"; } // Instant::now()'
# axess-clock holds the clock: one read of the system clock, in the body of
# `SystemClock`'s `now`, and no other.
SYSTEM_CLOCK='pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_system_time(SystemTime::now())
    }
}'
case_ "the system clock's one read passes" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-clock/src/lib.rs "$SYSTEM_CLOCK"
case_ "the system clock's read spelled in full passes" 0 "ok: scanned library code" -- \
  axess-clock/src/lib.rs 'impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_system_time(std::time::SystemTime::now())
    }
}'
case_ "a second read in the system clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 5 (SystemTime::now)" -- \
  axess-clock/src/lib.rs 'impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let first = SystemTime::now();
        let _ = first;
        Timestamp::from_system_time(SystemTime::now())
    }
}'
case_ "two reads on the system clock's one line are refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 3" -- \
  axess-clock/src/lib.rs 'impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        later_of(SystemTime::now(), SystemTime::now())
    }
}'
case_ "another clock's read in the system clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 3 (Utc::now)" -- \
  axess-clock/src/lib.rs 'impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        from_chrono(Utc::now())
    }
}'
case_ "a read in another function of axess-clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 7 (SystemTime::now)" -- \
  axess-clock/src/lib.rs "$SYSTEM_CLOCK
fn f() { let _ = SystemTime::now(); }"
case_ "a read in another method of the system clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 2 (SystemTime::now)" -- \
  axess-clock/src/lib.rs 'impl SystemClock {
    pub fn started() -> Timestamp { Timestamp::from_system_time(SystemTime::now()) }
}'
case_ "the now of another clock in axess-clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 2 (SystemTime::now)" -- \
  axess-clock/src/lib.rs 'impl Clock for HostClock {
    fn now(&self) -> Timestamp { Timestamp::from_system_time(SystemTime::now()) }
}'
case_ "a mock that reads the system clock itself is refused" 1 "axess-clock/src/testing.rs: 1 clock finding(s) (allowed 0), at line(s) 2 (SystemTime::now)" -- \
  axess-clock/src/lib.rs "$SYSTEM_CLOCK" \
  axess-clock/src/testing.rs 'impl MockClock {
    pub fn now() -> Self { Self::at(Timestamp::from_system_time(SystemTime::now())) }
}'
case_ "a mock started at the system clock's reading passes" 0 "ok: scanned library code" -- \
  axess-clock/src/lib.rs "$SYSTEM_CLOCK" \
  axess-clock/src/testing.rs 'impl MockClock {
    pub fn now() -> Self { Self::at(SystemClock.now()) }
}'
case_ "any other clock read in axess-clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (Utc::now)" -- \
  axess-clock/src/lib.rs 'fn f() { let _ = Utc::now(); }'
case_ "the monotonic clock in axess-clock is refused" 1 "axess-clock/src/timestamp.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (Instant::now)" -- \
  axess-clock/src/timestamp.rs 'fn f() { let _ = Instant::now(); }'
case_ "axess-clock's tests name its clocks" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-clock/src/lib.rs "$SYSTEM_CLOCK
#[cfg(test)]
mod tests {
    fn t() { let _ = SystemClock.now(); let _ = MockClock::now(); }
}" \
  axess-clock/src/clock_tests.rs 'fn t() { let _ = SystemClock.now(); let _ = SystemTime::now(); }' \
  axess-clock/tests/t.rs 'fn t() { let _ = MockClock::now(); let _ = SystemClock; }'
# The mock's second public name: declared once in axess-clock, known to the
# rules everywhere, and the only renaming of a clock that passes.
ALIAS='#[cfg(any(test, feature = "testing"))]
pub use testing::MockClock as DeterministicClock;'
case_ "axess-clock's declared alias of its mock passes" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-clock/src/lib.rs "$SYSTEM_CLOCK
$ALIAS"
case_ "the alias declared twice in axess-clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 10 (MockClock as DeterministicClock)" -- \
  axess-clock/src/lib.rs "$SYSTEM_CLOCK
$ALIAS
$ALIAS"
case_ "another name for the mock in axess-clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (MockClock as FakeClock)" -- \
  axess-clock/src/lib.rs 'pub use testing::MockClock as FakeClock;'
case_ "the alias given to another clock in axess-clock is refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (SystemClock as DeterministicClock)" -- \
  axess-clock/src/lib.rs 'pub use SystemClock as DeterministicClock;'
case_ "the alias and a read on one line are refused" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 1" -- \
  axess-clock/src/lib.rs 'pub use testing::MockClock as DeterministicClock; fn f() { let _ = Utc::now(); }'
case_ "the alias declared in another crate is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (MockClock as DeterministicClock)" -- \
  axess-core/src/a.rs 'pub use testing::MockClock as DeterministicClock;'
case_ "a renaming of the alias is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (DeterministicClock as Fixed)" -- \
  axess-core/src/a.rs 'use axess_clock::DeterministicClock as Fixed;'
case_ "a mock started at the real time under the alias is refused in a test" 1 "axess-core/tests/a.rs: 1 clock finding(s) (allowed 0), at line(s) 2 (DeterministicClock::now)" -- \
  axess-core/tests/a.rs 'fn t() {
    let _ = DeterministicClock::now();
}'
case_ "a mock set to the reference instant under the alias passes in a test" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-core/tests/a.rs 'fn t() {
    let clock = DeterministicClock::at_reference();
    let _ = clock.now();
}'
case_ "a second clock built under the alias is refused" 1 "at line(s) 3 (a second clock in fn t)" -- \
  axess-core/tests/a.rs 'fn t() {
    let a = MockClock::at_reference();
    let b = DeterministicClock::at_reference();
}'
case_ "a doc example in axess-clock is held to the library rule" 1 "axess-clock/src/lib.rs: 1 clock finding(s) (allowed 0), at line(s) 2 (SystemTime::now)" -- \
  axess-clock/src/lib.rs "/// \`\`\`
/// let _ = std::time::SystemTime::now();
/// \`\`\`
$SYSTEM_CLOCK"
case_ "a doc example in axess-clock may name the system clock" 0 "ok: scanned library code" -- \
  axess-clock/src/lib.rs "/// \`\`\`
/// let _ = axess_clock::SystemClock.now();
/// \`\`\`
$SYSTEM_CLOCK"
case_ "the admitted read is of axess-clock alone" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 4 (SystemTime::now)" -- \
  axess-core/src/a.rs "$SYSTEM_CLOCK"
case_ "a bench, which times real work, passes" 0 "ok: scanned library code" -- \
  axess-cache/benches/b.rs 'fn f() { let _ = std::time::Instant::now(); }'
case_ "an example's own code is not scanned" 0 "ok: scanned library code" -- \
  examples/x/src/main.rs 'fn main() { let _ = Utc::now(); }'
case_ "a baselined read passes and a grown file fails" 1 "axess-core/src/b.rs: 2 clock finding(s) (allowed 1)" -- \
  scripts/clock-usage-baseline.txt 'axess-core/src/a.rs:1
axess-core/src/b.rs:1' \
  axess-core/src/a.rs 'fn f() { let _ = Utc::now(); }' \
  axess-core/src/b.rs 'fn f() {
    let _ = Utc::now();
    let _ = SystemTime::now();
}'
case_ "a file that shrank is reported" 0 "note: axess-core/src/a.rs now has 0 (baseline 1); run --bless" -- \
  scripts/clock-usage-baseline.txt 'axess-core/src/a.rs:1' \
  axess-core/src/a.rs 'fn f() {}'
case_ "a brace in a char literal inside a test module exempts nothing after it" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 6" -- \
  axess-core/src/a.rs "fn f() {}
#[cfg(test)]
mod tests {
    const OPEN: char = '{';
}
fn g() { let _ = Utc::now(); }"

# Test code inside src: a test module, a test file, a file its parent
# declares under cfg(test).
case_ "a read in a trailing test module is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 4 (Utc::now)" -- \
  axess-core/src/a.rs 'fn f() {}
#[cfg(test)]
mod tests {
    fn g() { let _ = Utc::now(); }
}'
case_ "a read in a file its parent declares under cfg(test) is refused" 1 "axess-core/src/a/pacing.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (Instant::now)" -- \
  axess-core/src/a.rs '#[cfg(test)]
mod pacing;' \
  axess-core/src/a/pacing.rs 'fn g() { let _ = Instant::now(); }'
case_ "a read in a test module directory inside src is refused" 1 "axess-core/src/a/tests/b.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (MockClock::now)" -- \
  axess-core/src/a/tests/b.rs 'fn t() { let _ = MockClock::now(); }'
case_ "tokio's Instant::now in a test is refused" 1 "axess-core/src/a_tests.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (Instant::now)" -- \
  axess-core/src/a_tests.rs 'fn t() { let _ = tokio::time::Instant::now(); }'
case_ "the system clock in a unit test is refused" 1 "axess-core/src/tests.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (SystemClock)" -- \
  axess-core/src/tests.rs 'fn t() { let _ = Arc::new(SystemClock); }'
case_ "a stopwatch over real work passes in a test" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-core/src/tests.rs 'fn t() { let watch = Stopwatch::start(); let _ = watch.elapsed(); }'
case_ "a mock started at the real time in library code is not the test rule" 0 "ok: scanned library code" -- \
  axess-core/src/a.rs 'fn f() { let _ = MockClock::now(); }'

# Doc examples are compiled and run as tests, and teach what adopters copy.
case_ "a read in a doc example is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 3 (Utc::now)" -- \
  axess-core/src/a.rs '/// Stamp it.
/// ```
/// let now = chrono::Utc::now();
/// ```
fn f() {}'
case_ "a read in an ignored doc example is refused" 1 "axess-core/src/a.rs: 1 clock finding(s) (allowed 0), at line(s) 2 (Utc::now)" -- \
  axess-core/src/a.rs '//! ```rust,ignore
//! let now = Utc::now();
//! ```'
case_ "a read in a text block of a doc comment passes" 0 "ok: scanned library code" -- \
  axess-core/src/a.rs '/// ```text
/// Utc::now()
/// ```
fn f() {}'
case_ "the system clock in a doc example passes" 0 "ok: scanned library code" -- \
  axess-core/src/a.rs '/// ```
/// let now = SystemClock.now();
/// ```
fn f() {}'

test_refused() { # test_refused NAME PATH LINE: one line of an integration test that must be a finding
  case_ "$1" 1 "$2: 1 clock finding(s) (allowed 0), at line(s) 2" -- \
    "$2" "fn t() {
    let _ = $3;
}"
}
test_refused "a Utc::now call in an integration test is refused" axess-core/tests/a.rs "Utc::now()"
test_refused "SystemTime::now in an integration test is refused" axess-core/tests/a.rs "std::time::SystemTime::now()"
test_refused "a mock started at the real time in an integration test is refused" axess-core/tests/a.rs "MockClock::now()"
test_refused "the system clock in an integration test is refused" axess-core/tests/a.rs "SystemClock.now()"
test_refused "tokio's Instant::now in an integration test is refused" axess-core/tests/a.rs "tokio::time::Instant::now()"
test_refused "the epoch's elapsed time in an integration test is refused" axess-core/tests/a.rs "UNIX_EPOCH.elapsed()"
test_refused "the time crate's now_utc in an integration test is refused" axess-core/tests/a.rs "time::OffsetDateTime::now_utc()"
test_refused "the time crate's UtcDateTime::now in an integration test is refused" axess-core/tests/a.rs "time::UtcDateTime::now()"
test_refused "the time crate's local offset in an integration test is refused" axess-core/tests/a.rs "UtcOffset::current_local_offset()"
test_refused "jiff's Timestamp::now in an integration test is refused" axess-core/tests/a.rs "jiff::Timestamp::now()"
test_refused "jiff's Zoned::now in an integration test is refused" axess-core/tests/a.rs "jiff::Zoned::now()"
test_refused "jiff's read of the host's time zone in an integration test is refused" axess-core/tests/a.rs "jiff::tz::TimeZone::system()"
test_refused "a read in a test fixture module is refused" axess-core/tests/fixture/mod.rs "Utc::now()"
test_refused "a read in an example's integration test is refused" examples/sqlite/tests/a.rs "Utc::now()"
case_ "a renamed import of the system clock in an integration test is refused" 1 "axess-core/tests/a.rs: 1 clock finding(s) (allowed 0), at line(s) 1" -- \
  axess-core/tests/a.rs 'use axess_clock::SystemClock as Real;
fn t() { let _ = Real; }'
case_ "a read under cfg(test) in an integration test is refused" 1 "axess-core/tests/a.rs: 1 clock finding(s) (allowed 0), at line(s) 3" -- \
  axess-core/tests/a.rs '#[cfg(test)]
mod inner {
    fn t() { let _ = Utc::now(); }
}'
case_ "a mock set to the reference instant passes in an integration test" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-core/tests/a.rs 'fn t() {
    let clock = MockClock::at_reference();
    let _ = clock.now();
}'
case_ "an integration test read listed in the tests baseline passes" 0 "1 baselined clock finding(s) in 1 file(s)" -- \
  scripts/clock-usage-tests-baseline.txt 'axess-core/tests/a.rs:1' \
  axess-core/tests/a.rs 'fn t() { let _ = Utc::now(); }'
case_ "an integration test read listed in the library baseline fails" 1 "axess-core/tests/a.rs: 1 clock finding(s) (allowed 0)" -- \
  scripts/clock-usage-baseline.txt 'axess-core/tests/a.rs:1' \
  axess-core/tests/a.rs 'fn t() { let _ = Utc::now(); }'

# A world test builds every part on the test's clock. The library below
# has a store built on the system clock unless a chain sets another, and
# helpers that hand one out.
STORE='pub struct Store { clock: Arc<dyn Clock> }
impl Store {
    pub fn new() -> Self { Self { clock: Arc::new(SystemClock) } }
    pub fn try_new(ok: bool) -> Result<Self, String> { if ok { Ok(Self::new()) } else { Err("no".into()) } }
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self { self.clock = clock; self }
}
pub fn store() -> Store { Store::new() }
pub fn shared_store() -> Arc<Store> { Arc::new(Store::new()) }
pub fn store_on(clock: Arc<dyn Clock>) -> Store { Store::new().with_clock(clock) }'
world() { # world NAME EXIT FRAGMENT TEST: the test body against the library above
  case_ "$1" "$2" "$3" -- axess-core/src/store.rs "$STORE" axess-core/tests/a.rs "$4"
}
world "a store built without its clock in an integration test is refused" 1 "axess-core/tests/a.rs: 1 clock finding(s) (allowed 0), at line(s) 2 (Store::new (its clock is not set in the chain))" 'fn t() {
    let _ = Store::new();
}'
world "a store built in an argument, without its clock, is refused" 1 "at line(s) 3 (Store::new (its clock is not set in the chain))" 'fn t() {
    let clock = test_clock();
    let _ = Arc::new(Store::new()).with_clock(Arc::new(clock));
}'
world "a store whose chain sets the clock passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let clock = test_clock();
    let _ = Store::new().with_clock(Arc::new(clock));
}'
world "a store unwrapped and then clocked passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let clock = test_clock();
    let _ = Store::try_new(true).expect("built").with_clock(Arc::new(clock));
}'
world "a store clocked inside a map of its result passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let clock = test_clock();
    let _ = Store::try_new(true).map(|s| s.with_clock(Arc::new(clock))).and_then(check);
}'
world "a refused construction passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let Err(e) = Store::try_new(false) else { panic!() };
    assert!(Store::try_new(false).is_err());
}'
world "a helper that hands out a system-clock store is refused" 1 "at line(s) 2 (store (its clock is not set in the chain))" 'fn t() {
    let _ = store();
}'
world "a helper whose store no chain can reach is refused" 1 "at line(s) 2 (shared_store (a system-clock form))" 'fn t() {
    let _ = shared_store().clone();
}'
world "the clocked helper passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let clock = test_clock();
    let _ = store_on(Arc::new(clock));
}'
world "a test function of the same name as a helper passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn store() -> u8 { 1 }
fn t() { let _ = store(); }'
world "a second clock in one test function is refused" 1 "at line(s) 3 (a second clock in fn t)" 'fn t() {
    let a = test_clock();
    let b = MockClock::at_reference();
}'
world "a second clock from a helper of the tests is refused" 1 "at line(s) 4 (a second clock in fn t)" 'fn frozen_clock() -> MockClock { MockClock::at_reference() }
fn t() {
    let a = frozen_clock();
    let b = frozen_clock();
}'
world "one clock in each of two functions passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn first() { let clock = test_clock(); }
fn second() { let clock = test_clock(); }'
world "a clock from a helper beside one of the test's own is refused" 1 "at line(s) 4 (a second clock in fn t)" 'fn helper() -> MockClock { test_clock() }
fn t() {
    let clock = helper();
    let other = test_clock();
}'
world "a part a helper builds on a clock of its own is a second clock" 1 "at line(s) 4 (a second clock in fn t, built by seeded)" 'fn seeded() -> Store { Store::new().with_clock(Arc::new(test_clock())) }
fn t() {
    let clock = test_clock();
    let store = seeded();
}'
world "a part a helper builds on the clock it is handed passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn seeded(clock: &MockClock) -> Store { Store::new().with_clock(Arc::new(clock.clone())) }
fn t() {
    let clock = test_clock();
    let store = seeded(&clock);
}'
world "a helper that builds the world, clock and all, passes alone" 0 "ok: scanned library code and test code; 0 baselined" 'struct World { clock: MockClock, store: Store }
impl World {
    fn new() -> Self { let clock = test_clock(); Self { store: Store::new().with_clock(Arc::new(clock.clone())), clock } }
}
fn t() {
    let world = World::new();
    world.clock.advance_secs(1);
}'
world "a world from a helper beside a clock of the test's own is refused" 1 "at line(s) 7 (a second clock in fn t)" 'struct World { clock: MockClock }
impl World {
    fn new() -> Self { Self { clock: test_clock() } }
}
fn t() {
    let world = World::new();
    let clock = test_clock();
}'
world "two helpers that each build a clock make two clocks" 1 "at line(s) 4 (a second clock in fn t, built by two)" 'fn one() -> Store { Store::new().with_clock(Arc::new(test_clock())) }
fn two() -> Store { one() }
fn t() {
    let (a, b) = (one(), two());
}'
case_ "a clock a declared fixture module builds counts in the test that calls it" 1 "axess-core/tests/a.rs: 1 clock finding(s) (allowed 0), at line(s) 4 (a second clock in fn t, built by rig)" -- \
  axess-core/src/store.rs "$STORE" \
  axess-core/tests/fixture/mod.rs 'pub fn rig() -> Store { let clock = MockClock::at_reference(); Store::new().with_clock(Arc::new(clock)) }' \
  axess-core/tests/a.rs 'mod fixture;
fn t() {
    let clock = MockClock::at_reference();
    let store = fixture::rig();
}'
# A test binary kept as a directory: `main.rs` declares the modules, and a
# clock a sibling module builds counts in the test of another that calls it.
RIG='pub fn rig() -> Store { let clock = MockClock::at_reference(); Store::new().with_clock(Arc::new(clock)) }'
case_ "a clock a sibling module of a directory binary builds counts in the test that calls it" 1 "axess-core/tests/group/topic.rs: 1 clock finding(s) (allowed 0), at line(s) 4 (a second clock in fn t, built by rig)" -- \
  axess-core/src/store.rs "$STORE" \
  axess-core/tests/group/main.rs 'mod fixture;
mod topic;' \
  axess-core/tests/group/fixture.rs "$RIG" \
  axess-core/tests/group/topic.rs 'use super::fixture::*;
fn t() {
    let clock = MockClock::at_reference();
    let store = rig();
}'
case_ "called through the sibling's path too" 1 "axess-core/tests/group/topic.rs: 1 clock finding(s) (allowed 0), at line(s) 3 (a second clock in fn t, built by rig)" -- \
  axess-core/src/store.rs "$STORE" \
  axess-core/tests/group/main.rs 'mod fixture;
mod topic;' \
  axess-core/tests/group/fixture.rs "$RIG" \
  axess-core/tests/group/topic.rs 'fn t() {
    let clock = MockClock::at_reference();
    let store = super::fixture::rig();
}'
case_ "a test of a directory binary that takes its one clock from the sibling passes" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-core/src/store.rs "$STORE" \
  axess-core/tests/group/main.rs 'mod fixture;
mod topic;' \
  axess-core/tests/group/fixture.rs "$RIG" \
  axess-core/tests/group/topic.rs 'use super::fixture::*;
fn t() {
    let store = rig();
}'
case_ "a file beside a main.rs that does not declare the module is not read with it" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-core/src/store.rs "$STORE" \
  axess-core/tests/group/main.rs 'mod topic;' \
  axess-core/tests/group/fixture.rs "$RIG" \
  axess-core/tests/group/topic.rs 'fn rig() {}
fn t() {
    let clock = MockClock::at_reference();
    rig();
}'
case_ "a unit test inside src may build the store without its clock" 0 "ok: scanned library code and test code; 0 baselined" -- \
  axess-core/src/store.rs "$STORE" axess-core/src/store_tests.rs 'fn t() { let _ = Store::new(); }'
case_ "a unit test inside src may not use a helper no chain can clock" 1 "axess-core/src/store_tests.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (shared_store (a system-clock form))" -- \
  axess-core/src/store.rs "$STORE" axess-core/src/store_tests.rs 'fn t() { let _ = shared_store(); }'
case_ "an example's tests of its own application build a world" 1 "examples/x/src/tests.rs: 1 clock finding(s) (allowed 0), at line(s) 1 (Store::new (its clock is not set in the chain))" -- \
  axess-core/src/store.rs "$STORE" examples/x/src/tests.rs 'fn t() { let _ = Store::new(); }'

# A constructor's signature says whether it falls back to the system clock:
# one of a type a setter clocks, handed no clock and nothing that carries
# one, builds it on the default, wherever the body reaches it from. A
# helper that hands out what such a form built, or a value holding a clock
# built from it, is a form too.
WRAPPED='pub struct Inner { clock: Arc<dyn Clock> }
impl Inner {
    pub fn new() -> Self { Self { clock: Arc::new(SystemClock) } }
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self { self.clock = clock; self }
}
pub struct Wrapper { inner: Inner }
impl Default for Wrapper {
    fn default() -> Self { Self { inner: Inner::new() } }
}
impl Wrapper {
    pub fn new() -> Self { Self::default() }
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self { self.inner = self.inner.with_clock(clock); self }
}
pub struct Layer { inner: Wrapper }
impl Layer {
    pub fn over(inner: Wrapper) -> Self { Self { inner } }
    pub fn with_clock(self, clock: Arc<dyn Clock>) -> Self { Self { inner: self.inner.with_clock(clock) } }
}
pub struct Config;
pub struct Built<C: ?Sized = dyn Clock> { clock: Arc<C> }
pub struct Builder { clock: Arc<dyn Clock> }
impl Config {
    pub fn discover() -> Builder { Builder { clock: Arc::new(SystemClock) } }
}
impl Builder {
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self { self.clock = clock; self }
    pub fn build(self) -> Built { Built { clock: self.clock } }
}'
HELPERS='pub fn discovered() -> Builder { Config::discover() }
pub fn built() -> Built { discovered().build() }
pub fn built_on(clock: Arc<dyn Clock>) -> Built { discovered().with_clock(clock).build() }'
wrapped() { # wrapped NAME EXIT FRAGMENT TEST: the test body against the library above
  case_ "$1" "$2" "$3" -- axess-core/src/wrap.rs "$WRAPPED" axess-core/src/testing/helpers.rs "$HELPERS" \
    axess-core/tests/a.rs "$4"
}
wrapped "a constructor that reaches the system clock through another type's is refused" 1 "at line(s) 2 (Wrapper::new (its clock is not set in the chain))" 'fn t() {
    let _ = Wrapper::new();
}'
wrapped "a Default that reaches the system clock through another type's is refused" 1 "at line(s) 2 (Wrapper::default (its clock is not set in the chain))" 'fn t() {
    let _ = Wrapper::default();
}'
wrapped "a wrapping constructor whose chain sets the clock passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let clock = test_clock();
    let _ = Wrapper::new().with_clock(Arc::new(clock));
}'
wrapped "a constructor handed a part that carries a clock passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let clock = test_clock();
    let _ = Layer::over(Wrapper::new().with_clock(Arc::new(clock)));
}'
wrapped "a helper that hands out another type's system-clock builder is refused" 1 "at line(s) 2 (discovered (its clock is not set in the chain))" 'fn t() {
    let _ = discovered().build();
}'
wrapped "a helper whose builder chain sets the clock passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let clock = test_clock();
    let _ = discovered().with_clock(Arc::new(clock)).build();
}'
wrapped "a helper that builds a value holding a clock from a system-clock builder is refused" 1 "at line(s) 2 (built (a system-clock form))" 'fn t() {
    let _ = built();
}'
wrapped "the clocked sibling of that helper passes" 0 "ok: scanned library code and test code; 0 baselined" 'fn t() {
    let clock = test_clock();
    let _ = built_on(Arc::new(clock));
}'

# The gate as it runs on the repository, on the files git lists: a file not
# yet added is read, and a file the ignore rules name is not.
CLOCK_READ='fn f() {
    let _ = Instant::now();
}'
listed "$CHECK" "an untracked file is read" 1 "axess-core/src/new.rs: 1 clock finding(s) (allowed 0), at line(s) 2" "ignored.rs" \
  axess-core/src/new.rs "$CLOCK_READ" axess-core/src/ignored.rs "$CLOCK_READ"
listed "$CHECK" "an ignored file is not read" 0 "ok: scanned library code and test code; 0 baselined" "ignored.rs" \
  axess-core/src/a.rs 'fn f() {}' axess-core/src/ignored.rs "$CLOCK_READ"

echo "check-clock-usage tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
