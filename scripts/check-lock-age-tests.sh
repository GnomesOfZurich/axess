#!/usr/bin/env bash
# axess: crafted cases for scripts/check-lock-age.sh.
#
# Each case builds a throwaway git repository under a temporary root (a
# .cargo/config.toml with the cooldown, a Cargo.lock and a fuzz/Cargo.lock,
# a release tag), makes the commits the case needs, runs the check on it
# against a local directory laid out like the crates.io sparse index, and
# asserts the exit status and a fragment of the output. The repository is
# removed when the case ends. Nothing here reaches the network: the one case
# of an unreachable index asks a closed port on this host.
#
# Publish times are written relative to the moment the cases run: OLD (thirty
# days ago), TEN (ten days ago) and YOUNG (three days ago).
#
# Usage: ./scripts/check-lock-age-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-lock-age.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-lock-age.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

passed=0
failed=0

stamp() {
  python3 -I -c 'import datetime, sys; print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"
}
OLD="$(stamp 30)"
TEN="$(stamp 10)"
YOUNG="$(stamp 3)"
REGISTRY='registry+https://github.com/rust-lang/crates.io-index'

# lock NAME VERSION [NAME VERSION...]: a lockfile of crates.io entries and the
# workspace's own crate, which has no source.
lock() {
  printf 'version = 4\n\n[[package]]\nname = "axess-core"\nversion = "0.20.0"\n'
  while [ $# -gt 0 ]; do
    printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "%s"\n' "$1" "$2" "$REGISTRY"
    shift 2
  done
}

# index_file NAME: the path of a crate's file in the index directory.
index_file() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case ${#lower} in
    1|2) echo "$INDEX/${#lower}/$lower" ;;
    3) echo "$INDEX/3/${lower:0:1}/$lower" ;;
    *) echo "$INDEX/${lower:0:2}/${lower:2:2}/$lower" ;;
  esac
}

# publish NAME VERSION [PUBTIME]: one line of the index; with no PUBTIME the
# line carries none.
publish() {
  local file
  file="$(index_file "$1")"
  mkdir -p "$(dirname "$file")"
  if [ $# -ge 3 ]; then
    printf '{"name":"%s","vers":"%s","deps":[],"cksum":"00","features":{},"yanked":false,"pubtime":"%s"}\n' "$1" "$2" "$3" >> "$file"
  else
    printf '{"name":"%s","vers":"%s","deps":[],"cksum":"00","features":{},"yanked":false}\n' "$1" "$2" >> "$file"
  fi
}

# The index every case reads unless it makes its own.
INDEX="$WORK/index"
publish serde 1.0.0 "$OLD"
publish serde 1.0.1 "$TEN"
publish serde 1.0.2 "$YOUNG"
publish serde 1.0.3 "$YOUNG"
publish serde 1.0.4
publish serde 1.0.5 "yesterday"
publish rand 0.8.0 "$OLD"
publish rand 0.9.0 "$YOUNG"
publish libc 0.2.0 "$OLD"
publish libc 0.2.1 "$YOUNG"
publish a 1.0.0 "$OLD"
publish ab 1.0.0 "$OLD"
publish abc 1.0.0 "$OLD"
publish Abcd 1.0.0 "$OLD"
mkdir -p "$INDEX/br/ok"
printf '{"name":"broken","vers":"1.0.0","pubtime":"%s"}\nnot json\n' "$OLD" > "$INDEX/br/ok/broken"
mkdir -p "$INDEX/tw/ic"
printf '{"name":"twice","vers":"1.0.0","pubtime":"%s"}\n{"name":"twice","vers":"1.0.0","pubtime":"%s"}\n' "$OLD" "$OLD" > "$INDEX/tw/ic/twice"
BASE_LOCK="$(lock serde 1.0.0 rand 0.8.0)"
FUZZ_LOCK="$(lock serde 1.0.0)"

# new_repo [AGE]: a repository at $REPO with both lockfiles and the tag
# v0.1.0, and at $CONFIG the cargo configuration the check is pointed at:
# the cooldown is seven days unless AGE is given, none when AGE is "-". (It
# lies outside the repository: nothing here writes a cargo configuration
# cargo would read.)
new_repo() {
  REPO="$WORK/repo-$passed-$failed"
  CONFIG="$WORK/config-$passed-$failed.toml"
  mkdir -p "$REPO/fuzz"
  git init -q -b main "$REPO"
  # An identity of its own and no signing, whatever this machine's user set.
  git -C "$REPO" config user.name cases
  git -C "$REPO" config user.email cases@example.org
  git -C "$REPO" config commit.gpgsign false
  git -C "$REPO" config tag.gpgsign false
  if [ "${1:-}" != "-" ]; then
    printf '[registry]\nglobal-min-publish-age = "%s"\n' "${1:-7 days}" > "$CONFIG"
  else
    printf '[build]\njobs = 2\n' > "$CONFIG"
  fi
  printf '%s\n' "$BASE_LOCK" > "$REPO/Cargo.lock"
  printf '%s\n' "$FUZZ_LOCK" > "$REPO/fuzz/Cargo.lock"
  git -C "$REPO" add -A
  git -C "$REPO" commit -q -m "base"
  git -C "$REPO" tag v0.1.0
}

# change FILE TEXT MESSAGE: one commit that writes TEXT to FILE.
change() {
  mkdir -p "$(dirname "$REPO/$1")"
  printf '%s\n' "$2" > "$REPO/$1"
  git -C "$REPO" add -A
  git -C "$REPO" commit -q --allow-empty -m "$3"
}

# verdict NAME WANTED_EXIT FRAGMENT [CHECK ARGS...]: run the check on $REPO,
# judge it and remove the repository.
verdict() {
  local name="$1" want="$2" fragment="$3"
  shift 3
  local out status
  out="$("$CHECK" --root "$REPO" --cargo-config "$CONFIG" --index "$INDEX" "$@" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$REPO" "$CONFIG"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

TRAILER_SERDE=$'bump serde\n\nCooldown-Exempt: RUSTSEC-2026-0001 serde'

# What passes.
new_repo; change x "" "nothing"
verdict "no lockfile change passes" 0 "OK: no lockfile gained a crates.io entry since v0.1.0"
new_repo; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
verdict "an entry ten days old passes" 0 "ok Cargo.lock: serde 1.0.1"
new_repo; change Cargo.lock "$(lock rand 0.8.0)" "drop serde"
verdict "a removed entry is not judged" 0 "OK: no lockfile gained"
new_repo; change Cargo.lock "$(lock serde 1.0.0 rand 0.8.0 a 1.0.0 ab 1.0.0 abc 1.0.0 Abcd 1.0.0)" "add four"
verdict "names of one to four letters are found where the index keeps them" 0 "ok Cargo.lock: Abcd 1.0.0"
new_repo
change Cargo.lock "$BASE_LOCK
[[package]]
name = \"local\"
version = \"0.1.0\"
source = \"git+https://example.org/local?rev=1#1\"" "a git dependency"
verdict "a git entry has no publish time and is not judged" 0 "OK: no lockfile gained"

# What the cooldown refuses.
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "bump serde"
verdict "an entry three days old is refused" 1 "REFUSED Cargo.lock: serde 1.0.2, published $YOUNG, is younger than 7 days"
new_repo; change fuzz/Cargo.lock "$(lock serde 1.0.2)" "bump serde in the fuzz lock"
verdict "a young entry of the fuzz lock is refused" 1 "REFUSED fuzz/Cargo.lock: serde 1.0.2"
new_repo; change fuzz/Cargo.lock "$(lock serde 1.0.0 libc 0.2.1)" "a fuzz-only crate"
verdict "a young crate only the fuzz lock holds is refused" 1 "REFUSED fuzz/Cargo.lock: libc 0.2.1"
new_repo; git -C "$REPO" rm -q --cached fuzz/Cargo.lock; git -C "$REPO" commit -q -m "untrack"; git -C "$REPO" tag v0.1.1
change fuzz/Cargo.lock "$(lock serde 1.0.0 rand 0.8.0)" "track the fuzz lock again"
verdict "a lockfile new since the base adds every entry it holds" 0 "ok fuzz/Cargo.lock: rand 0.8.0"
new_repo; change notes "x" "after the tag"; printf '%s\n' "$(lock serde 1.0.2 rand 0.8.0)" > "$REPO/Cargo.lock"
verdict "an uncommitted young entry is refused" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; change notes "x" "after the tag"; mkdir -p "$REPO/side"; printf '%s\n' "$(lock serde 1.0.2)" > "$REPO/side/Cargo.lock"
verdict "a young entry of a lockfile not yet added is refused" 1 "REFUSED side/Cargo.lock: serde 1.0.2"
new_repo; change .gitignore "ignored/" "ignore a directory"; mkdir -p "$REPO/ignored"; printf '%s\n' "$(lock serde 1.0.2)" > "$REPO/ignored/Cargo.lock"
verdict "a lockfile the ignore rules name is not judged" 0 "OK: no lockfile gained"
new_repo "2 weeks"; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
verdict "the age is the one the cargo configuration sets" 1 "serde 1.0.1, published $TEN, is younger than 2 weeks"

# The exception: a trailer of the commit that adds the entry.
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "$TRAILER_SERDE"
verdict "a young entry admitted by a RUSTSEC trailer naming its crate passes" 0 "admitted Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nCooldown-Exempt: GHSA-abcd-23fg-h4jk serde'
verdict "a GHSA trailer admits" 0 "admitted Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nCooldown-Exempt: CVE-2026-12345 serde'
verdict "a CVE trailer admits" 0 "admitted Cargo.lock: serde 1.0.2"
new_repo; change fuzz/Cargo.lock "$(lock serde 1.0.2)" "$TRAILER_SERDE"
verdict "a trailer admits a young entry of the fuzz lock" 0 "admitted fuzz/Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.9.0)" "$TRAILER_SERDE"
verdict "a trailer does not admit another young crate of the same commit" 1 "REFUSED Cargo.lock: rand 0.9.0"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nCooldown-Exempt: RUSTSEC-2026-0001 rand'
verdict "a trailer naming another crate admits nothing" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nCooldown-Exempt: RUSTSEC-2026-0001 Serde'
verdict "a trailer naming the crate in other case admits nothing" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "fix RUSTSEC-2026-0001 in serde"
verdict "an advisory id in the subject admits nothing" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nThis fixes RUSTSEC-2026-0001 in serde.'
verdict "an advisory id in prose admits nothing" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nCooldown-Exempt: RUSTSEC-2026-0001'
verdict "a trailer with no crate admits nothing and is named" 1 "a Cooldown-Exempt trailer that admits nothing (not \`<advisory id> <crate>\`): RUSTSEC-2026-0001"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nCooldown-Exempt: RUSTSEC-2026-0001 fixed in serde'
verdict "a trailer with words beside the id and the crate admits nothing" 1 "admits nothing (not \`<advisory id> <crate>\`): RUSTSEC-2026-0001 fixed in serde"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nCooldown-Exempt: RUSTSEC-26-1 serde'
verdict "a trailer whose id is malformed admits nothing" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" $'bump serde\n\nCooldown-Exempt: RUSTSEC-2026-0001 serde\n\nThe release notes follow.'
verdict "a trailer outside the last paragraph admits nothing" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "bump serde"; change notes "x" "$TRAILER_SERDE"
verdict "a trailer on a commit that does not change the lockfile admits nothing" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "$TRAILER_SERDE"; change Cargo.lock "$(lock serde 1.0.3 rand 0.8.0)" "bump serde again"
verdict "a trailer admits the version its commit adds, not a later one" 1 "REFUSED Cargo.lock: serde 1.0.3"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "bump serde"; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0 a 1.0.0)" "$TRAILER_SERDE"
verdict "a trailer does not admit an entry an earlier commit added" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo; git -C "$REPO" checkout -q -b side; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "$TRAILER_SERDE"
git -C "$REPO" checkout -q -; change notes "x" "beside"; git -C "$REPO" merge -q --no-edit side
verdict "a trailer on a merged branch's commit admits its entry" 0 "admitted Cargo.lock: serde 1.0.2"

# What cannot be read is refused.
new_repo; change Cargo.lock "$(lock serde 1.0.4 rand 0.8.0)" "bump serde"
verdict "an entry the index gives no publish time is refused" 1 "the index gives no publish time (pubtime) for serde 1.0.4"
new_repo; change Cargo.lock "$(lock serde 1.0.5 rand 0.8.0)" "bump serde"
verdict "a publish time that is not a time is refused" 1 "the publish time the index gives for serde 1.0.5 is not a time: yesterday"
new_repo; change Cargo.lock "$(lock serde 9.9.9 rand 0.8.0)" "bump serde"
verdict "a version the index does not list is refused" 1 "the index lists no version 9.9.9 of serde"
new_repo; change Cargo.lock "$(lock serde 1.0.0 rand 0.8.0 nosuch 1.0.0)" "a crate"
verdict "a crate the index does not list is refused" 1 "the index lists no crate nosuch"
new_repo; change Cargo.lock "$(lock serde 1.0.0 rand 0.8.0 broken 1.0.0)" "a crate"
verdict "an index file with a line that is not JSON is refused" 1 "the index file of broken is not read: line 2 is not a JSON object"
new_repo; change Cargo.lock "$(lock serde 1.0.0 rand 0.8.0 twice 1.0.0)" "a crate"
verdict "a version the index lists twice is refused" 1 "the index lists version 1.0.0 of twice 2 times"
new_repo; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
out="$("$CHECK" --root "$REPO" --cargo-config "$CONFIG" --index "https://127.0.0.1:9/" 2>"$WORK/stderr")"; status=$?; rm -rf "$REPO" "$CONFIG"
judge "an index that cannot be reached is refused" 1 "REFUSED Cargo.lock: serde 1.0.1: the index cannot be read for serde: https://127.0.0.1:9/se/rd/serde" "$status" "$out"
new_repo; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
out="$("$CHECK" --root "$REPO" --cargo-config "$CONFIG" --index "http://127.0.0.1:9/" 2>"$WORK/stderr")"; status=$?; rm -rf "$REPO" "$CONFIG"
judge "an index over plain http is refused" 1 "the index http://127.0.0.1:9/ is not read" "$status" "$out"
new_repo
change Cargo.lock "$BASE_LOCK
[[package]]
name = \"other\"
version = \"1.0.0\"
source = \"sparse+https://registry.example.org/index/\"" "another registry"
verdict "an entry of another registry is refused" 1 "other 1.0.0 comes from sparse+https://registry.example.org/index/, not crates.io"
new_repo; change Cargo.lock "[[package]
name = 1" "broken"
verdict "a lockfile that is not TOML is refused" 1 "Cargo.lock is not a lockfile this check reads"
new_repo; change notes "x" "after the tag"; rm "$REPO/fuzz/Cargo.lock"
verdict "a tracked lockfile missing from the tree is refused" 1 "fuzz/Cargo.lock cannot be read"

# The cargo configuration.
new_repo -; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
verdict "a configuration with no publish age is refused" 1 "sets no registry.global-min-publish-age, so there is no cooldown to hold"
new_repo 0; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
verdict "a publish age of 0 is refused" 1 "registry.global-min-publish-age is '0', which this check does not read"
new_repo "0 days"; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
verdict "a publish age of 0 days is refused" 1 "registry.global-min-publish-age is '0 days', which this check does not read"
new_repo "1 month"; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
verdict "a publish age in months is refused" 1 "registry.global-min-publish-age is '1 month', which this check does not read"
out="$(python3 -I -B "$SCRIPT_DIR/lib/lock_age.py" --repo "$SCRIPT_DIR/.." --print-age 2>"$WORK/stderr")"; status=$?
judge "this repository's configuration holds seven days" 0 "7 days (604800 seconds)" "$status" "$out"

# The base.
new_repo; git -C "$REPO" tag -d v0.1.0 >/dev/null; change Cargo.lock "$(lock serde 1.0.1 rand 0.8.0)" "bump serde"
verdict "no release tag below HEAD is refused and says how to give a base" 1 "name the base: "
new_repo; git -C "$REPO" tag -d v0.1.0 >/dev/null; base="$(git -C "$REPO" rev-parse HEAD)"; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "bump serde"
verdict "a base named on the command line is used" 1 "REFUSED Cargo.lock: serde 1.0.2" --base "$base"
new_repo; change Cargo.lock "$(lock serde 1.0.2 rand 0.8.0)" "bump serde"; git -C "$REPO" tag v0.2.0
verdict "a tag on HEAD is not its own base" 1 "REFUSED Cargo.lock: serde 1.0.2"
new_repo
verdict "a base that is not a commit is refused" 1 "the base 'no-such-ref' is not a commit" --base no-such-ref
new_repo; git -C "$REPO" rm -q -r Cargo.lock fuzz/Cargo.lock; git -C "$REPO" commit -q -m "remove the lockfiles"
verdict "a repository with no lockfile is refused" 1 "git lists no Cargo.lock"
out="$("$CHECK" --bogus 2>"$WORK/stderr")"; status=$?
judge "an unknown argument is a usage error" 2 "usage:" "$status" "$out"

echo "check-lock-age crafted cases: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
