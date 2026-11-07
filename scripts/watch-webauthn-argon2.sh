#!/usr/bin/env bash
# axess: does webauthn-rs still reach argon2 0.5 through crypto-glue?
#
# A build with `fido2` carries argon2, password-hash and blake2 twice: axess
# uses argon2 0.6, and webauthn-rs-core reaches 0.5 through crypto-glue. The
# second line goes when a crypto-glue release that webauthn-rs-core accepts
# leaves argon2 0.5. This reads crates.io and answers that question:
#
#   1. the newest stable webauthn-rs-core and its crypto-glue requirement;
#   2. the newest stable, unyanked crypto-glue that requirement admits;
#   3. that release's argon2 requirement.
#
# It reports `hit=true` when webauthn-rs-core no longer depends on crypto-glue,
# or crypto-glue no longer depends on argon2, or the argon2 requirement has
# left the 0.5 line; `hit=false` while the requirement is still 0.5. Both go to
# stdout and, under GitHub Actions, to $GITHUB_OUTPUT as `hit` and `summary`.
#
# It FAILS (exit 1) on a failed request, an empty answer or a requirement it
# cannot read, so a broken query is a red run and never a silent "no change".
#
# Usage: scripts/watch-webauthn-argon2.sh

set -euo pipefail

STUCK_LINE="0.5"
USER_AGENT="axess-upstream-watch (https://github.com/GnomesOfZurich/axess)"
API="https://crates.io/api/v1"

fail() {
  echo "watch-webauthn-argon2: $*" >&2
  exit 1
}

api() {
  curl --fail --silent --show-error --retry 3 --max-time 30 \
    --user-agent "$USER_AGENT" "$API/$1" || fail "request failed: $API/$1"
}

# The normal-kind requirement on `$2` in a dependencies answer `$1`, or empty
# when the crate is not a normal dependency. An answer with no dependencies
# at all is treated as a broken query, not as a dependency dropped.
requirement_on() {
  local answer=$1 crate=$2
  jq -e '.dependencies | length > 0' <<<"$answer" >/dev/null ||
    fail "empty dependency list in the answer for $crate"
  jq -r --arg c "$crate" \
    '[.dependencies[] | select(.crate_id == $c and .kind == "normal")][0].req // empty' \
    <<<"$answer"
}

# The release line a plain or caret requirement admits: `0.Y` for `^0.Y.Z`,
# `X` for `^X.Y.Z` with X above 0. Anything else is refused by name.
line_of() {
  local req=${1#^}
  [[ $req =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || fail "cannot read requirement '$1'"
  local major=${req%%.*} rest=${req#*.}
  if [ "$major" = "0" ]; then
    echo "0.${rest%%.*}"
  else
    echo "$major"
  fi
}

report() {
  local hit=$1 summary=$2
  echo "hit=$hit"
  echo "summary=$summary"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      echo "hit=$hit"
      echo "summary=$summary"
    } >>"$GITHUB_OUTPUT"
  fi
  exit 0
}

core=$(api crates/webauthn-rs-core | jq -er '.crate.max_stable_version // empty') ||
  fail "no stable webauthn-rs-core version in the answer"
core_deps=$(api "crates/webauthn-rs-core/$core/dependencies")
glue_req=$(requirement_on "$core_deps" crypto-glue)
[ -n "$glue_req" ] ||
  report true "webauthn-rs-core $core no longer depends on crypto-glue."

glue_line=$(line_of "$glue_req")
glue_min=${glue_req#^}
glue=$(api crates/crypto-glue | jq -er --arg line "$glue_line." --arg min "$glue_min" '
  def parts: split(".") | map(tonumber);
  [.versions[]
    | select(.yanked | not)
    | .num
    | select(startswith($line) and (contains("-") | not))
    | select(parts >= ($min | parts))]
  | sort_by(parts) | last // empty') ||
  fail "no stable crypto-glue release admitted by webauthn-rs-core $core's requirement $glue_req"

glue_deps=$(api "crates/crypto-glue/$glue/dependencies")
argon2_req=$(requirement_on "$glue_deps" argon2)
[ -n "$argon2_req" ] ||
  report true "crypto-glue $glue (admitted by webauthn-rs-core $core, $glue_req) no longer depends on argon2."

argon2_line=$(line_of "$argon2_req")
summary="webauthn-rs-core $core requires crypto-glue $glue_req; crypto-glue $glue requires argon2 $argon2_req."
if [ "$argon2_line" = "$STUCK_LINE" ]; then
  report false "$summary"
fi
report true "$summary"
