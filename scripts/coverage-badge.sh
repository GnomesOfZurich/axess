#!/usr/bin/env bash
# axess: the coverage badge, written during release preparation and checked
# on the release pull request.
#
# main changes only by a release pull request, so CI cannot commit the badge
# after a merge as it once did. Instead release preparation measures line
# coverage on the release branch and commits the badge with the release, and
# the Coverage job, on a pull request into main, refuses a committed figure
# more than TOLERANCE points from the one it measured. The same rule as the
# version and license badges: a stale badge fails by name.
#
# TOLERANCE is one point because the two measurements are not the same run:
# the job measures on a Linux runner and preparation on a maintainer's
# machine, and code under `cfg(target_os)` and timing-dependent branches
# (retry, back-off and timeout paths) cover a few lines differently between
# them. One point leaves room for that and still fails a release whose
# tests lost or gained real coverage since the badge was written.
#
# Usage:
#   ./scripts/coverage-badge.sh measured        line coverage of the last
#                                               `cargo llvm-cov --no-report`
#                                               run, two decimals
#   ./scripts/coverage-badge.sh write [PCT]     write the badge for PCT (default:
#                                               measured), rounded to a whole percent
#   ./scripts/coverage-badge.sh check PCT       refuse when the committed badge
#                                               is more than TOLERANCE from PCT
#
#   --badge FILE  before the mode: read or write FILE instead of
#                 .github/badges/coverage.svg (the tests use it).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BADGE="$AXESS_DIR/.github/badges/coverage.svg"
TOLERANCE=1

usage() { sed -n '/^# Usage:/,/^#   *\.github/p' "$0" >&2; exit 2; }

if [ "${1:-}" = "--badge" ]; then
  [ $# -ge 2 ] || usage
  BADGE="$2"; shift 2
fi

is_pct() { [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]] && awk -v p="$1" 'BEGIN { exit !(p >= 0 && p <= 100) }'; }

measured() {
  (cd "$AXESS_DIR" && cargo llvm-cov report --json --summary-only) \
    | python3 -I -c 'import json, sys; print("%.2f" % json.load(sys.stdin)["data"][0]["totals"]["lines"]["percent"])'
}

badge_figure() {
  [ -f "$BADGE" ] || { echo "REFUSED: no coverage badge at $BADGE" >&2; exit 1; }
  local fig
  fig="$(grep -oE '>[0-9]+(\.[0-9]+)?%<' "$BADGE" | head -1 | tr -d '<>%')"
  [ -n "$fig" ] || { echo "REFUSED: $BADGE carries no percentage" >&2; exit 1; }
  printf '%s\n' "$fig"
}

case "${1:-}" in
  measured)
    measured ;;
  write)
    pct="${2:-$(measured)}"
    is_pct "$pct" || { echo "REFUSED: '$pct' is not a percentage" >&2; exit 1; }
    whole="$(awk -v p="$pct" 'BEGIN { printf "%d", p + 0.5 }')"
    if [ "$whole" -ge 80 ]; then color=brightgreen
    elif [ "$whole" -ge 60 ]; then color=yellow
    else color=red; fi
    "$SCRIPT_DIR/generate-badge.sh" coverage "${whole}%" "$color" "$BADGE"
    echo "Coverage badge: ${whole}% (measured ${pct}%), $color, written to $BADGE." ;;
  check)
    [ $# -ge 2 ] || usage
    pct="$2"
    is_pct "$pct" || { echo "REFUSED: '$pct' is not a percentage" >&2; exit 1; }
    fig="$(badge_figure)"
    if awk -v a="$fig" -v b="$pct" -v t="$TOLERANCE" 'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d > t) }'; then
      echo "REFUSED: the committed coverage badge says ${fig}% and this run measured ${pct}%, more than ${TOLERANCE} point apart." >&2
      echo "         Release preparation measures and commits it: docs/project/publishing.md, \"Release preparation\"." >&2
      exit 1
    fi
    echo "OK: the committed coverage badge (${fig}%) is within ${TOLERANCE} point of the measured ${pct}%." ;;
  *)
    usage ;;
esac
