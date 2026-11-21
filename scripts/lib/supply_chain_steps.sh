#!/usr/bin/env bash
# axess: how scripts/supply-chain.sh reports a step, and what it reads from
# cargo geiger. Sourced by that script and by its crafted cases
# (scripts/supply-chain-tests.sh), so the cases run the code the gate runs.
#
# A step ends one of three ways: OK; FAILED, and the gate exits 1; or, for a
# step that is informational unless STRICT=1, FAILED (informational): the
# tool was missing, failed or did not count every crate, the step's lines
# say which and why the gate does not stop on it, and the gate's exit status
# is left alone. A step never prints OK when its tool did not count, and the
# geiger step prints OK only after every crate's row, with the total of
# geiger's own warnings.
#
# The sourcing script holds the array FAILED.

# The status an informational step returns when its tool was missing, failed
# or counted nothing.
INFORMATIONAL_FAILURE=3

# step NAME CMD...: run CMD and print its outcome.
step() {
  local name="$1" rc
  shift
  echo "::group::$name"
  "$@"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "OK: $name"
  elif [ "$rc" -eq "$INFORMATIONAL_FAILURE" ]; then
    echo "::warning::FAILED (informational, the gate goes on): $name"
  else
    echo "::error::FAILED: $name"
    FAILED+=("$name")
  fi
  echo "::endgroup::"
}

have() { command -v "cargo-$1" >/dev/null 2>&1; }

# informational TOOL FUNCTION REASON: run FUNCTION, which fails when TOOL
# failed or counted nothing. Under STRICT=1 that fails the step and the gate;
# otherwise the step fails as informational, with REASON saying why the gate
# does not stop on it. A tool that is not installed is the same outcome,
# named as a skip.
informational() {
  local tool="$1" fn="$2" reason="$3"
  if ! have "$tool"; then
    if [ "${STRICT:-0}" = 1 ]; then
      echo "::error::cargo-$tool is not installed and STRICT=1 (cargo install --locked cargo-$tool)"
      return 1
    fi
    echo "::warning::SKIPPED: cargo-$tool is not installed (cargo install --locked cargo-$tool); nothing was counted. Informational: $reason. STRICT=1 makes it fatal."
    return "$INFORMATIONAL_FAILURE"
  fi
  if "$fn"; then return 0; fi
  if [ "${STRICT:-0}" = 1 ]; then return 1; fi
  echo "::warning::cargo-$tool failed or counted nothing (see above). Informational: $reason. STRICT=1 makes it fatal."
  return "$INFORMATIONAL_FAILURE"
}

# geiger_total_row OUTPUT: the crate's own total row of a
# `cargo geiger --output-format Ratio` report, the last row of ratios, or
# nothing when geiger counted nothing.
geiger_total_row() {
  grep -E '^ *[0-9]+/[0-9]+=[0-9.]+%  *[0-9]+/[0-9]+=' <<<"$1" | tail -1
}

# geiger_warnings ERROR_LINE: the number of warnings when ERROR_LINE is
# geiger's own summary of them ("error: Found 209 warnings"), which it ends
# a counted report with and exits 1 on; nothing otherwise.
geiger_warnings() {
  sed -nE 's/^error: Found ([0-9]+) warnings?$/\1/p' <<<"$1"
}

# geiger_crate CRATE OUTPUT STATUS: print CRATE's row, and count it. A crate
# is counted when its report holds its row and geiger exited 0, or exited
# after the row with only its summary of warnings, whose number is printed
# and added to GEIGER_WARNINGS. It is not counted, and the call fails, when
# the report holds no row (naming the last error geiger printed) or when
# geiger exited with any other error after the row (a file it cannot
# parse, say), naming the status.
geiger_crate() {
  local crate="$1" out="$2" status="$3" row why warnings
  row=$(geiger_total_row "$out")
  why=$(grep -E '^(error|Error)' <<<"$out" | tail -1)
  if [ -z "$row" ]; then
    echo "::error::$crate: cargo geiger counted nothing (exit $status): ${why:-no error line, and the report holds no row of ratios}"
    return 1
  fi
  echo "$crate: $row"
  if [ "$status" -eq 0 ]; then
    return 0
  fi
  warnings=$(geiger_warnings "$why")
  if [ -n "$warnings" ]; then
    echo "$crate: counted, with $warnings geiger warning(s)"
    GEIGER_WARNINGS=$((${GEIGER_WARNINGS:-0} + warnings))
    return 0
  fi
  echo "::error::$crate: cargo geiger exited $status after counting: ${why:-no error line}"
  return 1
}

# geiger_count CRATE...: count each crate's unsafe code in a target
# directory made for this call and removed after it: geiger reads every
# dep-info file under the target, and one left by another tree's build names
# files this tree does not have, on which geiger stops and counts nothing.
# The sourcing script defines `geiger_run CRATE TARGET`, which runs geiger
# from the crate's directory with that target and prints its report. When
# every crate was counted (geiger_crate), it prints how many and the total
# of geiger's warnings over them; it fails when any crate was not.
geiger_count() {
  local rc=0 c out status target
  GEIGER_WARNINGS=0
  target=$(mktemp -d "${TMPDIR:-/tmp}/axess-geiger.XXXXXX") || { echo "::error::cannot make a target directory for geiger"; return 1; }
  for c in "$@"; do
    out=$(geiger_run "$c" "$target" 2>&1)
    status=$?
    geiger_crate "$c" "$out" "$status" || rc=1
  done
  rm -rf "$target"
  if [ "$rc" -eq 0 ]; then
    echo "geiger counted $# crate(s); geiger warnings over them: $GEIGER_WARNINGS"
  fi
  return $rc
}
