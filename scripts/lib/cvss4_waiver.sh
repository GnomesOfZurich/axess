#!/usr/bin/env bash
# axess: the one cargo-deny failure ALLOW_DENY_CVSS4_PARSE_ERROR=1 may waive.
#
# The line the cvss crate prints when a cargo-deny older than 0.19 meets a
# CVSS 4.0 vector in the RustSec database. Nothing else that mentions CVSS
# is that failure, and an advisory finding beside it is never waived.
# Sourced by scripts/supply-chain.sh, which applies it, and by
# scripts/supply-chain-tests.sh, which holds it to crafted outputs.
# shellcheck disable=SC2034
CVSS4_PARSE_ERROR='unsupported CVSS version: 4\.0'
cvss4_parse_error_only() { # cvss4_parse_error_only <output>
  grep -qE "$CVSS4_PARSE_ERROR" <<<"$1" \
    && ! grep -qE 'error\[(vulnerability|unmaintained|yanked|unsound)\]' <<<"$1"
}
