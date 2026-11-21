#!/usr/bin/env bash
# axess: has an upstream moved to the release that fixes an accepted advisory?
#
# .cargo/audit.toml and deny.toml accept three advisories because a crate
# axess depends on still requires the affected release line. The fixed
# releases exist; what axess waits for is the dependent's next release. (The
# fourth accepted advisory, RUSTSEC-2026-0543, says chrono is unmaintained:
# no release fixes it, so nothing here watches for one.)
#
#   jsonwebtoken-rsa             RUSTSEC-2023-0071: jsonwebtoken's
#                                `rust_crypto` backend requires rsa 0.9, and
#                                the fix is rsa 0.10.0.
#   openidconnect-rsa            RUSTSEC-2023-0071: openidconnect requires
#                                rsa 0.9.
#   crypto-glue-rsa              RUSTSEC-2023-0071: crypto-glue (under
#                                webauthn-rs) requires an rsa 0.10
#                                pre-release with the feature `sha2`, which
#                                rsa 0.10.0 does not have, so cargo keeps the
#                                pre-release, and the advisory counts a
#                                pre-release as affected.
#   jsonwebtoken-p256            RUSTSEC-2026-0387: jsonwebtoken requires
#                                p256 0.13, which is on crypto-bigint 0.5;
#                                the fix is crypto-bigint 0.7.6, which p256
#                                0.14 uses.
#   jsonwebtoken-p384            The same advisory through jsonwebtoken's
#                                p384 0.13; crypto-bigint 0.5 leaves the
#                                tree when both curves have moved.
#   sqlx-sqlite-libsqlite3-sys   RUSTSEC-2026-0459: sqlx-sqlite requires
#                                libsqlite3-sys below 0.38, and the fix is
#                                0.39.0.
#
# For the watch named, this reads crates.io for the dependent's newest stable
# release and its requirement on the pinned crate, and reports `hit=true`
# when that requirement admits the fixed release (or the dependency is gone)
# and `hit=false` while it stays below it, or asks for a feature the fixed
# release no longer has. Both go to stdout and to the step outputs
# ($GITHUB_OUTPUT, or the file `--output` names) as `hit` and `summary`.
# With `--all` it runs every watch and writes one output, `hits`: a JSON list
# of `{"watch", "summary"}` for each watch that is a hit. A hit means the
# bump can be made and the ignore dropped; the weekly `advisory-fix-watch`
# workflow opens an issue that says so.
#
# It FAILS (exit 1) on a failed request, an answer without what it reads or
# a requirement it cannot read, so a broken query is a red run and never a
# silent "no change"; under `--all`, after the hits of the other watches are
# written, whatever the failure of the one watch was. It needs python3 and
# nothing else.
#
# Usage: scripts/watch-advisory-fixes.sh NAME|--all [--answers DIR] [--output FILE]
#   --answers DIR  read the answers recorded under DIR instead of crates.io
#                  (DIR/crates/CRATE.json and
#                  DIR/crates/CRATE/VERSION/dependencies.json), as
#                  scripts/watch-advisory-fixes-tests.sh does
#   --output FILE  append the step outputs to FILE instead of $GITHUB_OUTPUT

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 -I -B "$AXESS_DIR/scripts/lib/upstream_watch.py" "$@"
