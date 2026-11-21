#!/usr/bin/env bash
# axess: install the pinned ShellCheck release binary.
#
# The one place the ShellCheck version is pinned. CI's "Shell Scripts" job
# runs this before scripts/check-shellcheck.sh, which reads
# SHELLCHECK_VERSION from here and refuses any other version: a newer or
# older ShellCheck reports a different set of findings, so a gate run with
# another version proves nothing about the pinned one.
#
# The archive is checked against the SHA-256 pinned below before anything is
# extracted, so a release asset replaced after the version was pinned stops
# here instead of running. To move the version: change it, download the new
# archive, read its digest from `gh api
# repos/koalaman/shellcheck/releases/tags/v<version>` (the asset's `digest`)
# and from `sha256sum` of the file, and pin it only when the two agree.
#
# Linux x86_64 only (the GitHub runners); locally, install the same version
# from the release page or a package manager that ships it.
#
# Usage: ./scripts/install-shellcheck.sh [BIN_DIR]   (default: ~/.cargo/bin,
#        which is on the runners' PATH ahead of the image's own ShellCheck)

set -euo pipefail

SHELLCHECK_VERSION=0.11.0

# SHA-256 of shellcheck-v<SHELLCHECK_VERSION>.linux.x86_64.tar.xz (2,559,196
# bytes, published 2025-08-04): the digest the release records for the
# asset and the SHA-256 of a separate download of the file agreed.
SHELLCHECK_SHA256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198

BIN_DIR="${1:-$HOME/.cargo/bin}"
mkdir -p "$BIN_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Download, check (with -e set, a mismatch stops the script here, before
# anything is extracted), then extract and install the one binary. Written
# out in this order so that scripts/check-workflow-pins.sh reads the check
# beside the download.
curl -fsSL -o "$WORK/shellcheck.tar.xz" \
  "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz"
echo "$SHELLCHECK_SHA256  $WORK/shellcheck.tar.xz" | sha256sum --check --strict -
tar -xJ -C "$BIN_DIR" --strip-components=1 -f "$WORK/shellcheck.tar.xz" "shellcheck-v${SHELLCHECK_VERSION}/shellcheck"
chmod +x "$BIN_DIR/shellcheck"

echo "Installed ShellCheck ${SHELLCHECK_VERSION} into ${BIN_DIR}."
