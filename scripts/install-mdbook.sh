#!/usr/bin/env bash
# axess: install the pinned mdBook and mdbook-mermaid release binaries.
#
# The one place the book toolchain is pinned. The docs workflow (which
# publishes the book) and the CI "Book" job (which gates a pull request on
# it) both run this, so the book a pull request was checked with is the
# book that gets published. The release preflight reads MDBOOK_VERSION from
# here to warn when a local mdbook differs: a newer one accepts book.toml
# keys the pinned one rejects, which is how `edition = "2024"` reached CI.
#
# Each archive is checked against a SHA-256 pinned below before anything is
# extracted. The binaries build the Pages site the docs workflow deploys, so a
# release asset replaced after the version was pinned must stop here, not run.
# To move a version: change the version, download the new archive, read its
# digest from `gh api repos/<owner>/<repo>/releases/tags/<tag>` (the asset's
# `digest`) and from `sha256sum` of the file, and pin both only when they agree.
#
# Linux x86_64 only (the GitHub runners); locally, `cargo install mdbook
# --version <MDBOOK_VERSION>` and `cargo install mdbook-mermaid`.
#
# Usage: ./scripts/install-mdbook.sh [BIN_DIR]   (default: ~/.cargo/bin)

set -euo pipefail

MDBOOK_VERSION=0.5.3
MDBOOK_MERMAID_VERSION=0.17.0

# SHA-256 of the x86_64-unknown-linux-gnu archives named above.
MDBOOK_SHA256=e2fd508a4fac06cbaa9f88b97d27bdc3b55a08946304ca845879fe26a3699e11
MDBOOK_MERMAID_SHA256=8aced70d781830fb0e81988f081c4abdd49e056a001ae2f1e4d484e1f6385c57

BIN_DIR="${1:-$HOME/.cargo/bin}"
mkdir -p "$BIN_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# fetch <url> <sha256> <file>: download, verify, then extract into BIN_DIR.
fetch() {
  local url="$1" sha="$2" file="$WORK/$3"
  curl -fsSL -o "$file" "$url"
  (cd "$WORK" && printf '%s  %s\n' "$sha" "$3" | sha256sum -c -) \
    || { echo "refused: $3 does not match its pinned SHA-256; nothing was extracted." >&2; exit 1; }
  tar -xz -C "$BIN_DIR" -f "$file"
}

fetch "https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/mdbook-v${MDBOOK_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
  "$MDBOOK_SHA256" mdbook.tar.gz
fetch "https://github.com/badboy/mdbook-mermaid/releases/download/v${MDBOOK_MERMAID_VERSION}/mdbook-mermaid-v${MDBOOK_MERMAID_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
  "$MDBOOK_MERMAID_SHA256" mdbook-mermaid.tar.gz
chmod +x "$BIN_DIR/mdbook" "$BIN_DIR/mdbook-mermaid"

echo "Installed mdbook ${MDBOOK_VERSION} and mdbook-mermaid ${MDBOOK_MERMAID_VERSION} into ${BIN_DIR}."
