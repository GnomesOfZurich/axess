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
# Linux x86_64 only (the GitHub runners); locally, `cargo install mdbook
# --version <MDBOOK_VERSION>` and `cargo install mdbook-mermaid`.
#
# Usage: ./scripts/install-mdbook.sh [BIN_DIR]   (default: ~/.cargo/bin)

set -euo pipefail

MDBOOK_VERSION=0.5.3
MDBOOK_MERMAID_VERSION=0.17.0

BIN_DIR="${1:-$HOME/.cargo/bin}"
mkdir -p "$BIN_DIR"

curl -fsSL "https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/mdbook-v${MDBOOK_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
  | tar -xz -C "$BIN_DIR"
curl -fsSL "https://github.com/badboy/mdbook-mermaid/releases/download/v${MDBOOK_MERMAID_VERSION}/mdbook-mermaid-v${MDBOOK_MERMAID_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
  | tar -xz -C "$BIN_DIR"
chmod +x "$BIN_DIR/mdbook" "$BIN_DIR/mdbook-mermaid"

echo "Installed mdbook ${MDBOOK_VERSION} and mdbook-mermaid ${MDBOOK_MERMAID_VERSION} into ${BIN_DIR}."
