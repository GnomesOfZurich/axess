#!/usr/bin/env bash
# axess: crafted cases for the report of scripts/check-doc-links.sh.
#
# The documentation gate hands cargo's JSON messages to
# scripts/lib/doc_links.py; scripts/lib/doc_links_tests.py runs that report
# over crafted workspaces, messages and rendered pages, with no build. The
# contract: every diagnostic of every crate is reported with its crate, one
# rustdoc gives no location for names the module docs it can come from, and
# a run that documented less than the workspace, or failed with nothing
# said, does not pass.
#
# Usage: ./scripts/check-doc-links-tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 -I -B "$SCRIPT_DIR/lib/doc_links_tests.py"
