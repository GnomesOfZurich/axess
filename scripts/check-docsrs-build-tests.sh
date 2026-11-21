#!/usr/bin/env bash
# axess: crafted cases for the plan of scripts/check-docsrs-build.sh.
#
# The docs.rs build gate hands cargo's metadata to
# scripts/lib/docsrs_build.py, which reads each published crate's
# `[package.metadata.docs.rs]` into the arguments of its `cargo doc`;
# scripts/lib/docsrs_build_tests.py runs it over crafted members, with no
# build. The contract: one line per published crate with the features and
# the rustdoc arguments its table asks for, an unpublished member left out,
# and a key the gate does not apply, or a value it cannot hand on, refused
# by name.
#
# Usage: ./scripts/check-docsrs-build-tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 -I -B "$SCRIPT_DIR/lib/docsrs_build_tests.py"
