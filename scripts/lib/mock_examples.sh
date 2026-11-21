#!/usr/bin/env bash
# axess: the examples built on the mock stores and mock provider that the
# `testing` feature compiles. They enable `testing` on purpose and are debug
# demos: a release build of one refuses by name (the release-build gate in
# every crate root), and the workspace release build CI checks leaves them
# out. Sourced by scripts/supply-chain.sh and scripts/check-release-build.sh.
# shellcheck disable=SC2034
EXAMPLES_WITH_MOCKS=(axess-example-minimal axess-example-oauth axess-example-fapi axess-example-fido2)
