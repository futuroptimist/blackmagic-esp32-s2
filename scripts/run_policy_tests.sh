#!/usr/bin/env bash
# Compiles and runs the wolfSSH-spike policy unit tests with the host C
# compiler. No ESP-IDF toolchain required -- policy.c is dependency-free
# (only <string.h>/<stddef.h>/<stdint.h>), by design, specifically so it
# can be tested this way. See docs/design/ssh-feasibility-spike.md and
# AGENTS.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPONENT_DIR="${REPO_ROOT}/components/wolfssh_spike"
CC="${CC:-cc}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

BIN="${WORKDIR}/test_policy"

"${CC}" -std=c11 -Wall -Wextra -Werror -O1 \
    -o "${BIN}" \
    "${COMPONENT_DIR}/policy.c" \
    "${COMPONENT_DIR}/test/test_policy.c"

"${BIN}"
