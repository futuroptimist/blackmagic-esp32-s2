#!/usr/bin/env bash
# Compiles and runs the wolfSSH-spike SSH keystore codec unit tests with
# the host C compiler. No ESP-IDF toolchain required -- ssh_keystore_codec.c
# is dependency-free (only <string.h>/<stddef.h>/<stdint.h>), by design,
# specifically so it can be tested this way. Mirrors run_policy_tests.sh.
# See docs/design/ssh-feasibility-spike.md and AGENTS.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPONENT_DIR="${REPO_ROOT}/components/wolfssh_spike"
CC="${CC:-cc}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

BIN="${WORKDIR}/test_ssh_keystore_codec"

"${CC}" -std=c11 -Wall -Wextra -Werror -O1 \
    -o "${BIN}" \
    "${COMPONENT_DIR}/ssh_keystore_codec.c" \
    "${COMPONENT_DIR}/test/test_ssh_keystore_codec.c"

"${BIN}"
