#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_bin=$(mktemp "${TMPDIR:-/tmp}/nvs-recovery-policy-test.XXXXXX")
trap 'rm -f -- "$test_bin"' EXIT HUP INT TERM

cc -std=c11 -Wall -Wextra -Werror \
    "$repo_root/main/nvs_recovery_policy.c" \
    "$repo_root/main/test/test_nvs_recovery_policy.c" \
    -o "$test_bin"
"$test_bin"
