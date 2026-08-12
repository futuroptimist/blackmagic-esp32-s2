/* policy.h -- pure, dependency-free policy functions for the wolfSSH
 * feasibility spike (no ESP-IDF or wolfSSL/wolfSSH headers included here,
 * so this file and policy.c can be compiled and unit-tested with a plain
 * host C compiler -- see scripts/run_policy_tests.sh). Used from
 * wolfssh_spike.c to decide: is this username allowed, is this exec
 * command allowed, does this presented public key match the single
 * authorized key.
 */
#ifndef WOLFSSH_SPIKE_POLICY_H
#define WOLFSSH_SPIKE_POLICY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1 if `username` (exactly `username_len` bytes, not necessarily
 * NUL-terminated) matches the single fixed allowed username, else 0. */
int policy_username_ok(const char* username, size_t username_len);

/* Returns 1 if `command` (exactly `command_len` bytes) is exactly the one
 * allowed exec command string, else 0. No prefix/substring/glob matching
 * of any kind -- exact length and exact bytes only. */
int policy_command_allowed(const char* command, size_t command_len);

/* Constant-time comparison of a presented SSH public-key blob against the
 * single embedded authorized-key blob. Returns 1 on an exact match (same
 * length, same bytes), else 0. Does not short-circuit on the first
 * mismatching byte, so timing does not reveal how many leading bytes
 * matched. */
int policy_key_matches(const uint8_t* presented, size_t presented_len,
                        const uint8_t* authorized, size_t authorized_len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_SPIKE_POLICY_H */
