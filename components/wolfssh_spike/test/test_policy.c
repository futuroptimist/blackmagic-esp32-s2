/* test_policy.c -- native host tests for policy.c. Compiled and run with
 * a plain host C compiler (no ESP-IDF), see scripts/run_policy_tests.sh.
 */
#include "../policy.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(desc, cond)                                                    \
    do {                                                                     \
        if (cond) {                                                          \
            printf("PASS: %s\n", desc);                                      \
        } else {                                                             \
            printf("FAIL: %s\n", desc);                                      \
            g_failures++;                                                    \
        }                                                                    \
    } while (0)

static void test_username(void)
{
    CHECK("username: exact match allowed",
          policy_username_ok("flipper", 7) == 1);
    CHECK("username: wrong name rejected",
          policy_username_ok("root", 4) == 0);
    CHECK("username: prefix rejected",
          policy_username_ok("flippers", 8) == 0);
    CHECK("username: truncated rejected",
          policy_username_ok("flippe", 6) == 0);
    CHECK("username: empty rejected",
          policy_username_ok("", 0) == 0);
    CHECK("username: NULL rejected",
          policy_username_ok(NULL, 0) == 0);
    CHECK("username: embedded NUL not treated as terminator",
          policy_username_ok("flipper\0x", 9) == 0);
    CHECK("username: case-sensitive",
          policy_username_ok("Flipper", 7) == 0);
}

static void test_command(void)
{
    CHECK("command: exact 'ping' allowed",
          policy_command_allowed("ping", 4) == 1);
    CHECK("command: 'pingpong' rejected",
          policy_command_allowed("pingpong", 8) == 0);
    CHECK("command: 'ping ' with trailing space rejected",
          policy_command_allowed("ping ", 5) == 0);
    CHECK("command: 'ping; rm -rf /' rejected",
          policy_command_allowed("ping; rm -rf /", 14) == 0);
    CHECK("command: empty rejected",
          policy_command_allowed("", 0) == 0);
    CHECK("command: NULL rejected",
          policy_command_allowed(NULL, 0) == 0);
    CHECK("command: other allowlist-shaped command rejected",
          policy_command_allowed("device_info", 11) == 0);
}

static void test_key_matches(void)
{
    const uint8_t key_a[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t key_a_copy[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t key_b[] = {0x01, 0x02, 0x03, 0x05};
    const uint8_t key_short[] = {0x01, 0x02, 0x03};

    CHECK("key: identical bytes match",
          policy_key_matches(key_a, sizeof(key_a), key_a_copy,
                              sizeof(key_a_copy)) == 1);
    CHECK("key: differing last byte rejected",
          policy_key_matches(key_a, sizeof(key_a), key_b, sizeof(key_b)) == 0);
    CHECK("key: length mismatch rejected",
          policy_key_matches(key_a, sizeof(key_a), key_short,
                              sizeof(key_short)) == 0);
    CHECK("key: empty vs empty is not a match (no wildcard keys)",
          policy_key_matches(NULL, 0, NULL, 0) == 0);
    CHECK("key: NULL presented rejected",
          policy_key_matches(NULL, 4, key_a, sizeof(key_a)) == 0);
    CHECK("key: NULL authorized rejected",
          policy_key_matches(key_a, sizeof(key_a), NULL, 4) == 0);
}

int main(void)
{
    test_username();
    test_command();
    test_key_matches();

    if (g_failures == 0) {
        printf("\nAll policy tests passed.\n");
        return 0;
    }
    printf("\n%d policy test(s) FAILED.\n", g_failures);
    return 1;
}
