#include "policy.h"

#include <string.h>

#define POLICY_USERNAME "flipper"
#define POLICY_COMMAND  "ping"

int policy_username_ok(const char* username, size_t username_len)
{
    size_t expected_len = strlen(POLICY_USERNAME);

    if (username == NULL || username_len != expected_len) {
        return 0;
    }
    return memcmp(username, POLICY_USERNAME, expected_len) == 0;
}

int policy_command_allowed(const char* command, size_t command_len)
{
    size_t expected_len = strlen(POLICY_COMMAND);

    if (command == NULL || command_len != expected_len) {
        return 0;
    }
    return memcmp(command, POLICY_COMMAND, expected_len) == 0;
}

int policy_key_matches(const uint8_t* presented, size_t presented_len,
                        const uint8_t* authorized, size_t authorized_len)
{
    uint8_t diff;
    size_t i;

    if (presented == NULL || authorized == NULL || presented_len == 0 ||
        authorized_len == 0) {
        return 0;
    }
    if (presented_len != authorized_len) {
        return 0;
    }

    diff = 0;
    for (i = 0; i < presented_len; i++) {
        diff |= (uint8_t)(presented[i] ^ authorized[i]);
    }
    return diff == 0;
}

int policy_claim_exec_once(int* claimed)
{
    if (claimed == NULL || *claimed) {
        return 0;
    }
    *claimed = 1;
    return 1;
}
