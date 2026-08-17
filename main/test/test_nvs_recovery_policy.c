#include <stdio.h>

#include "../nvs_recovery_policy.h"

static int failures;

#define CHECK(name, condition) do { \
    if(!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        failures++; \
    } \
} while(0)

int main(void) {
    CHECK("SSH disabled preserves legacy recovery",
          nvs_storage_should_auto_erase(false, true));
    CHECK("SSH enabled preserves unexpected state",
          !nvs_storage_should_auto_erase(true, true));
    CHECK("successful init is never erased (SSH disabled)",
          !nvs_storage_should_auto_erase(false, false));
    CHECK("successful init is never erased (SSH enabled)",
          !nvs_storage_should_auto_erase(true, false));

    if(failures != 0) return 1;
    puts("nvs recovery policy tests passed");
    return 0;
}
