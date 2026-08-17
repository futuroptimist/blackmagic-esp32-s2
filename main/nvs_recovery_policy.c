#include "nvs_recovery_policy.h"

bool nvs_storage_should_auto_erase(bool ssh_enabled, bool recovery_error) {
    return recovery_error && !ssh_enabled;
}
