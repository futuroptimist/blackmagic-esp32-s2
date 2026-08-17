#pragma once

#include <stdbool.h>

/* Unexpected NVS initialization recovery may erase an SSH host identity.
 * Preserve the legacy auto-recovery behavior unless experimental SSH is
 * enabled, in which case the trusted factory-reset paths must perform the
 * erase explicitly. */
bool nvs_storage_should_auto_erase(bool ssh_enabled, bool recovery_error);
