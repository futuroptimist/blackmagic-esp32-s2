/* ssh_keystore.h -- ESP-IDF/wolfCrypt glue that owns NVS I/O and
 * on-device key generation for the wolfSSH spike's host key and
 * authorized key. See ssh_keystore_codec.h for the underlying blob
 * format, and docs/design/ssh-feasibility-spike.md section 10 (Phase 1)
 * for the design rationale.
 *
 * Deliberately self-contained inside components/wolfssh_spike/ rather
 * than reusing main/nvs.c: `main` implicitly depends on every component
 * (main/CMakeLists.txt's idf_component_register() has no explicit
 * REQUIRES) and already calls into wolfssh_spike_start(), so
 * wolfssh_spike must never depend back on `main` -- ESP-IDF does not
 * support component dependency cycles. This module opens the same
 * "nvs_storage" NVS partition main/nvs.c uses directly via nvs_flash,
 * under its own "ssh_keys" namespace, so the existing nvs_erase()
 * factory-reset path (main/nvs.c, called from both
 * main/factory-reset-service.c and the CLI's factory_reset command)
 * wipes SSH key material with no changes needed to nvs_erase() itself.
 */
#ifndef WOLFSSH_SPIKE_SSH_KEYSTORE_H
#define WOLFSSH_SPIKE_SSH_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

#include <esp_err.h>

#include "ssh_keystore_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Loads the persisted host private key (raw SEC1 "EC PRIVATE KEY" DER) from
 * NVS, or generates a fresh ECDSA P-256 key on-device (via wolfCrypt's
 * wc_ecc_make_key(), seeded from the ESP-IDF hardware RNG) and persists it
 * if none exists yet.
 *
 * Fails closed on any state other than "key absent": a stored blob that
 * fails ssh_keystore_validate_host_key_blob() (corruption) returns an
 * error WITHOUT regenerating -- see docs/design/ssh-access.md's "fail
 * closed... do not silently generate a new identity unless the documented
 * recovery/reset operation requests rotation." Only a genuinely absent key
 * (ESP_ERR_NVS_NOT_FOUND, i.e. first boot or just after a factory reset,
 * which is exactly that documented reset operation) generates a new one.
 *
 * `der_out_cap` must be at least SSH_KEYSTORE_HOST_KEY_DER_MAX. Returns
 * ESP_OK and sets *der_len_out on success; any other return means the
 * caller must not start the SSH listener. */
esp_err_t ssh_keystore_load_or_generate_host_key(
    uint8_t* der_out, size_t der_out_cap, size_t* der_len_out);

/* Loads the persisted authorized-key SSH wire-format blob from NVS, or
 * seeds NVS from `seed_blob` (the build-time-embedded key -- real
 * enrollment is Phase 2, out of scope here) if none exists yet. Same
 * fail-closed behavior on corruption as the host-key function above.
 *
 * `blob_out_cap` must be at least SSH_KEYSTORE_AUTH_KEY_BLOB_MAX. Returns
 * ESP_OK and sets *blob_len_out on success. */
esp_err_t ssh_keystore_load_or_seed_authorized_key(
    const uint8_t* seed_blob,
    size_t seed_blob_len,
    uint8_t* blob_out,
    size_t blob_out_cap,
    size_t* blob_len_out);

#define SSH_KEYSTORE_FINGERPRINT_LEN 32 /* SHA-256 digest, raw bytes */

/* Computes the SHA-256 fingerprint of the SSH wire-format public key
 * derived from a SEC1 "EC PRIVATE KEY" DER private key (as returned by
 * ssh_keystore_load_or_generate_host_key()) -- the same quantity `ssh
 * -lf`/known_hosts fingerprints are computed over, used here only to give
 * a concrete, loggable way to verify "stable fingerprint across ordinary
 * reboots" (log this once at boot and diff it across reboots). Writes
 * exactly SSH_KEYSTORE_FINGERPRINT_LEN bytes to `fingerprint_out`. Never
 * logs or otherwise exposes the private key itself. */
esp_err_t ssh_keystore_host_key_fingerprint_sha256(
    const uint8_t* der, size_t der_len, uint8_t* fingerprint_out);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_SPIKE_SSH_KEYSTORE_H */
