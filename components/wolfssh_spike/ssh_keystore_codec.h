/* ssh_keystore_codec.h -- pure, dependency-free encode/validate functions
 * for the wolfSSH-spike NVS key-storage blob format (no ESP-IDF or
 * wolfSSL/wolfSSH headers included here, so this file and
 * ssh_keystore_codec.c can be compiled and unit-tested with a plain host C
 * compiler -- see scripts/run_ssh_keystore_codec_tests.sh, mirroring
 * policy.h/policy.c). Used from ssh_keystore.c, which owns the actual NVS
 * I/O and key generation and is not host-testable (it depends on
 * ESP-IDF's nvs_flash and wolfCrypt).
 *
 * Each stored item (host key, authorized key) is one fixed-size packed
 * struct, written with a single nvs_set_blob()+nvs_commit() call -- NVS
 * itself guarantees no torn writes across that single call (a read after
 * an interrupted write returns either the old value or the new one, never
 * a mix), which is what makes each update atomic. What NVS's own
 * guarantees do NOT cover is schema and integrity validation: a
 * structurally-valid NVS blob can still be the wrong schema version, the
 * wrong key type, or have a damaged payload. schema_version/key_type/
 * payload_len/crc32 validate that envelope before any bytes are handed to
 * consumers -- see ssh_keystore_validate_host_key_blob() and
 * ssh_keystore_validate_auth_key_blob(). Semantic key parsing remains the
 * responsibility of wolfCrypt's host-key decode and wolfSSH's
 * authorized-key handling.
 */
#ifndef WOLFSSH_SPIKE_SSH_KEYSTORE_CODEC_H
#define WOLFSSH_SPIKE_SSH_KEYSTORE_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSH_KEYSTORE_SCHEMA_VERSION 1

/* SEC1 "EC PRIVATE KEY" DER for a P-256 key is ~121-150 bytes in practice
 * (OpenSSL's ecparam / wolfCrypt's wc_EccKeyToDer output); 224 leaves
 * margin without being large enough to matter for NVS/flash budget. */
#define SSH_KEYSTORE_HOST_KEY_DER_MAX 224

/* SSH wire format for ecdsa-sha2-nistp256 is a deterministic ~104 bytes
 * (string "ecdsa-sha2-nistp256" + string "nistp256" + string Q); 160
 * leaves margin. */
#define SSH_KEYSTORE_AUTH_KEY_BLOB_MAX 160

typedef enum {
    SSH_KEYSTORE_KEYTYPE_ECDSA_P256_SEC1_DER = 1, /* host key payload */
    SSH_KEYSTORE_KEYTYPE_ECDSA_P256_SSH_WIRE = 2, /* authorized key payload */
} ssh_keystore_key_type_t;

typedef struct {
    uint8_t schema_version;
    uint8_t key_type;
    uint16_t payload_len;
    uint32_t crc32;
    uint8_t payload[SSH_KEYSTORE_HOST_KEY_DER_MAX];
} __attribute__((packed)) ssh_keystore_host_key_blob_t;

typedef struct {
    uint8_t schema_version;
    uint8_t key_type;
    uint16_t payload_len;
    uint32_t crc32;
    uint8_t payload[SSH_KEYSTORE_AUTH_KEY_BLOB_MAX];
} __attribute__((packed)) ssh_keystore_auth_key_blob_t;

/* Standard CRC-32 (polynomial 0xEDB88320, the same one used by zlib/gzip),
 * implemented from scratch here (not esp_rom_crc32_le()) specifically to
 * keep this file free of any ESP-IDF dependency. */
uint32_t ssh_keystore_crc32(const uint8_t* data, size_t len);

/* Fills `blob` from `payload` (exactly `payload_len` bytes): sets
 * schema_version/key_type, copies the payload, and computes crc32.
 * Returns 1 on success, 0 if `blob`/`payload` is NULL or `payload_len`
 * exceeds the payload capacity for this blob type. */
int ssh_keystore_encode_host_key_blob(
    ssh_keystore_host_key_blob_t* blob, const uint8_t* payload, size_t payload_len);
int ssh_keystore_encode_auth_key_blob(
    ssh_keystore_auth_key_blob_t* blob, const uint8_t* payload, size_t payload_len);

/* Returns 1 if `blob` has the expected schema_version and key_type, a
 * payload_len within the payload array's capacity, and a crc32 matching
 * the stored payload bytes; else 0. Never trusts payload_len beyond the
 * fixed array bound, even if the stored value claims otherwise -- this is
 * what stops a corrupted length field from reading past the struct. */
int ssh_keystore_validate_host_key_blob(const ssh_keystore_host_key_blob_t* blob);
int ssh_keystore_validate_auth_key_blob(const ssh_keystore_auth_key_blob_t* blob);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_SPIKE_SSH_KEYSTORE_CODEC_H */
