/* test_ssh_keystore_codec.c -- native host tests for ssh_keystore_codec.c.
 * Compiled and run with a plain host C compiler (no ESP-IDF), see
 * scripts/run_ssh_keystore_codec_tests.sh.
 */
#include "../ssh_keystore_codec.h"

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

static void test_crc32(void)
{
    /* Well-known reference vector: CRC-32 of "123456789" is 0xCBF43926. */
    CHECK("crc32: reference vector",
          ssh_keystore_crc32((const uint8_t*)"123456789", 9) == 0xCBF43926u);
    CHECK("crc32: empty input", ssh_keystore_crc32((const uint8_t*)"", 0) == 0);
    CHECK("crc32: NULL input", ssh_keystore_crc32(NULL, 5) == 0);
}

static void test_host_key_blob(void)
{
    ssh_keystore_host_key_blob_t blob;
    uint8_t payload[64];
    size_t i;

    for (i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(i * 3 + 1);
    }

    CHECK("host blob: encode succeeds",
          ssh_keystore_encode_host_key_blob(&blob, payload, sizeof(payload)) == 1);
    CHECK("host blob: round-trips as valid",
          ssh_keystore_validate_host_key_blob(&blob) == 1);
    CHECK("host blob: payload preserved",
          memcmp(blob.payload, payload, sizeof(payload)) == 0);

    CHECK("host blob: encode rejects NULL blob",
          ssh_keystore_encode_host_key_blob(NULL, payload, sizeof(payload)) == 0);
    CHECK("host blob: encode rejects NULL payload",
          ssh_keystore_encode_host_key_blob(&blob, NULL, sizeof(payload)) == 0);
    CHECK("host blob: encode rejects zero length",
          ssh_keystore_encode_host_key_blob(&blob, payload, 0) == 0);
    CHECK("host blob: encode rejects oversize payload",
          ssh_keystore_encode_host_key_blob(
              &blob, payload, SSH_KEYSTORE_HOST_KEY_DER_MAX + 1) == 0);

    CHECK("host blob: validate rejects NULL",
          ssh_keystore_validate_host_key_blob(NULL) == 0);

    ssh_keystore_encode_host_key_blob(&blob, payload, sizeof(payload));
    blob.schema_version = SSH_KEYSTORE_SCHEMA_VERSION + 1;
    CHECK("host blob: validate rejects wrong schema version",
          ssh_keystore_validate_host_key_blob(&blob) == 0);

    ssh_keystore_encode_host_key_blob(&blob, payload, sizeof(payload));
    blob.key_type = SSH_KEYSTORE_KEYTYPE_ECDSA_P256_SSH_WIRE;
    CHECK("host blob: validate rejects wrong key type",
          ssh_keystore_validate_host_key_blob(&blob) == 0);

    ssh_keystore_encode_host_key_blob(&blob, payload, sizeof(payload));
    blob.payload_len = SSH_KEYSTORE_HOST_KEY_DER_MAX + 1;
    CHECK("host blob: validate rejects out-of-bounds payload_len",
          ssh_keystore_validate_host_key_blob(&blob) == 0);

    ssh_keystore_encode_host_key_blob(&blob, payload, sizeof(payload));
    blob.payload_len = 0;
    CHECK("host blob: validate rejects zero payload_len",
          ssh_keystore_validate_host_key_blob(&blob) == 0);

    ssh_keystore_encode_host_key_blob(&blob, payload, sizeof(payload));
    blob.crc32 ^= 0x1u;
    CHECK("host blob: validate rejects a single flipped CRC bit",
          ssh_keystore_validate_host_key_blob(&blob) == 0);

    ssh_keystore_encode_host_key_blob(&blob, payload, sizeof(payload));
    blob.payload[0] ^= 0x1u;
    CHECK("host blob: validate rejects a single flipped payload bit",
          ssh_keystore_validate_host_key_blob(&blob) == 0);
}

static void test_auth_key_blob(void)
{
    ssh_keystore_auth_key_blob_t blob;
    uint8_t payload[32];
    size_t i;

    for (i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(0xA0 + i);
    }

    CHECK("auth blob: encode succeeds",
          ssh_keystore_encode_auth_key_blob(&blob, payload, sizeof(payload)) == 1);
    CHECK("auth blob: round-trips as valid",
          ssh_keystore_validate_auth_key_blob(&blob) == 1);
    CHECK("auth blob: payload preserved",
          memcmp(blob.payload, payload, sizeof(payload)) == 0);

    CHECK("auth blob: encode rejects oversize payload",
          ssh_keystore_encode_auth_key_blob(
              &blob, payload, SSH_KEYSTORE_AUTH_KEY_BLOB_MAX + 1) == 0);

    /* A well-formed host-key blob must never validate as an authorized-key
     * blob, and vice versa -- key_type is what stops a key of the wrong
     * kind from being silently accepted by the wrong loader. */
    {
        ssh_keystore_host_key_blob_t host_blob;
        ssh_keystore_encode_host_key_blob(&host_blob, payload, sizeof(payload));
        CHECK("auth blob: a valid host blob does not validate as an auth blob",
              ssh_keystore_validate_auth_key_blob(
                  (const ssh_keystore_auth_key_blob_t*)&host_blob) == 0);
    }

    ssh_keystore_encode_auth_key_blob(&blob, payload, sizeof(payload));
    blob.crc32 ^= 0x1u;
    CHECK("auth blob: validate rejects a single flipped CRC bit",
          ssh_keystore_validate_auth_key_blob(&blob) == 0);
}

int main(void)
{
    test_crc32();
    test_host_key_blob();
    test_auth_key_blob();

    if (g_failures == 0) {
        printf("\nAll ssh_keystore_codec tests passed.\n");
        return 0;
    }
    printf("\n%d ssh_keystore_codec test(s) FAILED.\n", g_failures);
    return 1;
}
