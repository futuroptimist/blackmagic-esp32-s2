#include "ssh_keystore_codec.h"

#include <string.h>

uint32_t ssh_keystore_crc32(const uint8_t* data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    int bit;

    if (data == NULL) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

int ssh_keystore_encode_host_key_blob(
    ssh_keystore_host_key_blob_t* blob, const uint8_t* payload, size_t payload_len)
{
    if (blob == NULL || payload == NULL || payload_len == 0 ||
        payload_len > sizeof(blob->payload)) {
        return 0;
    }

    memset(blob, 0, sizeof(*blob));
    blob->schema_version = SSH_KEYSTORE_SCHEMA_VERSION;
    blob->key_type = SSH_KEYSTORE_KEYTYPE_ECDSA_P256_SEC1_DER;
    blob->payload_len = (uint16_t)payload_len;
    memcpy(blob->payload, payload, payload_len);
    blob->crc32 = ssh_keystore_crc32(blob->payload, payload_len);
    return 1;
}

int ssh_keystore_encode_auth_key_blob(
    ssh_keystore_auth_key_blob_t* blob, const uint8_t* payload, size_t payload_len)
{
    if (blob == NULL || payload == NULL || payload_len == 0 ||
        payload_len > sizeof(blob->payload)) {
        return 0;
    }

    memset(blob, 0, sizeof(*blob));
    blob->schema_version = SSH_KEYSTORE_SCHEMA_VERSION;
    blob->key_type = SSH_KEYSTORE_KEYTYPE_ECDSA_P256_SSH_WIRE;
    blob->payload_len = (uint16_t)payload_len;
    memcpy(blob->payload, payload, payload_len);
    blob->crc32 = ssh_keystore_crc32(blob->payload, payload_len);
    return 1;
}

int ssh_keystore_validate_host_key_blob(const ssh_keystore_host_key_blob_t* blob)
{
    if (blob == NULL) {
        return 0;
    }
    if (blob->schema_version != SSH_KEYSTORE_SCHEMA_VERSION) {
        return 0;
    }
    if (blob->key_type != SSH_KEYSTORE_KEYTYPE_ECDSA_P256_SEC1_DER) {
        return 0;
    }
    if (blob->payload_len == 0 || blob->payload_len > sizeof(blob->payload)) {
        return 0;
    }
    if (ssh_keystore_crc32(blob->payload, blob->payload_len) != blob->crc32) {
        return 0;
    }
    return 1;
}

int ssh_keystore_validate_auth_key_blob(const ssh_keystore_auth_key_blob_t* blob)
{
    if (blob == NULL) {
        return 0;
    }
    if (blob->schema_version != SSH_KEYSTORE_SCHEMA_VERSION) {
        return 0;
    }
    if (blob->key_type != SSH_KEYSTORE_KEYTYPE_ECDSA_P256_SSH_WIRE) {
        return 0;
    }
    if (blob->payload_len == 0 || blob->payload_len > sizeof(blob->payload)) {
        return 0;
    }
    if (ssh_keystore_crc32(blob->payload, blob->payload_len) != blob->crc32) {
        return 0;
    }
    return 1;
}
