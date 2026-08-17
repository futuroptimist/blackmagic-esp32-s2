#include "ssh_keystore.h"

#include <string.h>

#include <esp_log.h>
#include <nvs.h>
#include <nvs_flash.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>

/* "string ecdsa-sha2-nistp256" + "string nistp256" + "string Q" (Q is the
 * 65-byte uncompressed P-256 point, 0x04||X||Y) -- the same SSH
 * wire-format public-key blob wolfSSH hands user_auth_cb() for a
 * client-presented key (see policy_key_matches() call sites in
 * wolfssh_spike.c), built here only to compute a fingerprint. */
#define SSH_WIRE_KEY_TYPE_NAME "ecdsa-sha2-nistp256"
#define SSH_WIRE_CURVE_NAME    "nistp256"
#define SSH_WIRE_POINT_LEN     65

static void put_be32(uint8_t* out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static size_t put_ssh_string(uint8_t* out, const uint8_t* data, size_t len)
{
    put_be32(out, (uint32_t)len);
    memcpy(out + 4, data, len);
    return 4 + len;
}

static const char* TAG = "ssh_keystore";

/* Same partition main/nvs.c uses (NVS_STORE there); a dedicated namespace
 * within it keeps SSH key material logically separate from the WiFi/USB
 * config keys nvs-config.c manages, while still being wiped by the
 * existing nvs_erase()'s full-partition erase -- see ssh_keystore.h. */
#define SSH_KEYSTORE_NVS_PARTITION "nvs_storage"
#define SSH_KEYSTORE_NVS_NAMESPACE "ssh_keys"
#define SSH_KEYSTORE_NVS_KEY_HOST "host_key"
#define SSH_KEYSTORE_NVS_KEY_AUTH "auth_key"

static esp_err_t generate_host_key_der(uint8_t* der_out, size_t der_out_cap, size_t* der_len_out)
{
    WC_RNG rng;
    ecc_key key;
    int wc_ret;
    esp_err_t result = ESP_FAIL;
    word32 der_len;

    if (wc_InitRng(&rng) != 0) {
        ESP_LOGE(TAG, "wc_InitRng failed");
        return ESP_FAIL;
    }

    if (wc_ecc_init(&key) != 0) {
        ESP_LOGE(TAG, "wc_ecc_init failed");
        wc_FreeRng(&rng);
        return ESP_FAIL;
    }

    /* wc_ecc_make_key_ex(), not wc_ecc_make_key(), to pin the curve
     * explicitly rather than relying on keysize=32 implying
     * ECC_CURVE_DEF's default curve. */
    wc_ret = wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
    if (wc_ret != 0) {
        ESP_LOGE(TAG, "wc_ecc_make_key_ex failed: %d", wc_ret);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return ESP_FAIL;
    }

    der_len = (word32)der_out_cap;
    wc_ret = wc_EccKeyToDer(&key, der_out, der_len);
    if (wc_ret < 0) {
        ESP_LOGE(TAG, "wc_EccKeyToDer failed: %d", wc_ret);
    } else {
        *der_len_out = (size_t)wc_ret;
        result = ESP_OK;
    }

    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    return result;
}

esp_err_t ssh_keystore_load_or_generate_host_key(
    uint8_t* der_out, size_t der_out_cap, size_t* der_len_out)
{
    nvs_handle_t handle;
    ssh_keystore_host_key_blob_t blob;
    size_t blob_len = sizeof(blob);
    esp_err_t err;

    if (der_out == NULL || der_len_out == NULL ||
        der_out_cap < SSH_KEYSTORE_HOST_KEY_DER_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    err = nvs_open_from_partition(
        SSH_KEYSTORE_NVS_PARTITION, SSH_KEYSTORE_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to open ssh_keys namespace: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_get_blob(handle, SSH_KEYSTORE_NVS_KEY_HOST, &blob, &blob_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        /* No stored key: the documented first-boot / just-after-factory-
         * reset case, not corruption at this layer -- generate and persist
         * a fresh identity. Note this can also be reached if main/nvs.c's
         * nvs_init() itself just erased the whole "nvs_storage" partition
         * (ESP_ERR_NVS_NO_FREE_PAGES / ESP_ERR_NVS_NEW_VERSION_FOUND at
         * that lower layer, handled before this code ever runs) -- an
         * unreadable partition can't have its prior identity "preserved,"
         * so generating fresh here is the correct recovery for that case
         * too, not a violation of the fail-closed policy above (which is
         * about a validation failure on an otherwise-*readable* stored
         * blob, a different failure mode entirely). */
        size_t der_len = 0;

        if (generate_host_key_der(der_out, der_out_cap, &der_len) != ESP_OK) {
            nvs_close(handle);
            return ESP_FAIL;
        }

        if (!ssh_keystore_encode_host_key_blob(&blob, der_out, der_len)) {
            ESP_LOGE(TAG, "failed to encode generated host key blob");
            nvs_close(handle);
            return ESP_FAIL;
        }

        err = nvs_set_blob(handle, SSH_KEYSTORE_NVS_KEY_HOST, &blob, sizeof(blob));
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
        nvs_close(handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "failed to persist generated host key: %s", esp_err_to_name(err));
            return err;
        }

        ESP_LOGI(TAG, "generated and persisted a new host key");
        *der_len_out = der_len;
        return ESP_OK;
    }

    nvs_close(handle);

    if (err != ESP_OK) {
        /* Any error other than "not found" is treated as unavailable /
         * corrupted storage -- fail closed, never regenerate here. */
        ESP_LOGE(TAG, "failed to read stored host key: %s", esp_err_to_name(err));
        return err;
    }

    if (blob_len != sizeof(blob) || !ssh_keystore_validate_host_key_blob(&blob)) {
        ESP_LOGE(TAG, "stored host key failed integrity validation; refusing to start SSH");
        return ESP_ERR_INVALID_STATE;
    }

    if (blob.payload_len > der_out_cap) {
        ESP_LOGE(TAG, "stored host key is larger than the output buffer");
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(der_out, blob.payload, blob.payload_len);
    *der_len_out = blob.payload_len;
    return ESP_OK;
}

esp_err_t ssh_keystore_load_or_seed_authorized_key(
    const uint8_t* seed_blob,
    size_t seed_blob_len,
    uint8_t* blob_out,
    size_t blob_out_cap,
    size_t* blob_len_out)
{
    nvs_handle_t handle;
    ssh_keystore_auth_key_blob_t blob;
    size_t blob_len = sizeof(blob);
    esp_err_t err;

    if (seed_blob == NULL || seed_blob_len == 0 || blob_out == NULL ||
        blob_len_out == NULL || blob_out_cap < SSH_KEYSTORE_AUTH_KEY_BLOB_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    err = nvs_open_from_partition(
        SSH_KEYSTORE_NVS_PARTITION, SSH_KEYSTORE_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to open ssh_keys namespace: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_get_blob(handle, SSH_KEYSTORE_NVS_KEY_AUTH, &blob, &blob_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        /* No stored authorized key: seed from the build-embedded key.
         * Real enrollment is Phase 2 -- see ssh_keystore.h. */
        if (!ssh_keystore_encode_auth_key_blob(&blob, seed_blob, seed_blob_len)) {
            ESP_LOGE(TAG, "failed to encode seed authorized key blob");
            nvs_close(handle);
            return ESP_FAIL;
        }

        err = nvs_set_blob(handle, SSH_KEYSTORE_NVS_KEY_AUTH, &blob, sizeof(blob));
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
        nvs_close(handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "failed to persist seeded authorized key: %s", esp_err_to_name(err));
            return err;
        }

        ESP_LOGI(TAG, "seeded NVS authorized key from the build-embedded key");
        memcpy(blob_out, seed_blob, seed_blob_len);
        *blob_len_out = seed_blob_len;
        return ESP_OK;
    }

    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to read stored authorized key: %s", esp_err_to_name(err));
        return err;
    }

    if (blob_len != sizeof(blob) || !ssh_keystore_validate_auth_key_blob(&blob)) {
        ESP_LOGE(TAG, "stored authorized key failed integrity validation; refusing to start SSH");
        return ESP_ERR_INVALID_STATE;
    }

    if (blob.payload_len > blob_out_cap) {
        ESP_LOGE(TAG, "stored authorized key is larger than the output buffer");
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(blob_out, blob.payload, blob.payload_len);
    *blob_len_out = blob.payload_len;
    return ESP_OK;
}

esp_err_t ssh_keystore_host_key_fingerprint_sha256(
    const uint8_t* der, size_t der_len, uint8_t* fingerprint_out)
{
    ecc_key key;
    word32 idx = 0;
    int wc_ret;
    esp_err_t result = ESP_FAIL;

    if (der == NULL || fingerprint_out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (wc_ecc_init(&key) != 0) {
        return ESP_FAIL;
    }

    wc_ret = wc_EccPrivateKeyDecode(der, &idx, &key, (word32)der_len);
    if (wc_ret != 0) {
        ESP_LOGE(TAG, "wc_EccPrivateKeyDecode failed: %d", wc_ret);
        wc_ecc_free(&key);
        return ESP_FAIL;
    }

    {
        uint8_t point[SSH_WIRE_POINT_LEN];
        word32 point_len = sizeof(point);

        wc_ret = wc_ecc_export_x963(&key, point, &point_len);
        wc_ecc_free(&key);
        if (wc_ret != 0 || point_len != SSH_WIRE_POINT_LEN) {
            ESP_LOGE(TAG, "wc_ecc_export_x963 failed: %d", wc_ret);
            return ESP_FAIL;
        }

        {
            uint8_t wire[4 + sizeof(SSH_WIRE_KEY_TYPE_NAME) - 1 + 4 +
                         sizeof(SSH_WIRE_CURVE_NAME) - 1 + 4 + SSH_WIRE_POINT_LEN];
            size_t off = 0;

            off += put_ssh_string(
                wire + off, (const uint8_t*)SSH_WIRE_KEY_TYPE_NAME,
                sizeof(SSH_WIRE_KEY_TYPE_NAME) - 1);
            off += put_ssh_string(
                wire + off, (const uint8_t*)SSH_WIRE_CURVE_NAME,
                sizeof(SSH_WIRE_CURVE_NAME) - 1);
            off += put_ssh_string(wire + off, point, point_len);

            if (wc_Sha256Hash(wire, (word32)off, fingerprint_out) != 0) {
                return ESP_FAIL;
            }
            result = ESP_OK;
        }
    }

    return result;
}
