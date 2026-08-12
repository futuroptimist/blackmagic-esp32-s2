/* wolfssh_spike.c -- experimental, disabled-by-default wolfSSH server for
 * the feasibility spike. See docs/design/ssh-feasibility-spike.md for the
 * full architecture, threat model, and rationale behind every policy
 * decision in this file.
 *
 * Scope, deliberately narrow:
 *   - one listener task plus at most one session task on port 2222
 *   - one session/channel at a time; any extra connection is accepted and
 *     immediately closed, never left queued
 *   - public-key auth only, fixed username "flipper", one authorized key
 *   - exactly one exec command ("ping" -> "pong\n" + success exit)
 *   - shell, PTY, subsystems, forwarding, agent, SCP, SFTP: all rejected
 */
#include "wolfssh_spike.h"

#include <stdbool.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lwip/sockets.h>
#include <esp_log.h>
#include <esp_system.h>
/* heap_caps_get_largest_free_block()/MALLOC_CAP_INTERNAL are available
 * transitively via esp_system.h in this ESP-IDF version -- mirrors
 * main/network-http.c, which uses heap_caps_get_info() the same way. */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssh/ssh.h>
#include <wolfssh/error.h>

#include "policy.h"
#include "allocator.h"

static const char* TAG = "wolfssh_spike";

#define WOLFSSH_SPIKE_PORT            2222
#define WOLFSSH_SPIKE_TASK_STACK      12288
#define WOLFSSH_SPIKE_TASK_PRIORITY   5
#define WOLFSSH_SPIKE_WINDOW_SZ       2000   /* see design doc section 6 */
#define WOLFSSH_SPIKE_PACKET_SZ       1200
#define WOLFSSH_SPIKE_HANDSHAKE_MS    10000
#define WOLFSSH_SPIKE_AUTH_MS         10000
#define WOLFSSH_SPIKE_IDLE_MS         30000
#define WOLFSSH_SPIKE_IO_TIMEOUT_S    5
#define WOLFSSH_SPIKE_MAX_AUTH_TRIES  3

/* Build-time embedded key material -- see CMakeLists.txt
 * target_add_binary_data() calls. Never logged; never copied to a mutable
 * buffer beyond what wolfSSH itself requires internally. */
extern const uint8_t embedded_host_key_pem_start[] asm(
    "_binary_embedded_host_key_pem_start");
extern const uint8_t embedded_host_key_pem_end[] asm(
    "_binary_embedded_host_key_pem_end");
extern const uint8_t embedded_authorized_key_blob_start[] asm(
    "_binary_embedded_authorized_key_blob_start");
extern const uint8_t embedded_authorized_key_blob_end[] asm(
    "_binary_embedded_authorized_key_blob_end");

static WOLFSSH_CTX* g_ctx = NULL;
static volatile bool g_session_active = false;
static uint32_t (*g_get_station_ip)(void) = NULL;
/* Reset per connection in handle_connection(); wolfSSH does not itself
 * expose a configurable max-auth-attempts bound, so this is enforced
 * explicitly here rather than assumed. */
static int g_auth_attempts = 0;

typedef struct {
    WOLFSSH* ssh;
    bool channel_opened;
} connection_state_t;

/* ---- resource-checkpoint instrumentation (never logs key material) --- */

static void log_resource_checkpoint(const char* label)
{
    ESP_LOGI(TAG,
             "checkpoint=%s free_heap=%u min_free_heap=%u "
             "largest_free_block=%u stack_hwm=%u",
             label,
             (unsigned)esp_get_free_heap_size(),
             (unsigned)esp_get_minimum_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
}

/* ---- authentication: public key only, fixed user, single key --------- */

static int auth_types_cb(WOLFSSH* ssh, void* ctx)
{
    (void)ssh;
    (void)ctx;
    /* Advertise/accept public-key auth only. No password, no
     * keyboard-interactive, no "none". */
    return WOLFSSH_USERAUTH_PUBLICKEY;
}

static int user_auth_cb(byte authType, WS_UserAuthData* authData, void* ctx)
{
    (void)ctx;

    if (authType != WOLFSSH_USERAUTH_PUBLICKEY) {
        /* Should be unreachable given auth_types_cb() above, but this
         * callback must not depend on that -- reject explicitly. */
        return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
    }

    if (!policy_username_ok((const char*)authData->username,
                             authData->usernameSz)) {
        return WOLFSSH_USERAUTH_INVALID_USER;
    }

    if (!authData->sf.publicKey.hasSignature) {
        /* wolfSSH calls this callback twice per public-key attempt: once
         * to ask "is this key acceptable" (no signature yet) and again
         * with a verified signature. Reject unknown keys at the first
         * pass so no work is wasted verifying a signature for a key we
         * will not accept regardless. */
        if (!policy_key_matches(authData->sf.publicKey.publicKey,
                                 authData->sf.publicKey.publicKeySz,
                                 embedded_authorized_key_blob_start,
                                 (size_t)(embedded_authorized_key_blob_end -
                                          embedded_authorized_key_blob_start))) {
            return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
        }
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    /* Second pass: wolfSSH has already cryptographically verified the
     * signature against the key presented in the first pass before
     * calling us again. This is a real authentication attempt -- bound
     * it explicitly and tear down the connection once exceeded. */
    g_auth_attempts++;
    if (g_auth_attempts > WOLFSSH_SPIKE_MAX_AUTH_TRIES) {
        ESP_LOGW(TAG, "too many authentication attempts, failing closed");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (!policy_key_matches(authData->sf.publicKey.publicKey,
                             authData->sf.publicKey.publicKeySz,
                             embedded_authorized_key_blob_start,
                             (size_t)(embedded_authorized_key_blob_end -
                                      embedded_authorized_key_blob_start))) {
        return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
    }
    return WOLFSSH_USERAUTH_SUCCESS;
}

/* ---- channel policy: one "session" channel, explicit rejections ------ */

static int channel_open_cb(WOLFSSH_CHANNEL* channel, void* ctx)
{
    const char* channelType;
    connection_state_t* state = (connection_state_t*)ctx;

    channelType = wolfSSH_ChannelGetType(channel);
    if (channelType == NULL || strcmp(channelType, "session") != 0) {
        /* Rejects "direct-tcpip"/forwarded-channel opens explicitly, in
         * addition to WOLFSSH_FWD never being compiled in. */
        ESP_LOGW(TAG, "rejecting non-session channel open");
        return WS_FATAL_ERROR;
    }
    if (state == NULL || state->channel_opened) {
        ESP_LOGW(TAG, "rejecting additional session channel");
        return WS_FATAL_ERROR;
    }
    state->channel_opened = true;
    return WS_SUCCESS;
}

static int channel_req_shell_cb(WOLFSSH_CHANNEL* channel, void* ctx)
{
    (void)channel;
    (void)ctx;
    ESP_LOGW(TAG, "rejecting shell request");
    return WS_FATAL_ERROR;
}

static int channel_req_subsys_cb(WOLFSSH_CHANNEL* channel, void* ctx)
{
    (void)channel;
    (void)ctx;
    ESP_LOGW(TAG, "rejecting subsystem request");
    return WS_FATAL_ERROR;
}

static int channel_req_exec_cb(WOLFSSH_CHANNEL* channel, void* ctx)
{
    /* ctx holds per-connection state, set via wolfSSH_SetChannelReqCtx().
     * The allocation wrapper retains the requested size because wolfSSH's
     * public command accessor exposes the bytes but not their SSH protocol
     * length. Using that size (minus wolfSSH's trailing NUL) prevents an
     * embedded NUL from truncating the command during policy validation. */
    connection_state_t* state = (connection_state_t*)ctx;
    const char* command;
    size_t command_allocation_size;

    if (wolfSSH_ChannelIsPty(channel)) {
        ESP_LOGW(TAG, "rejecting exec with PTY allocated");
        return WS_FATAL_ERROR;
    }

    command = wolfSSH_ChannelGetSessionCommand(channel);
    command_allocation_size = wolfssh_spike_allocation_size(command);
    if (command == NULL ||
        command_allocation_size == 0 ||
        !policy_command_allowed(command, command_allocation_size - 1)) {
        ESP_LOGW(TAG, "rejecting unsupported exec command");
        return WS_FATAL_ERROR;
    }

    if (wolfSSH_ChannelSend(channel, (const byte*)"pong\n", 5) < 0) {
        return WS_FATAL_ERROR;
    }
    if (state != NULL && state->ssh != NULL) {
        wolfSSH_SetExitStatus(state->ssh, 0);
    }
    return WS_SUCCESS;
}

/* ---- one accepted connection: handshake, auth, one exec, cleanup ----- */

static void handle_connection(int client_sock)
{
    WOLFSSH* ssh;
    connection_state_t state = {0};
    int ret;
    TickType_t deadline;
    struct timeval io_timeout = {.tv_sec = WOLFSSH_SPIKE_IO_TIMEOUT_S,
                                  .tv_usec = 0};

    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &io_timeout,
               sizeof(io_timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &io_timeout,
               sizeof(io_timeout));

    g_auth_attempts = 0;

    ssh = wolfSSH_new(g_ctx);
    if (ssh == NULL) {
        ESP_LOGE(TAG, "wolfSSH_new failed");
        close(client_sock);
        return;
    }
    wolfSSH_set_fd(ssh, client_sock);
    state.ssh = ssh;
    /* See channel_req_exec_cb(): this is how it recovers a WOLFSSH* from a
     * WOLFSSH_CHANNEL*. */
    wolfSSH_SetChannelOpenCtx(ssh, &state);
    wolfSSH_SetChannelReqCtx(ssh, &state);

    log_resource_checkpoint("before_handshake");

    deadline = xTaskGetTickCount() + pdMS_TO_TICKS(WOLFSSH_SPIKE_HANDSHAKE_MS +
                                                     WOLFSSH_SPIKE_AUTH_MS);
    do {
        ret = wolfSSH_accept(ssh);
        if (ret == WS_SUCCESS) {
            break;
        }
        if (ret != WS_WANT_READ && ret != WS_WANT_WRITE) {
            ESP_LOGW(TAG, "wolfSSH_accept failed: %d", ret);
            break;
        }
    } while (xTaskGetTickCount() < deadline);

    if (ret != WS_SUCCESS) {
        ESP_LOGW(TAG, "handshake/auth did not complete (ret=%d)", ret);
        log_resource_checkpoint("after_failed_handshake");
        wolfSSH_free(ssh);
        close(client_sock);
        return;
    }

    log_resource_checkpoint("after_auth");

    /* One exec request is serviced by channel_req_exec_cb() above; there
     * is nothing further to pump here besides letting wolfSSH process the
     * channel lifecycle to completion or idle-timeout. wolfSSH_stream_read
     * with a bounded number of idle iterations stands in for an explicit
     * idle timeout, since no dedicated idle-timeout API is exposed. */
    {
        byte scratch[1];
        TickType_t idle_deadline =
            xTaskGetTickCount() + pdMS_TO_TICKS(WOLFSSH_SPIKE_IDLE_MS);
        while (xTaskGetTickCount() < idle_deadline) {
            ret = wolfSSH_stream_read(ssh, scratch, sizeof(scratch));
            if (ret <= 0) {
                break;
            }
        }
    }

    wolfSSH_shutdown(ssh);
    wolfSSH_free(ssh);
    close(client_sock);

    log_resource_checkpoint("after_disconnect");
}

static void connection_task(void* arg)
{
    int client_sock = (int)(intptr_t)arg;

    handle_connection(client_sock);
    g_session_active = false;
    vTaskDelete(NULL);
}

/* ---- listener task: accept-and-reject-if-busy, poll for IP first ----- */

static void wolfssh_spike_task(void* arg)
{
    int listen_sock;
    struct sockaddr_in addr;
    int opt = 1;
    (void)arg;

    while (g_get_station_ip() == 0) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    ESP_LOGI(TAG, "station IP available, starting listener");

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "socket() failed");
        vTaskDelete(NULL);
        return;
    }
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(WOLFSSH_SPIKE_PORT);

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(listen_sock, 1) != 0) {
        ESP_LOGE(TAG, "bind/listen failed on port %d", WOLFSSH_SPIKE_PORT);
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    log_resource_checkpoint("after_listener_init");
    ESP_LOGI(TAG, "listening on port %d", WOLFSSH_SPIKE_PORT);

    for (;;) {
        int client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock < 0) {
            continue;
        }
        if (g_session_active) {
            /* Second simultaneous connection: accept it only to reject
             * it immediately, rather than leaving it queued in the TCP
             * backlog until the active session ends. */
            ESP_LOGW(TAG, "rejecting second simultaneous connection");
            close(client_sock);
            continue;
        }

        g_session_active = true;
        if (xTaskCreate(connection_task, "wolfssh_session",
                        WOLFSSH_SPIKE_TASK_STACK, (void*)(intptr_t)client_sock,
                        WOLFSSH_SPIKE_TASK_PRIORITY, NULL) != pdPASS) {
            ESP_LOGE(TAG, "failed to create session task");
            g_session_active = false;
            close(client_sock);
        }
    }
}

void wolfssh_spike_start(uint32_t (*get_station_ip)(void))
{
    size_t host_key_len = (size_t)(embedded_host_key_pem_end -
                                    embedded_host_key_pem_start);

    if (get_station_ip == NULL) {
        ESP_LOGE(TAG, "station IP callback must not be NULL");
        return;
    }
    g_get_station_ip = get_station_ip;

    wolfSSH_Init();

    g_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (g_ctx == NULL) {
        ESP_LOGE(TAG, "wolfSSH_CTX_new failed");
        return;
    }

    if (wolfSSH_CTX_UsePrivateKey_buffer(g_ctx, embedded_host_key_pem_start,
                                          (word32)host_key_len,
                                          WOLFSSH_FORMAT_PEM) != WS_SUCCESS) {
        ESP_LOGE(TAG, "failed to load embedded host key");
        wolfSSH_CTX_free(g_ctx);
        g_ctx = NULL;
        return;
    }

    /* Restrict algorithm lists explicitly rather than accepting every
     * compiled algorithm -- P-256 / SHA-256 / AES-GCM profile only. */
    wolfSSH_CTX_SetAlgoListKex(g_ctx, "ecdh-sha2-nistp256");
    wolfSSH_CTX_SetAlgoListKey(g_ctx, "ecdsa-sha2-nistp256");
    wolfSSH_CTX_SetAlgoListCipher(g_ctx, "aes256-gcm@openssh.com");
    /* AES-GCM is an AEAD cipher (integrity is folded into the cipher, no
     * separate MAC pass), but wolfSSH's algorithm negotiation still wants
     * a legal MAC name in the list; hmac-sha2-256 is not actually used
     * once aes256-gcm@openssh.com is negotiated. */
    wolfSSH_CTX_SetAlgoListMac(g_ctx, "hmac-sha2-256");

    wolfSSH_CTX_SetWindowPacketSize(g_ctx, WOLFSSH_SPIKE_WINDOW_SZ,
                                     WOLFSSH_SPIKE_PACKET_SZ);

    wolfSSH_SetUserAuthTypes(g_ctx, auth_types_cb);
    wolfSSH_SetUserAuth(g_ctx, user_auth_cb);

    wolfSSH_CTX_SetChannelOpenCb(g_ctx, channel_open_cb);
    wolfSSH_CTX_SetChannelReqShellCb(g_ctx, channel_req_shell_cb);
    wolfSSH_CTX_SetChannelReqExecCb(g_ctx, channel_req_exec_cb);
    wolfSSH_CTX_SetChannelReqSubsysCb(g_ctx, channel_req_subsys_cb);

    log_resource_checkpoint("before_ssh_init");

    xTaskCreate(wolfssh_spike_task, "wolfssh_spike", WOLFSSH_SPIKE_TASK_STACK,
                NULL, WOLFSSH_SPIKE_TASK_PRIORITY, NULL);
}
