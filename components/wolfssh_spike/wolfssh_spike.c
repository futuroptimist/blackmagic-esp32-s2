/* wolfssh_spike.c -- experimental, disabled-by-default wolfSSH server for
 * the feasibility spike. See docs/design/ssh-feasibility-spike.md for the
 * full architecture, threat model, and rationale behind every policy
 * decision in this file.
 *
 * Scope, deliberately narrow:
 *   - one listener task plus one persistent session-worker task on port
 *     2222 (the worker is created once, not spawned per connection -- see
 *     connection_task()'s comment)
 *   - one session/channel at a time; any extra connection is accepted and
 *     immediately closed, never left queued
 *   - public-key auth only, fixed username "flipper", one authorized key
 *   - exactly one exec command ("ping" -> "pong\n" + success exit)
 *   - shell, subsystems, forwarding, agent, SCP, SFTP: all rejected. A
 *     pty-req is protocol-acknowledged (the pinned wolfSSH has no pty-req
 *     rejection callback to hook) but that grants nothing: no exec/shell
 *     request is ever serviced through the allocated PTY -- see
 *     channel_req_exec_cb()'s wolfSSH_ChannelIsPty() check below.
 */
#include "wolfssh_spike.h"

#include <stdbool.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <lwip/sockets.h>
#include <esp_log.h>
#include <esp_system.h>
/* heap_caps_get_largest_free_block()/MALLOC_CAP_INTERNAL are available
 * transitively via esp_system.h in this ESP-IDF version -- mirrors
 * main/network-http.c, which uses heap_caps_get_info() the same way. */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssh/ssh.h>
#include <wolfssh/error.h>

#include "policy.h"
#include "allocator.h"
#include "ssh_keystore.h"

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
 * buffer beyond what wolfSSH itself requires internally. The host key is
 * generated on-device and NVS-persisted instead (see ssh_keystore.h); only
 * the authorized-key blob is still build-embedded, as the first-boot NVS
 * seed (real enrollment is Phase 2). */
extern const uint8_t embedded_authorized_key_blob_start[] asm(
    "_binary_embedded_authorized_key_blob_start");
extern const uint8_t embedded_authorized_key_blob_end[] asm(
    "_binary_embedded_authorized_key_blob_end");

static WOLFSSH_CTX* g_ctx = NULL;
static volatile bool g_session_active = false;
static uint32_t (*g_get_station_ip)(void) = NULL;
/* Populated once in wolfssh_spike_start() from ssh_keystore.h's NVS-backed
 * store (seeded from embedded_authorized_key_blob_start/end on first
 * boot) -- see user_auth_cb()'s policy_key_matches() calls below, which
 * compare against this, not the build-embedded blob directly. */
static uint8_t g_authorized_key[SSH_KEYSTORE_AUTH_KEY_BLOB_MAX];
static size_t g_authorized_key_len = 0;
/* Hands one accepted client socket at a time from the listener task to the
 * persistent session-worker task -- see connection_task() below for why
 * this replaced spawning a new task per connection. */
static QueueHandle_t g_session_queue = NULL;
/* Reset per connection in handle_connection(); wolfSSH does not itself
 * expose a configurable max-auth-attempts bound, so this is enforced
 * explicitly here rather than assumed. */
static int g_auth_attempts = 0;

typedef struct {
    WOLFSSH* ssh;
    bool channel_opened;
    /* See policy_claim_exec_once(): must be 0 until the first exec
     * request claims it. wolfSSH's channel-request dispatcher
     * (DoChannelRequest() in the pinned src/internal.c) invokes
     * channelReqExecCb for every "exec" channel request on a channel with
     * no built-in limit -- this is the only thing enforcing "exactly one
     * exec command per connection". */
    int exec_claimed;
    /* True only once the single allowed "ping" exec has been fully
     * serviced: "pong\n" was sent and wolfSSH_SetExitStatus(ssh, 0)
     * reported success. RFC 4254 defines "exit-status" as a
     * server-to-client request, but the pinned DoChannelRequest()
     * (src/internal.c) also accepts it inbound from the client and stores
     * it directly into ssh->exitStatus with no application callback or
     * validation -- so a client could send its own "exit-status" request
     * after a successful ping and silently overwrite the 0 that
     * wolfSSH_shutdown() later sends. handle_connection() reasserts status
     * 0 immediately before shutdown, but only when this flag is true, so a
     * rejected/failed exec is never made to look successful. */
    bool exec_succeeded;
} connection_state_t;

/* ---- resource-checkpoint instrumentation (never logs key material) --- */

static void log_resource_checkpoint(const char* label)
{
    /* min_free_heap_since_boot is esp_get_minimum_free_heap_size(): the
     * lowest free-heap value observed at any point since boot, sampled at
     * this checkpoint -- it is NOT isolated to whatever happened between
     * the previous checkpoint and this one. Treat it as a monotonically
     * non-increasing running low-water-mark, not a per-phase delta. */
    ESP_LOGI(TAG,
             "checkpoint=%s free_heap=%u min_free_heap_since_boot=%u "
             "largest_free_block=%u stack_hwm=%u",
             label,
             (unsigned)esp_get_free_heap_size(),
             (unsigned)esp_get_minimum_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
}

/* Elapsed wall-clock time (via the FreeRTOS tick count, so it is bounded
 * by the same clock as the handshake deadline below) for the complete
 * wolfSSH_accept() handshake+auth loop, logged on both success and
 * failure. Never logs credentials or key material. */
static void log_handshake_duration(TickType_t start_ticks, bool success)
{
    TickType_t elapsed_ticks = xTaskGetTickCount() - start_ticks;

    ESP_LOGI(TAG, "handshake_auth_duration_ms=%u result=%s",
             (unsigned)(elapsed_ticks * portTICK_PERIOD_MS),
             success ? "success" : "failure");
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
                                 g_authorized_key, g_authorized_key_len)) {
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
                             g_authorized_key, g_authorized_key_len)) {
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
        /* Defense in depth, not what actually stops "direct-tcpip" today:
         * with WOLFSSH_FWD undefined, the pinned wolfSSH dispatcher
         * (DoChannelOpen(), src/internal.c) never compiles in the
         * direct-tcpip case, fails the request as OPEN_UNKNOWN_CHANNEL_TYPE
         * before this callback is even invoked, and so this branch is
         * currently unreachable for that request type. It only matters if
         * the set of compiled-in channel types ever changes. */
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

    /* Claim the one allowed exec attempt before any validation or output.
     * A malformed/rejected first command, or a send failure below, must
     * not leave the one-shot open for a retry -- see policy.h. */
    if (state == NULL || !policy_claim_exec_once(&state->exec_claimed)) {
        ESP_LOGW(TAG, "rejecting exec request: no state or already consumed");
        return WS_FATAL_ERROR;
    }

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
    if (state != NULL && state->ssh != NULL &&
        wolfSSH_SetExitStatus(state->ssh, 0) == WS_SUCCESS) {
        /* Only ever set on this success path -- see connection_state_t's
         * exec_succeeded comment for why handle_connection() reasserts
         * this immediately before shutdown. */
        state->exec_succeeded = true;
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
    TickType_t handshake_start_ticks;
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

    handshake_start_ticks = xTaskGetTickCount();
    deadline = handshake_start_ticks + pdMS_TO_TICKS(WOLFSSH_SPIKE_HANDSHAKE_MS +
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
        log_handshake_duration(handshake_start_ticks, false);
        log_resource_checkpoint("after_failed_handshake");
        wolfSSH_free(ssh);
        close(client_sock);
        return;
    }

    log_handshake_duration(handshake_start_ticks, true);
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

    /* The idle-read loop above lets wolfSSH's pinned DoChannelRequest()
     * (src/internal.c) process any further channel requests the client
     * sends, including an inbound "exit-status" request -- which that
     * dispatcher stores directly into ssh->exitStatus with no application
     * callback or validation, even though RFC 4254 defines "exit-status"
     * server-to-client. Reassert the server-owned status immediately
     * before shutdown so a client-supplied exit-status cannot silently
     * replace the result of a genuinely successful "ping"; only ever
     * reasserts 0, and only when state.exec_succeeded is true, so a
     * rejected/failed exec is never made to look successful. */
    if (state.exec_succeeded) {
        wolfSSH_SetExitStatus(ssh, 0);
    }
    wolfSSH_shutdown(ssh);
    wolfSSH_free(ssh);
    close(client_sock);

    log_resource_checkpoint("after_disconnect");
}

/* Persistent worker task, created once in wolfssh_spike_start() -- not
 * spawned and torn down per connection. Creating a fresh
 * WOLFSSH_SPIKE_TASK_STACK (12 KiB) task for every connection let
 * FreeRTOS's task-deletion cleanup (performed asynchronously by the IDLE
 * task, not synchronously at vTaskDelete()) lag behind rapid back-to-back
 * connections: xTaskCreate() for the next session could then fail under
 * transient heap pressure, and the failure path already in place closed
 * the just-accepted socket before any SSH bytes were exchanged -- observed
 * on real hardware as "Connection reset by peer" on most cycles of a
 * 100-cycle soak test. Blocking on a depth-1 queue for the next
 * handed-off client socket avoids the repeated allocation/teardown
 * entirely while keeping the same one-session-at-a-time behavior. */
static void connection_task(void* arg)
{
    int client_sock;
    (void)arg;

    for (;;) {
        if (xQueueReceive(g_session_queue, &client_sock, portMAX_DELAY) == pdTRUE) {
            handle_connection(client_sock);
            g_session_active = false;
        }
    }
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
        if (xQueueSend(g_session_queue, &client_sock, 0) != pdTRUE) {
            /* Queue depth is 1 and g_session_active gates every send, so
             * this should never actually happen -- fail closed rather than
             * leave the accepted socket open with nothing servicing it. */
            ESP_LOGE(TAG, "failed to hand off session (queue full)");
            g_session_active = false;
            close(client_sock);
        }
    }
}

void wolfssh_spike_start(uint32_t (*get_station_ip)(void))
{
    static uint8_t host_key_der[SSH_KEYSTORE_HOST_KEY_DER_MAX];
    size_t host_key_len = 0;

    if (get_station_ip == NULL) {
        ESP_LOGE(TAG, "station IP callback must not be NULL");
        return;
    }
    g_get_station_ip = get_station_ip;

    /* Logged here, before wolfSSH_Init() or any wolfSSH allocation, so the
     * label matches its actual position: this is the pre-initialization
     * baseline, not a post-setup snapshot. */
    log_resource_checkpoint("before_ssh_init");

    wolfSSH_Init();

    g_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (g_ctx == NULL) {
        ESP_LOGE(TAG, "wolfSSH_CTX_new failed");
        return;
    }

    /* Loads the persisted host key from NVS, generating and persisting a
     * fresh one on first boot (or just after a factory reset) -- see
     * ssh_keystore.h. Fails closed (does not start SSH) if stored key
     * material exists but fails integrity validation; never regenerates
     * in that case. */
    if (ssh_keystore_load_or_generate_host_key(
            host_key_der, sizeof(host_key_der), &host_key_len) != ESP_OK) {
        ESP_LOGE(TAG, "host key unavailable; refusing to start SSH");
        wolfSSH_CTX_free(g_ctx);
        g_ctx = NULL;
        return;
    }

    /* Raw SEC1 "EC PRIVATE KEY" DER, not PEM -- both
     * ssh_keystore_load_or_generate_host_key() and the pinned wolfSSH's
     * WOLFSSH_FORMAT_PEM path for private keys (compiled only under
     * #ifdef WOLFSSH_CERTS, which this spike does not define -- no X.509
     * certificate support, see user_settings.h) agree on
     * WOLFSSH_FORMAT_ASN1. */
    if (wolfSSH_CTX_UsePrivateKey_buffer(g_ctx, host_key_der,
                                          (word32)host_key_len,
                                          WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
        ESP_LOGE(TAG, "failed to load host key");
        wolfSSH_CTX_free(g_ctx);
        g_ctx = NULL;
        return;
    }

    {
        /* Logged once per boot so "stable fingerprint across ordinary
         * reboots" is concretely verifiable by diffing this line across
         * reboots. Never logs the private key itself. Must only ever be
         * derived from the key just loaded above -- this must never
         * trigger key generation itself, or fingerprint stability would
         * silently regress.
         *
         * Formatted as OpenSSH's "SHA256:<base64, no padding>" rather than
         * raw hex, so this line can be pasted directly as
         * run_ssh_spike_hardware_validation.sh's --host-key-fingerprint
         * argument -- that script always compares against
         * `ssh-keygen -lf` output on the *live* scanned key, which is
         * always in this format; see docs/design/ssh-feasibility-spike.md
         * section 8's hardware-validation prerequisites. */
        uint8_t fingerprint[SSH_KEYSTORE_FINGERPRINT_LEN];
        if (ssh_keystore_host_key_fingerprint_sha256(
                host_key_der, host_key_len, fingerprint) == ESP_OK) {
            char b64[((SSH_KEYSTORE_FINGERPRINT_LEN + 2) / 3) * 4 + 1];
            word32 b64_len = sizeof(b64);
            if (Base64_Encode_NoNl(fingerprint, SSH_KEYSTORE_FINGERPRINT_LEN,
                                    (byte*)b64, &b64_len) == 0) {
                while (b64_len > 0 && b64[b64_len - 1] == '=') {
                    b64_len--;
                }
                b64[b64_len] = '\0';
                ESP_LOGI(TAG, "host key fingerprint: SHA256:%s", b64);
            } else {
                ESP_LOGW(TAG, "failed to base64-encode host key fingerprint");
            }
        } else {
            ESP_LOGW(TAG, "failed to compute host key fingerprint");
        }
    }

    /* Loads the persisted authorized key from NVS, seeding NVS from the
     * build-embedded key on first boot (or just after a factory reset) --
     * see ssh_keystore.h. Real enrollment is Phase 2; this is the
     * interim, build-time-seeded key. Fails closed on stored corruption,
     * same as the host key above. */
    if (ssh_keystore_load_or_seed_authorized_key(
            embedded_authorized_key_blob_start,
            (size_t)(embedded_authorized_key_blob_end -
                     embedded_authorized_key_blob_start),
            g_authorized_key, sizeof(g_authorized_key), &g_authorized_key_len) !=
        ESP_OK) {
        ESP_LOGE(TAG, "authorized key unavailable; refusing to start SSH");
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

    /* Created once, here -- see connection_task()'s comment for why this
     * is a persistent worker rather than spawned per connection. Must
     * exist before wolfssh_spike_task() starts accepting, since its first
     * accepted connection is handed off through this same queue. */
    g_session_queue = xQueueCreate(1, sizeof(int));
    if (g_session_queue == NULL) {
        ESP_LOGE(TAG, "failed to create session queue");
        wolfSSH_CTX_free(g_ctx);
        g_ctx = NULL;
        return;
    }

    TaskHandle_t session_task_handle = NULL;
    if (xTaskCreate(connection_task, "wolfssh_session",
                     WOLFSSH_SPIKE_TASK_STACK, NULL,
                     WOLFSSH_SPIKE_TASK_PRIORITY,
                     &session_task_handle) != pdPASS) {
        ESP_LOGE(TAG, "failed to create session worker task");
        vQueueDelete(g_session_queue);
        g_session_queue = NULL;
        wolfSSH_CTX_free(g_ctx);
        g_ctx = NULL;
        g_session_active = false;
        return;
    }

    if (xTaskCreate(wolfssh_spike_task, "wolfssh_spike",
                     WOLFSSH_SPIKE_TASK_STACK, NULL,
                     WOLFSSH_SPIKE_TASK_PRIORITY, NULL) != pdPASS) {
        ESP_LOGE(TAG, "failed to create listener task");
        vTaskDelete(session_task_handle);
        vQueueDelete(g_session_queue);
        g_session_queue = NULL;
        wolfSSH_CTX_free(g_ctx);
        g_ctx = NULL;
        g_session_active = false;
        return;
    }
}
