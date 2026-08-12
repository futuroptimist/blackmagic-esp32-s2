/* user_settings.h -- minimal wolfSSL/wolfSSH server profile for the
 * wolfSSH feasibility spike.
 *
 * PRIV_INCLUDE_DIRS-only: never added to a public INCLUDE_DIRS, so these
 * macros do not leak outside this component. See
 * docs/design/ssh-feasibility-spike.md, section 6 and 7, for the reasoning
 * behind each setting below -- this file intentionally has a much smaller
 * surface than wolfSSL's own multi-target Espressif example
 * (components/wolfssh_spike/wolfssh/ide/Espressif/ESP-IDF/examples),
 * which supports many chips, examples, and both RSA and ECC. This spike
 * needs exactly one profile: ECDSA P-256 / ECDH P-256 / AES-GCM+CTR /
 * SHA-256, server-only, no TLS, no filesystem, no threading beyond the one
 * FreeRTOS task that owns the connection.
 */
#ifndef WOLFSSH_SPIKE_USER_SETTINGS_H
#define WOLFSSH_SPIKE_USER_SETTINGS_H

#include "sdkconfig.h"

#define WOLFSSL_ESPIDF

/* wolfSSL's WOLFSSL_ESPIDF defaults want an Espressif-specific allocator
 * wrapper (wc_pvPortMalloc() et al., from
 * wolfcrypt/src/port/Espressif/esp_sdk_mem_lib.c) when XMALLOC_USER isn't
 * defined. This spike deliberately does not compile the Espressif port
 * directory at all (see CMakeLists.txt) to keep the first working build's
 * surface area small. XMALLOC_USER tells wolfssl/wolfcrypt/types.h to
 * declare `extern` prototypes for XMALLOC/XFREE/XREALLOC instead of
 * defining its own macros -- the actual implementations (thin wrappers
 * over plain newlib malloc/free/realloc, used the same way as the rest of
 * this repository's own code) live in allocator.c. This keeps allocations
 * on internal SRAM (matching every existing service; CONFIG_SPIRAM_USE_MALLOC
 * is not set in this project's sdkconfig, so routing to PSRAM would need
 * explicit heap_caps_malloc() calls this spike does not make -- see
 * docs/design/ssh-feasibility-spike.md, "RAM is the real open risk"). */
#define XMALLOC_USER

/* This profile never compiles wolfSSL's TLS/SSL protocol layer
 * (wolfssl/src is not in this component's source list -- see
 * CMakeLists.txt) -- only wolfCrypt (crypto primitives) is used, by
 * wolfSSH. WOLFCRYPT_ONLY tells wolfSSL's settings.h sanity checks that,
 * so they don't assume a TLS-capable build (e.g. requiring MD5+SHA-1 for
 * "old TLS" support, which this profile deliberately excludes). */
#define WOLFCRYPT_ONLY

/* WOLFSSL_ESP32 is required for wc_GenerateSeed() (wolfcrypt/src/random.c)
 * to use the ESP-IDF hardware TRNG (esp_random(), from ESP-IDF's own
 * esp_system.h/esp_random.h) instead of failing to link at all -- there is
 * no generic/portable software fallback entropy source in this wolfCrypt
 * build, and a real hardware entropy source is exactly what this spike's
 * design requires ("Ensure the random source uses the ESP-IDF-supported
 * entropy path", docs/design/ssh-feasibility-spike.md section 7).
 *
 * WOLFSSL_ESP32 also gates AES/SHA/RSA *hardware acceleration* call sites
 * elsewhere (aes.c, sha256.c, ...) into wolfcrypt/src/port/Espressif,
 * which this spike deliberately does not compile (see CMakeLists.txt) to
 * keep the first working build's surface area small. The NO_ESP32_CRYPT
 * family below disables exactly those call sites, so only the RNG entropy
 * path is active and everything else stays portable software. Enabling
 * AES/SHA/RSA hardware acceleration is a Phase 1 production optimization,
 * not attempted in this feasibility spike. */
#define WOLFSSL_ESP32
#define NO_ESP32_CRYPT
#define NO_WOLFSSL_ESP32_CRYPT_HASH
#define NO_WOLFSSL_ESP32_CRYPT_AES
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD

/* wolfSSH server only; no client role compiled in this profile. */
#define WOLFSSH_NO_WOLFSSH_CLIENT

/* No RSA at all -- ECDSA/ECDH only. */
#define NO_RSA
#define WOLFSSH_NO_RSA

/* No traditional Diffie-Hellman group exchange -- ECDH only. */
#define NO_DH
#define WOLFSSH_NO_DH
#define WOLFSSH_NO_DH_GROUP_EXCHANGE

/* Ed25519 / Curve25519: not enabled. These are opt-in in wolfSSL (no
 * HAVE_ED25519 / HAVE_CURVE25519 define below), so omitting them is
 * sufficient -- no explicit NO_* macro is needed for either. */
#define WOLFSSH_NO_ED25519
#define WOLFSSH_NO_CURVE25519

/* Post-quantum (ML-KEM hybrid) key exchange: opt-in in wolfSSH, not
 * enabled here. */
#define WOLFSSH_NO_MLKEM

/* ECDSA / ECDH, restricted to the P-256 curve only. */
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define WOLFSSH_NO_ECC_SHA224 /* only sha2-256 signatures needed */

/* AES-GCM primary, AES-CTR fallback, per the modern minimal profile. No
 * AES-CBC, no other block cipher. */
#define HAVE_AESGCM
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_128
#define WOLFSSL_AES_256
#define NO_AES_CBC

/* SHA-256 only. No MD5, no SHA-1, no SHA-512/SHA-3 (wolfSSH's transport
 * layer needs SHA-256 for the P-256 key-exchange hash and host-key
 * signature; nothing here needs a larger hash). */
#define NO_MD5
#define NO_SHA
#define WOLFSSH_NO_SHA1_KDF
#define WOLFSSH_NO_HMAC_SHA1
#define WOLFSSH_NO_HMAC_SHA1_96

/* No RC4, no 3DES, no legacy ciphers. */
#define NO_RC4
#define NO_DES3

/* No X.509 certificates -- raw public keys only (WOLFSSH_CERTS not
 * defined). certman.c is also excluded from the component's source list
 * in CMakeLists.txt for the same reason (it needs wolfSSL's TLS layer,
 * which this spike does not compile at all). */

/* No SCP, SFTP, agent forwarding, or TCP forwarding. Source files for all
 * four (wolfscp.c, wolfsftp.c, agent.c) are excluded from the component's
 * source list in CMakeLists.txt -- these macros are defense in depth, not
 * the only enforcement. */
/* WOLFSSH_SCP, WOLFSSH_SFTP, WOLFSSH_AGENT, WOLFSSH_FWD: intentionally
 * never defined. */

/* WOLFSSH_TERM gates more than terminal *emulation* (wolfterm.c, which
 * this spike excludes from its source list regardless -- see
 * CMakeLists.txt): it also gates wolfSSH_ChannelIsPty() and
 * wolfSSH_SetExitStatus()/wolfSSH_GetExitStatus(), which are simple
 * protocol-bookkeeping accessors (was a pty-req received; what exit
 * status to report) this spike's exec callback needs regardless of
 * whether a PTY is ever actually allocated -- it isn't: the shell-request
 * callback rejects unconditionally, so a pty-req is parsed and recorded
 * (protocol-compliant bookkeeping only, no PTY device exists on this
 * target) but never leads to an actual shell/terminal session. */
#define WOLFSSH_TERM

/* Single connection, single FreeRTOS task drives the whole session --
 * no internal threading inside wolfSSL/wolfSSH. */
#define SINGLE_THREADED

/* No filesystem -- host key and authorized key are both build-time
 * embedded binary buffers (see CMakeLists.txt EMBED_FILES-equivalent
 * target_add_binary_data calls), loaded via *_buffer() APIs only. */
#define NO_FILESYSTEM

/* No TLS session cache -- this spike does not use TLS at all. */
#define NO_SESSION_CACHE

/* Trade stack for heap: keeps the FreeRTOS task's required stack size
 * (a scarce, hard-bounded resource) smaller at the cost of more heap
 * allocations, which are easier to size after measuring (see
 * docs/design/ssh-feasibility-spike.md section 8). */
#define WOLFSSL_SMALL_STACK

/* Portable big-integer math (not the single-precision/assembly-optimized
 * path) -- proven on all platforms including Xtensa via generic C, at the
 * cost of some size/speed relative to SP math. Switching to SP math for
 * ECC-only builds is a Phase 1 production optimization once this spike's
 * build is verified working. */
#define USE_FAST_MATH

/* Small session/window buffers appropriate for an embedded target -- see
 * wolfSSH's own bundled ESP-IDF example
 * (ide/Espressif/ESP-IDF/examples/wolfssh_echoserver) for the precedent
 * of DEFAULT_WINDOW_SZ 2000; this spike sets the equivalent via
 * wolfSSH_CTX_SetWindowPacketSize() at runtime instead of this macro, so
 * it can be tuned without a rebuild during hardware measurement.
 */

/* No debug builds by default in this profile; enable manually while
 * developing if needed. Never enable in a build whose logs might be
 * captured/shared -- wolfSSL/wolfSSH debug logging is not designed to
 * redact key material. */
/* #define DEBUG_WOLFSSL */
/* #define DEBUG_WOLFSSH */

#endif /* WOLFSSH_SPIKE_USER_SETTINGS_H */
