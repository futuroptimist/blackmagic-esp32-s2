# wolfSSH feasibility spike component.
#
# This is an ESP-IDF "configuration-only component": when
# CONFIG_EXPERIMENTAL_WOLFSSH_SERVER is not set (the default), it registers
# with no sources at all, so wolfSSL/wolfSSH are never compiled or linked
# into the default build. See docs/design/ssh-feasibility-spike.md.

if(NOT CONFIG_EXPERIMENTAL_WOLFSSH_SERVER)
    idf_component_register()
    return()
endif()

set(WOLFSSL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl")
set(WOLFSSH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wolfssh")

if(NOT EXISTS "${WOLFSSL_DIR}/wolfcrypt/src/aes.c")
    message(FATAL_ERROR
        "CONFIG_EXPERIMENTAL_WOLFSSH_SERVER is enabled, but the wolfssl "
        "submodule at ${WOLFSSL_DIR} looks empty. Run: "
        "git submodule update --init components/wolfssh_spike/wolfssl")
endif()
if(NOT EXISTS "${WOLFSSH_DIR}/src/ssh.c")
    message(FATAL_ERROR
        "CONFIG_EXPERIMENTAL_WOLFSSH_SERVER is enabled, but the wolfssh "
        "submodule at ${WOLFSSH_DIR} looks empty. Run: "
        "git submodule update --init components/wolfssh_spike/wolfssh")
endif()

# --- Required, externally-supplied key material -----------------------
#
# The host key is generated on-device and NVS-persisted (see
# ssh_keystore.c) -- no build-time host key input anymore. The single
# authorized key is still supplied externally and compared directly by
# user_auth_cb(); the future-facing NVS seeding API is not wired yet (real
# enrollment is Phase 2). Never read from a path inside the
# repository, and never fall back to a bundled default key. See
# docs/design/ssh-feasibility-spike.md and scripts/gen_ssh_spike_keys.sh.
if(NOT DEFINED ENV{WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH} OR "$ENV{WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}" STREQUAL "")
    message(FATAL_ERROR
        "CONFIG_EXPERIMENTAL_WOLFSSH_SERVER is enabled but the "
        "WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH environment variable is not set. "
        "It must point at the raw SSH wire-format public-key blob (not the "
        "text .pub line) for the single authorized ECDSA P-256 user key. "
        "Run scripts/gen_ssh_spike_keys.sh to generate one.")
endif()

set(WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH "$ENV{WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}")

if(NOT EXISTS "${WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}")
    message(FATAL_ERROR "WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH does not exist: ${WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}")
endif()

# Copy the externally-supplied key into the build tree under a fixed name,
# so the embedded-binary symbol name below is predictable regardless of
# the caller's original file name or directory. Nothing is copied into the
# source tree -- CMAKE_CURRENT_BINARY_DIR is a build (not source) directory.
set(EMBEDDED_AUTHORIZED_KEY "${CMAKE_CURRENT_BINARY_DIR}/embedded_authorized_key.blob")
configure_file("${WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}" "${EMBEDDED_AUTHORIZED_KEY}" COPYONLY)

# --- Source selection ---------------------------------------------------
#
# wolfSSH does not need wolfSSL's TLS layer (wolfssl/src/*.c) at all -- only
# certman.c (excluded below, we don't use X.509 certs) references it. Only
# wolfcrypt (crypto primitives) is required.
file(GLOB WOLFSSL_SRCS "${WOLFSSL_DIR}/wolfcrypt/src/*.c")

# wolfssh/src/*.c, minus:
#   misc.c       -- inlined by other .c files unless NO_INLINE is defined;
#                    compiling it separately causes duplicate-symbol errors.
#   agent.c      -- SSH agent forwarding (WOLFSSH_AGENT), explicitly unused.
#   wolfscp.c    -- SCP (WOLFSSH_SCP), explicitly unused.
#   wolfsftp.c   -- SFTP (WOLFSSH_SFTP), explicitly unused.
#   wolfterm.c   -- Windows terminal support (USE_WINDOWS_API), N/A on ESP32.
#   certman.c    -- X.509 certificate manager; needs wolfssl/src (TLS layer)
#                    which this spike does not compile. Raw public keys only.
file(GLOB WOLFSSH_SRCS "${WOLFSSH_DIR}/src/*.c")
list(REMOVE_ITEM WOLFSSH_SRCS
    "${WOLFSSH_DIR}/src/misc.c"
    "${WOLFSSH_DIR}/src/agent.c"
    "${WOLFSSH_DIR}/src/wolfscp.c"
    "${WOLFSSH_DIR}/src/wolfsftp.c"
    "${WOLFSSH_DIR}/src/wolfterm.c"
    "${WOLFSSH_DIR}/src/certman.c"
)

idf_component_register(
    SRCS ${WOLFSSL_SRCS} ${WOLFSSH_SRCS} "wolfssh_spike.c" "policy.c" "allocator.c"
         "ssh_keystore.c" "ssh_keystore_codec.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "${WOLFSSL_DIR}" "${WOLFSSH_DIR}" "user_settings" "freertos_shim"
    PRIV_REQUIRES lwip nvs_flash
)

# PRIV_REQUIRES above does add nvs_flash to this component's dependency
# graph, but (observed on this ESP-IDF v4.4.8 checkout) does not reliably
# propagate its own -- or its transitive spi_flash requirement's -- public
# INCLUDE_DIRS to a component that conditionally idf_component_register()s
# based on a Kconfig guard the way this one does. Linking against its
# target directly is the same underlying mechanism PRIV_REQUIRES wraps,
# and does propagate include dirs correctly (including nvs_flash's own
# transitive REQUIRES spi_flash, which nvs_flash.h needs for
# esp_partition.h).
target_link_libraries(${COMPONENT_LIB} PRIVATE idf::nvs_flash)

target_compile_definitions(${COMPONENT_LIB} PRIVATE WOLFSSL_USER_SETTINGS)

target_add_binary_data(${COMPONENT_TARGET} "${EMBEDDED_AUTHORIZED_KEY}" BINARY)
