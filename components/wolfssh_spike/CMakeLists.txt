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
# Never read from a path inside the repository, and never fall back to a
# bundled default key. See docs/design/ssh-feasibility-spike.md and
# scripts/gen_ssh_spike_keys.sh.
if(NOT DEFINED ENV{WOLFSSH_SPIKE_HOST_KEY_PATH} OR "$ENV{WOLFSSH_SPIKE_HOST_KEY_PATH}" STREQUAL "")
    message(FATAL_ERROR
        "CONFIG_EXPERIMENTAL_WOLFSSH_SERVER is enabled but the "
        "WOLFSSH_SPIKE_HOST_KEY_PATH environment variable is not set. It "
        "must point at a PEM-encoded ECDSA P-256 host private key generated "
        "OUTSIDE this repository. Run scripts/gen_ssh_spike_keys.sh to "
        "generate a disposable developer key.")
endif()
if(NOT DEFINED ENV{WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH} OR "$ENV{WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}" STREQUAL "")
    message(FATAL_ERROR
        "CONFIG_EXPERIMENTAL_WOLFSSH_SERVER is enabled but the "
        "WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH environment variable is not set. "
        "It must point at the raw SSH wire-format public-key blob (not the "
        "text .pub line) for the single authorized ECDSA P-256 user key. "
        "Run scripts/gen_ssh_spike_keys.sh to generate one.")
endif()

set(WOLFSSH_SPIKE_HOST_KEY_PATH "$ENV{WOLFSSH_SPIKE_HOST_KEY_PATH}")
set(WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH "$ENV{WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}")

if(NOT EXISTS "${WOLFSSH_SPIKE_HOST_KEY_PATH}")
    message(FATAL_ERROR "WOLFSSH_SPIKE_HOST_KEY_PATH does not exist: ${WOLFSSH_SPIKE_HOST_KEY_PATH}")
endif()
if(NOT EXISTS "${WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}")
    message(FATAL_ERROR "WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH does not exist: ${WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH}")
endif()

# Copy the externally-supplied keys into the build tree under fixed names,
# so the embedded-binary symbol names below are predictable regardless of
# the caller's original file name or directory. Nothing is copied into the
# source tree -- CMAKE_CURRENT_BINARY_DIR is a build (not source) directory.
set(EMBEDDED_HOST_KEY "${CMAKE_CURRENT_BINARY_DIR}/embedded_host_key.pem")
set(EMBEDDED_AUTHORIZED_KEY "${CMAKE_CURRENT_BINARY_DIR}/embedded_authorized_key.blob")
configure_file("${WOLFSSH_SPIKE_HOST_KEY_PATH}" "${EMBEDDED_HOST_KEY}" COPYONLY)
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
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "${WOLFSSL_DIR}" "${WOLFSSH_DIR}" "user_settings" "freertos_shim"
    PRIV_REQUIRES lwip
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE WOLFSSL_USER_SETTINGS)

target_add_binary_data(${COMPONENT_TARGET} "${EMBEDDED_HOST_KEY}" BINARY)
target_add_binary_data(${COMPONENT_TARGET} "${EMBEDDED_AUTHORIZED_KEY}" BINARY)
