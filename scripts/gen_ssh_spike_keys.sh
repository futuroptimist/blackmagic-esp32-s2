#!/usr/bin/env bash
# Generates disposable ECDSA P-256 developer keys for the wolfSSH
# feasibility spike (CONFIG_EXPERIMENTAL_WOLFSSH_SERVER).
#
# Writes to a caller-supplied directory, or a fresh mktemp directory if none
# is given. Never writes inside this repository -- these are the two
# externally-supplied inputs CMakeLists.txt requires
# (WOLFSSH_SPIKE_HOST_KEY_PATH / WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH); nothing
# it produces should ever be committed.
#
# Usage:
#   scripts/gen_ssh_spike_keys.sh [output-directory]
#   eval "$(scripts/gen_ssh_spike_keys.sh)"   # sets both env vars directly
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: gen_ssh_spike_keys.sh [output-directory]

Generates disposable ECDSA P-256 developer keys for the wolfSSH feasibility
spike: a host private key and one authorized user key pair. If no output
directory is given, a fresh directory is created under TMPDIR (or /tmp).

Prints two `export` lines to stdout (suitable for `eval "$(...)"`) and
human-readable paths to stderr. Never prints key contents.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUTDIR="${1:-}"
if [[ -z "${OUTDIR}" ]]; then
    OUTDIR="$(mktemp -d "${TMPDIR:-/tmp}/wolfssh-spike-keys.XXXXXX")"
else
    mkdir -p "${OUTDIR}"
fi
ABS_OUTDIR="$(cd "${OUTDIR}" && pwd)"

# Refuse to write inside the repository, even if the caller passes such a
# path by mistake -- these keys must never end up staged in Git.
case "${ABS_OUTDIR}" in
    "${REPO_ROOT}" | "${REPO_ROOT}"/*)
        echo "error: refusing to write keys inside the repository (${REPO_ROOT})" >&2
        echo "Pass a directory outside the repo, or omit the argument to use a temp dir." >&2
        exit 1
        ;;
esac

command -v openssl >/dev/null 2>&1 || { echo "error: openssl is required" >&2; exit 1; }
command -v ssh-keygen >/dev/null 2>&1 || { echo "error: ssh-keygen is required" >&2; exit 1; }

umask 077

HOST_KEY_DER="${ABS_OUTDIR}/embedded_host_key.der"
USER_KEY_PRIV="${ABS_OUTDIR}/id_ecdsa"
USER_KEY_PUB="${ABS_OUTDIR}/id_ecdsa.pub"
USER_KEY_BLOB="${ABS_OUTDIR}/authorized_key.blob"

# Host key: raw SEC1 "EC PRIVATE KEY" DER, loaded via
# wolfSSH_CTX_UsePrivateKey_buffer(..., WOLFSSH_FORMAT_ASN1) -- not PEM.
# The pinned wolfSSH's WOLFSSH_FORMAT_PEM path for private keys
# (wolfSSH_ProcessBuffer() in src/internal.c) is compiled only under
# #ifdef WOLFSSH_CERTS, which this spike does not define (no X.509
# certificate support -- see components/wolfssh_spike/user_settings/
# user_settings.h); passing PEM bytes with WOLFSSH_FORMAT_PEM in this
# build falls through to WS_UNIMPLEMENTED_E instead of parsing them.
# Generating DER directly and loading it via WOLFSSH_FORMAT_ASN1 uses a
# path that works unconditionally.
openssl ecparam -name prime256v1 -genkey -noout -outform DER -out "${HOST_KEY_DER}"

# Authorized user key: a normal OpenSSH keypair. The developer uses
# id_ecdsa with `ssh -i` to connect; the raw SSH wire-format public-key
# blob (decoded from the base64 field of id_ecdsa.pub) is what gets
# embedded into the firmware and byte-compared in the auth callback --
# the same wire format wolfSSH hands the callback for the client-presented
# key, so no format conversion happens at runtime.
rm -f "${USER_KEY_PRIV}" "${USER_KEY_PUB}"
ssh-keygen -q -t ecdsa -b 256 -N "" -C "wolfssh-spike-dev-key" -f "${USER_KEY_PRIV}"
awk '{print $2}' "${USER_KEY_PUB}" | base64 -d > "${USER_KEY_BLOB}"

{
    echo "Generated disposable developer keys in: ${ABS_OUTDIR}"
    echo "  Host private key            (WOLFSSH_SPIKE_HOST_KEY_PATH):       ${HOST_KEY_DER}"
    echo "  Authorized key blob         (WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH): ${USER_KEY_BLOB}"
    echo "  Developer SSH private key   (for: ssh -i <this>):                ${USER_KEY_PRIV}"
    echo
    echo "Example:"
    echo "  eval \"\$(scripts/gen_ssh_spike_keys.sh)\""
    echo "  idf.py build"
    echo "  ssh -p 2222 -i ${USER_KEY_PRIV} flipper@<board-ip> ping"
} >&2

echo "export WOLFSSH_SPIKE_HOST_KEY_PATH=\"${HOST_KEY_DER}\""
echo "export WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH=\"${USER_KEY_BLOB}\""
