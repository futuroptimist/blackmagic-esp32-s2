#!/usr/bin/env bash
# Generates a disposable ECDSA P-256 developer key pair for the wolfSSH
# feasibility spike (CONFIG_EXPERIMENTAL_WOLFSSH_SERVER).
#
# Writes to a caller-supplied directory, or a fresh mktemp directory if none
# is given. Never writes inside this repository -- this is the externally
# -supplied input CMakeLists.txt requires (WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH);
# nothing it produces should ever be committed. The host key is generated
# on-device on first boot and NVS-persisted (see ssh_keystore.c) -- this
# script no longer generates one.
#
# Usage:
#   scripts/gen_ssh_spike_keys.sh [output-directory]
#   eval "$(scripts/gen_ssh_spike_keys.sh)"   # sets the env var directly
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: gen_ssh_spike_keys.sh [output-directory]

Generates a disposable ECDSA P-256 developer key pair for the wolfSSH
feasibility spike's single authorized user key. If no output directory is
given, a fresh directory is created under TMPDIR (or /tmp).

Prints one `export` line to stdout (suitable for `eval "$(...)"`) and
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

command -v ssh-keygen >/dev/null 2>&1 || { echo "error: ssh-keygen is required" >&2; exit 1; }

umask 077

USER_KEY_PRIV="${ABS_OUTDIR}/id_ecdsa"
USER_KEY_PUB="${ABS_OUTDIR}/id_ecdsa.pub"
USER_KEY_BLOB="${ABS_OUTDIR}/authorized_key.blob"

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
    echo "Generated a disposable developer key pair in: ${ABS_OUTDIR}"
    echo "  Authorized key blob         (WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH): ${USER_KEY_BLOB}"
    echo "  Developer SSH private key   (for: ssh -i <this>):                ${USER_KEY_PRIV}"
    echo
    echo "Example:"
    echo "  eval \"\$(scripts/gen_ssh_spike_keys.sh)\""
    echo "  idf.py build"
    echo "  ssh -p 2222 -i ${USER_KEY_PRIV} flipper@<board-ip> ping"
} >&2

echo "export WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH=\"${USER_KEY_BLOB}\""
