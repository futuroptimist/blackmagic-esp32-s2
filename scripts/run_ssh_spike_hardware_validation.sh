#!/usr/bin/env bash
# Reproducible, fail-closed hardware validation for the wolfSSH feasibility
# spike (CONFIG_EXPERIMENTAL_WOLFSSH_SERVER). See AGENTS.md and
# docs/design/ssh-feasibility-spike.md sections 8-9.
#
# This script is host-side only: it drives a real board over the network
# with the standard OpenSSH client and a handful of common Unix tools. It
# does not flash, monitor a serial port, or claim any result it did not
# itself observe. Every check is either PASS, FAIL, or SKIP; any FAIL makes
# the whole run exit non-zero. A SKIP of a *required* check (a prerequisite
# tool was missing) also makes the run exit non-zero unless
# --allow-incomplete-evidence is given -- a skipped required check is
# incomplete evidence, not proof the board behaved correctly, and must not
# silently satisfy the merge gate.
#
# Negative checks do not equate "the ssh command exited non-zero" with "the
# board rejected the request": that conflates genuine protocol/auth
# rejection with DNS failures, an unreachable/offline board, local argument
# errors, and timeouts, any of which would otherwise let a broken or
# offline board falsely "pass" every rejection check. See
# classify_ssh_result() below -- it is unit tested in
# scripts/test_ssh_spike_hardware_validation.sh.
#
# Usage:
#   run_ssh_spike_hardware_validation.sh --mode default --host <ip> \
#       --firmware-image <path>
#   run_ssh_spike_hardware_validation.sh --mode experimental --host <ip> \
#       --user flipper --identity <path> \
#       --host-key-fingerprint SHA256:xxxxx --firmware-image <path> \
#       [--cycles 100] [--monitor-log <path>] [--evidence-dir <path>]
#
# --dry-run validates arguments and prints the planned phase order without
# touching the network, hardware, or any real key file.
#
# Never embeds, copies, or prints private-key material: the identity file
# is only ever passed by path to `ssh -i`.
#
# --firmware-image (required unless --dry-run) binds this run's evidence to
# an exact Git commit and firmware artifact: before any network check, the
# script requires a clean tracked worktree/index, resolves the current Git
# HEAD, and hashes the given image (SHA-256), writing all of it to a
# mode-specific provenance file in the evidence directory. This script
# cannot flash the board or read back what bytes it is actually running --
# the provenance record states plainly that "this image was flashed" is an
# operator attestation, not something observed. See
# record_firmware_provenance() below and
# docs/design/ssh-feasibility-spike.md's "Hardware validation procedure".
set -euo pipefail
IFS=$'\n\t'

PROG=$(basename "$0")
# Used to locate the Git repository this script lives in, regardless of the
# operator's current working directory -- see record_firmware_provenance().
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- defaults -------------------------------------------------------------
MODE=""
HOST=""
PORT=2222
HTTP_PORT=80
GDB_PORT=2345
UART_PORT=3456
SSH_USER="flipper"
IDENTITY=""
HOST_KEY_FINGERPRINT=""
FIRMWARE_IMAGE=""
CYCLES=100
MONITOR_LOG=""
EVIDENCE_DIR=""
DRY_RUN=0
SKIP_COEXISTENCE=0
ALLOW_INCOMPLETE=0
CONNECT_TIMEOUT=5
HOLD_SECONDS=5
COMMAND_TIMEOUT=15

EXPECTED_KEX="ecdh-sha2-nistp256"
EXPECTED_HOSTKEY_ALGO="ecdsa-sha2-nistp256"
EXPECTED_CIPHER="aes256-gcm@openssh.com"
EXPECTED_PING_OUTPUT="pong"
EXPECTED_PING_EXIT=0

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
REQUIRED_SKIP_COUNT=0

usage() {
    cat <<'EOF'
Usage:
  run_ssh_spike_hardware_validation.sh --mode default --host <ip> \
      --firmware-image <path> [options]
  run_ssh_spike_hardware_validation.sh --mode experimental --host <ip> \
      --user <name> --identity <path> --host-key-fingerprint <SHA256:...> \
      --firmware-image <path> \
      [--cycles N] [--monitor-log <path>] [--evidence-dir <path>] [options]

Required for every mode (unless --dry-run):
  --mode {default|experimental}   Which firmware configuration is on the board.
  --host <ip-or-hostname>         Board address.
  --firmware-image <path>         Path to the exact .bin flashed to the board
                                   for this run. Hashed (SHA-256) and recorded
                                   with the current Git HEAD in a
                                   mode-specific provenance file before any
                                   network check -- this script cannot verify
                                   the board actually runs this image; that
                                   remains an operator attestation.

Required for --mode experimental (unless --dry-run):
  --user <name>                   SSH username (default: flipper).
  --identity <path>                Path to the developer's authorized private
                                   key. Never read/printed by this script
                                   except by handing the path to `ssh -i`.
  --host-key-fingerprint <fp>     Expected host key fingerprint
                                   (`ssh-keygen -lf` format, e.g.
                                   SHA256:abcd...). The run aborts rather
                                   than trusting an unexpected host key.

Optional:
  --port <n>                      SSH port (default: 2222).
  --http-port <n>                 HTTP port, also used to confirm the board
                                   is actually reachable in --mode default
                                   before trusting a closed port 2222
                                   (default: 80).
  --gdb-port <n>                  GDB TCP port for coexistence probes (default: 2345).
  --uart-port <n>                 Raw UART TCP port for coexistence probes (default: 3456).
  --cycles <n>                    Soak-phase cycle count (default: 100).
  --monitor-log <path>             Serial monitor capture to extract
                                   checkpoint/heap/duration evidence from.
  --evidence-dir <path>            Directory to write PASS/FAIL transcripts
                                   and summaries into (default: a fresh
                                   mktemp directory, printed at the end).
  --connect-timeout <seconds>      Per-attempt SSH connect timeout (default: 5).
  --hold-seconds <seconds>         How long the concurrent-connection probe
                                   holds a raw TCP connection open (default: 5).
  --skip-coexistence               Skip HTTP/GDB/UART coexistence probes
                                   (these are already best-effort and never
                                   count as "required" -- see below).
  --allow-incomplete-evidence       Let a run with skipped *required* checks
                                   (a prerequisite tool was missing) still
                                   exit 0. Off by default: such a run cannot
                                   satisfy the merge gate, and this flag is
                                   for diagnostic/development use only, not
                                   for producing the recorded hardware
                                   evidence.
  --dry-run                        Validate arguments and print the planned
                                   phase order; no network/hardware access,
                                   no real key files required.
  -h, --help                       Show this help and exit.

Exit status: 0 only if every executed check PASSed AND no *required* check
was SKIPped (unless --allow-incomplete-evidence was given). Optional
checks (coexistence probes, the monitor-log summary) can be skipped
without affecting the exit status -- they are opt-in extras, not part of
the merge-gate evidence.
EOF
}

log()   { printf '[%s] %s\n' "$PROG" "$*" >&2; }
pass()  { PASS_COUNT=$((PASS_COUNT + 1)); log "PASS: $*"; }
fail()  { FAIL_COUNT=$((FAIL_COUNT + 1)); log "FAIL: $*"; }
skip()  { SKIP_COUNT=$((SKIP_COUNT + 1)); log "SKIP: $*"; }
# A skip caused by a missing prerequisite tool for a check this script's
# contract says it performs -- as opposed to a deliberately opted-out
# optional phase (--skip-coexistence, --cycles 0, no --monitor-log given).
# See --allow-incomplete-evidence above.
skip_required() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    REQUIRED_SKIP_COUNT=$((REQUIRED_SKIP_COUNT + 1))
    log "SKIP (required): $*"
}

# `timeout` is a GNU coreutils command, not a standard macOS/BSD one --
# Homebrew's coreutils installs it as `gtimeout` to avoid clobbering the
# system, but neither is guaranteed present on a plain macOS install (the
# expected environment for the operator checklist this script implements).
# Prefer a real timeout binary when available (more precise: it kills the
# whole process group), otherwise fall back to a portable background-job
# watchdog so this script has no hard external dependency beyond `ssh`
# itself and common Unix tools. Both paths return 124 specifically when the
# command was killed for running past its deadline (GNU timeout's own
# convention), so callers can distinguish "timed out" from any other
# failure without inspecting which path was taken.
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
else
    TIMEOUT_BIN=""
fi

run_with_timeout() {
    # run_with_timeout <seconds> <command...>
    local secs="$1"; shift
    if [[ -n "$TIMEOUT_BIN" ]]; then
        "$TIMEOUT_BIN" "$secs" "$@"
        return $?
    fi
    local sentinel
    sentinel="$(mktemp "${TMPDIR:-/tmp}/timeout_sentinel.XXXXXX")"
    rm -f "$sentinel"
    "$@" &
    local cmd_pid=$!
    (
        sleep "$secs" 2>/dev/null
        if kill -0 "$cmd_pid" 2>/dev/null; then
            : > "$sentinel"
            kill -TERM "$cmd_pid" 2>/dev/null
        fi
    ) &
    local watchdog_pid=$!
    local rc=0
    wait "$cmd_pid" 2>/dev/null || rc=$?
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    if [[ -e "$sentinel" ]]; then
        rm -f "$sentinel"
        return 124
    fi
    return "$rc"
}

# ---- SSH outcome classification --------------------------------------------
#
# Every negative check below needs to tell "the board's SSH server actively
# rejected this request" apart from "something else entirely prevented the
# request from ever reaching the board" -- an unreachable board, a DNS
# failure, a bad local ssh(1) argument, a stale host key, or a timeout would
# otherwise all look like "non-zero exit" and falsely satisfy a naive
# rejection check. classify_ssh_result() reads a captured `ssh -v` (or more
# verbose) transcript plus the exit status and returns exactly one of:
#
#   success              -- exit 0.
#   auth_rejected         -- OpenSSH printed its standard denial ("Permission
#                            denied", "No more authentication methods").
#   host_key_failure      -- host key verification failed (should not occur
#                            here since the fingerprint is pinned earlier,
#                            but if it does, that's a distinct anomaly, not
#                            evidence of anything this script is testing).
#   protocol_rejected      -- the client got past authentication
#                            ("Authenticated to ... using" is present) but
#                            the connection still ended in failure. This is
#                            deliberately coarse: it is consistent with the
#                            board rejecting a specific request, but also
#                            with a request the board actually serviced
#                            merely exiting non-zero, or an unrelated abrupt
#                            post-auth close. A request-specific rejection
#                            check must combine this class with the
#                            corresponding evidence predicate below
#                            (channel_request_failed(), channel_open_failed(),
#                            advertised_auth_methods_excludes()) --
#                            protocol_rejected alone is not sufficient
#                            evidence for those checks. It remains
#                            sufficient on its own only where a specific
#                            request/operation is not being distinguished,
#                            e.g. confirming a second simultaneous
#                            connection did not succeed.
#   timeout                -- run_with_timeout's watchdog had to kill it
#                            (rc 124); ambiguous on its own and never
#                            treated as proof of rejection.
#   transport_failure      -- connection-establishment failed before any
#                            protocol/auth exchange (refused, timed out, no
#                            route, DNS failure, network unreachable, or an
#                            unexplained close/reset before authentication).
#   local_invocation_failure -- ssh(1) never even attempted a network
#                            connection (no "Connecting to" line at all) --
#                            almost always a bad argument to this script's
#                            own ssh invocation, not board behavior.
#   unknown_failure         -- non-zero exit that matched none of the above;
#                            never treated as valid rejection evidence.
#
# This function is exercised directly by
# scripts/test_ssh_spike_hardware_validation.sh using canned transcripts, so
# treat its output contract (the exact class strings above) as stable.
classify_ssh_result() {
    local out_file="$1" rc="$2"

    if [[ "$rc" -eq 124 ]]; then
        printf '%s' "timeout"
        return
    fi
    if [[ ! -f "$out_file" ]]; then
        printf '%s' "unknown_failure"
        return
    fi
    if grep -qE 'Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|no matching host key type found' "$out_file"; then
        printf '%s' "host_key_failure"
        return
    fi
    if [[ "$rc" -eq 0 ]]; then
        printf '%s' "success"
        return
    fi
    if grep -qE 'Authenticated to .* using' "$out_file"; then
        # Authentication is confirmed to have succeeded -- whatever ended
        # the connection after that point is the board (or this script's
        # own SSH request) being refused at the protocol level, not a
        # transport-layer problem. This ordering matters: a post-auth
        # abrupt close can print the same "Connection closed"/"reset by
        # peer" text a genuine pre-auth transport failure would, so
        # "Authenticated to" must be checked before those patterns below.
        printf '%s' "protocol_rejected"
        return
    fi
    if grep -qE 'Permission denied|No more authentication methods to try|No supported authentication methods' "$out_file"; then
        printf '%s' "auth_rejected"
        return
    fi
    if grep -qE 'Connection refused|Connection timed out|Operation timed out|No route to host|Network is unreachable|Could not resolve hostname|Connection closed by remote host|Connection reset by peer|kex_exchange_identification' "$out_file"; then
        printf '%s' "transport_failure"
        return
    fi
    if ! grep -qE 'Connecting to .* port [0-9]+\.' "$out_file"; then
        printf '%s' "local_invocation_failure"
        return
    fi
    printf '%s' "unknown_failure"
}

# True if $1 (a class from classify_ssh_result) is one of the remaining
# arguments.
class_in() {
    local needle="$1"; shift
    local c
    for c in "$@"; do
        [[ "$needle" == "$c" ]] && return 0
    done
    return 1
}

# ---- request-specific rejection evidence -----------------------------------
#
# `protocol_rejected` above is deliberately coarse: "authenticated, then
# some non-zero exit." That is not enough to prove a *specific* request was
# refused -- a command the board actually ran could just happen to exit
# non-zero, an authenticated session could close abruptly for an unrelated
# reason, or a channel the board genuinely opened could fail later for a
# reason that has nothing to do with the board's request-level policy. The
# predicates below require the operation-specific evidence OpenSSH's own
# client prints only when it receives a genuine protocol-level refusal (RFC
# 4254 section 5.4), so every request-specific rejection check below
# combines a `protocol_rejected` classification with one of these.

# channel_request_failed <out_file> <request-type>
#
# True if the transcript contains OpenSSH's own, unprefixed
# "<type> request failed on channel <N>" line -- printed by ssh(1) only
# when it receives a real SSH_MSG_CHANNEL_FAILURE in reply to that exact
# channel-request type. Confirmed against the installed ssh(1) binary:
# "%s request failed on channel %d" is a single shared format string, with
# "exec", "shell", "subsystem", and "pty-req" all present as distinct
# request-type literals it is called with -- and confirmed live against a
# genuine OpenSSH server (requesting an unconfigured subsystem name), which
# produced exactly "subsystem request failed on channel 0". wolfSSH's own
# SendChannelSuccess() (components/wolfssh_spike/wolfssh/src/internal.c)
# sends a real SSH_MSG_CHANNEL_FAILURE, not merely a connection drop, for
# any wantReply channel-request this spike's callbacks reject, so a
# rejected exec/shell/subsystem request against this spike produces the
# same client-side message confirmed above.
channel_request_failed() {
    local out_file="$1" request_type="$2"
    grep -qE "^${request_type} request failed on channel [0-9]+\$" "$out_file"
}

# channel_open_failed <out_file> <reason>
#
# True if the transcript contains OpenSSH's own
# "channel N: open failed: <reason>: ..." line for a genuine
# SSH_MSG_CHANNEL_OPEN_FAILURE carrying that specific RFC 4254 open-failure
# reason, as ssh(1) itself renders it ("administratively prohibited",
# "connect failed", "unknown channel type", or "resource shortage" --
# confirmed via `strings` against the installed ssh(1) binary, which shows
# "channel %d: open failed: %s%s%s" as the shared format string and those
# four reason strings as literals). This is a *different* protocol message
# from channel_request_failed() above: SSH_MSG_CHANNEL_OPEN_FAILURE (a whole
# new channel refused), not SSH_MSG_CHANNEL_FAILURE (a request on an
# already-open channel refused).
#
# The reason argument is required, not optional: OpenSSH renders BOTH a
# genuine policy-level channel-open refusal and a server-side
# destination-connect failure with the identical "channel N: open failed:"
# prefix -- only the reason text (and the description that follows it)
# distinguishes "the server's policy refused this channel" from "the server
# accepted the channel-open and then failed to reach the requested
# destination," which is not evidence of this spike's forwarding policy at
# all. Confirmed live against a real, forwarding-enabled OpenSSH server
# (`-W` to a destination whose port refuses connections) that the latter
# case prints exactly "channel 0: open failed: connect failed: Connection
# refused" -- a real SSH_MSG_CHANNEL_OPEN_FAILURE, but the wrong reason.
channel_open_failed() {
    local out_file="$1" reason="$2"
    grep -qE "^channel [0-9]+: open failed: ${reason}:" "$out_file"
}

# advertised_auth_methods_excludes <out_file> <method>...
#
# True only if the transcript's "Authentications that can continue: ..."
# line (OpenSSH's own report, from every SSH_MSG_USERAUTH_FAILURE, of the
# server's remaining advertised auth methods) is present AND contains none
# of the given method names. Returns false both when the line is missing
# entirely and when any given method is present in it -- either way, that
# is insufficient evidence the method is actually unavailable, as opposed
# to some other, unrelated reason authentication with it failed.
advertised_auth_methods_excludes() {
    local out_file="$1"; shift
    local methods_line
    methods_line="$(grep -m1 -E 'Authentications that can continue:' "$out_file" 2>/dev/null || true)"
    if [[ -z "$methods_line" ]]; then
        return 1
    fi
    local m
    for m in "$@"; do
        if [[ "$methods_line" == *"$m"* ]]; then
            return 1
        fi
    done
    return 0
}

# Isolates the actual remote-command output line from an `ssh -v` capture:
# strips ssh(1)'s own "debug1:"/"debug2:"/"debug3:" lines plus the
# unprefixed "Transferred: ..."/"Bytes per second: ..." summary `-v` prints
# after the command finishes, then returns the last remaining line.
extract_last_output_line() {
    grep -vE '^debug[0-9]?:|^Transferred:|^Bytes per second:' "$1" 2>/dev/null | tail -1
}

# Plain array assignment rather than a function-that-prints-lines-captured-
# with-mapfile: `mapfile`/`readarray` need bash 4+, but macOS ships bash 3.2
# at /bin/bash by default, and this script otherwise has no bash-version
# requirement worth imposing. Call build_ssh_common_opts() once argument
# parsing/validation has finished and $KNOWN_HOSTS exists; every helper
# below just reads the SSH_COMMON_OPTS array it fills in. `-v` is included
# unconditionally: classify_ssh_result() needs its "Connecting to"/
# "Authenticated to" evidence, and it is the setting each pattern above was
# empirically captured against.
SSH_COMMON_OPTS=()
build_ssh_common_opts() {
    SSH_COMMON_OPTS=(
        -v
        -o "UserKnownHostsFile=$KNOWN_HOSTS"
        -o "StrictHostKeyChecking=yes"
        -o "ConnectTimeout=$CONNECT_TIMEOUT"
        -o "BatchMode=yes"
        -p "$PORT"
    )
}

# Everything below this point (argument parsing through the final exit) is
# wrapped in main() and only invoked when this file is executed directly
# (see the BASH_SOURCE guard at the very end) -- scripts/
# test_ssh_spike_hardware_validation.sh sources this file to unit-test
# classify_ssh_result() and other functions directly, without running a
# real validation pass or requiring any arguments.
# ---- mode: default ----------------------------------------------------------

# An unreachable or offline board must never be mistaken for "SSH is
# correctly disabled" -- confirm the board is actually there and running
# this firmware via a default HTTP endpoint before trusting anything the
# port-2222 probe below reports.
verify_default_board_reachable() {
    if command -v curl >/dev/null 2>&1; then
        if curl -fsS --max-time "$CONNECT_TIMEOUT" "http://$HOST:$HTTP_PORT/api/v1/system/ping" -o /dev/null 2>/dev/null; then
            pass "board is reachable and identifiable via HTTP /api/v1/system/ping"
            return 0
        fi
        fail "board is NOT reachable via HTTP /api/v1/system/ping at http://$HOST:$HTTP_PORT/ -- cannot distinguish 'default firmware, SSH correctly disabled' from 'board unreachable/offline/wrong host', so the port-$PORT check below would be meaningless"
        return 1
    fi
    skip_required "board liveness verification (curl not available -- cannot safely distinguish an unreachable board from a board with SSH correctly disabled)"
    return 1
}

check_port_closed() {
    if ! verify_default_board_reachable; then
        return
    fi
    local desc="default firmware does not expose SSH on port $PORT"
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w "$CONNECT_TIMEOUT" "$HOST" "$PORT" 2>/dev/null; then
            fail "$desc (nc connected -- port is open)"
        else
            pass "$desc"
        fi
        return
    fi
    # Portable fallback: bash's /dev/tcp pseudo-device.
    if run_with_timeout "$CONNECT_TIMEOUT" bash -c "exec 3<>\"/dev/tcp/$HOST/$PORT\"" 2>/dev/null; then
        fail "$desc (/dev/tcp connected -- port is open)"
    else
        pass "$desc"
    fi
}

# ---- firmware provenance (both modes) --------------------------------------
#
# record_firmware_provenance <mode>
#
# Ties this run's PASS/FAIL evidence to an exact repository state and
# firmware artifact -- without this, evidence collected against one board
# state could later be mistaken for evidence about a different (e.g. later)
# PR head, since flashing the board is a manual step this script never
# observes. This function can only record what it *can* check from the
# host side: the current Git HEAD, that the tracked worktree/index match
# it, and the SHA-256 of the image file the operator says was flashed. It
# cannot read back the board's actually-flashed bytes -- "this exact image
# was flashed" is recorded explicitly as an operator attestation, not a
# fact this script independently verified. Runs before any network check
# in main(); see also FIRMWARE_IMAGE's usage() entry above.
record_firmware_provenance() {
    local mode="$1"
    local out="$EVIDENCE_DIR/firmware_provenance_${mode}.txt"

    if [[ ! -f "$FIRMWARE_IMAGE" || ! -r "$FIRMWARE_IMAGE" ]]; then
        fail "firmware provenance ($mode): --firmware-image is not a regular readable file: $FIRMWARE_IMAGE"
        return 1
    fi

    local repo_root
    repo_root="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
    if [[ -z "$repo_root" ]]; then
        fail "firmware provenance ($mode): could not determine the Git repository root from $SCRIPT_DIR -- is this script running from inside a Git checkout?"
        return 1
    fi

    # The caller cannot supply the head -- it is only ever read from Git
    # itself, and must be a full, unambiguous 40-character commit SHA.
    local head
    head="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)"
    if ! [[ "$head" =~ ^[0-9a-f]{40}$ ]]; then
        fail "firmware provenance ($mode): could not resolve a full 40-character Git HEAD commit SHA (got '${head:-<none>}')"
        return 1
    fi

    # Tracked files and the index only -- untracked files are deliberately
    # not part of this check (an ignored scratch file sitting in the
    # worktree says nothing about what was built).
    if ! git -C "$repo_root" diff --quiet || ! git -C "$repo_root" diff --cached --quiet; then
        fail "firmware provenance ($mode): tracked files or the index are not clean -- refusing to attribute this evidence to Git HEAD $head while the working tree doesn't match it exactly"
        return 1
    fi

    local sha256
    if command -v sha256sum >/dev/null 2>&1; then
        sha256="$(sha256sum "$FIRMWARE_IMAGE" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        sha256="$(shasum -a 256 "$FIRMWARE_IMAGE" | awk '{print $1}')"
    else
        skip_required "firmware provenance ($mode) (neither sha256sum nor shasum -a 256 is available to hash --firmware-image)"
        return 1
    fi

    {
        echo "mode=$mode"
        echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "git_head=$head"
        echo "tracked_worktree_and_index=clean"
        echo "firmware_image_path=$FIRMWARE_IMAGE"
        echo "firmware_image_sha256=$sha256"
        echo "attestation=the operator running this script attests that the image at firmware_image_path (matching firmware_image_sha256 above) was flashed to the board before this run; this script has no way to read back or independently verify the board's actually-flashed bytes"
    } > "$out"

    pass "firmware provenance ($mode) recorded: git_head=$head firmware_image_sha256=$sha256 (see $out)"
    return 0
}

# ---- shared helpers for experimental mode ----------------------------------

verify_host_key_fingerprint() {
    local scan_out="$SCRATCH_DIR/keyscan.txt"
    # Both tools are prerequisites this check's own contract depends on, not
    # optional extras -- a missing one is incomplete evidence (see
    # skip_required()'s doc comment above), not an operational failure of
    # the check itself. ssh-keygen is checked here too, before ever
    # attempting the scan, since it's needed to parse the result below.
    if ! command -v ssh-keyscan >/dev/null 2>&1; then
        skip_required "host-key fingerprint verification (ssh-keyscan not available -- cannot proceed safely)"
        return 1
    fi
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        skip_required "host-key fingerprint verification (ssh-keygen not available -- cannot parse the fetched host key)"
        return 1
    fi
    if ! run_with_timeout "$CONNECT_TIMEOUT" ssh-keyscan -p "$PORT" -t ecdsa-sha2-nistp256 "$HOST" \
            > "$scan_out" 2>/dev/null || [[ ! -s "$scan_out" ]]; then
        fail "host-key fingerprint verification (could not fetch host key from $HOST:$PORT)"
        return 1
    fi
    local actual_fp
    actual_fp="$(ssh-keygen -lf "$scan_out" 2>/dev/null | awk '{print $2}')"
    if [[ "$actual_fp" != "$HOST_KEY_FINGERPRINT" ]]; then
        fail "host-key fingerprint mismatch: expected $HOST_KEY_FINGERPRINT, got ${actual_fp:-<none>} -- refusing to proceed (possible MITM or stale --host-key-fingerprint)"
        return 1
    fi
    cp "$scan_out" "$KNOWN_HOSTS"
    pass "host-key fingerprint matches ($actual_fp)"
    return 0
}

# run_ssh <label> <timeout-seconds> <extra ssh args...> -- <remote command...>
# Sets RUN_SSH_RC, RUN_SSH_OUT (transcript path), and RUN_SSH_CLASS (see
# classify_ssh_result()) rather than returning a value via command
# substitution, so callers don't need an extra subshell layer just to read
# the result.
RUN_SSH_RC=0
RUN_SSH_OUT=""
RUN_SSH_CLASS=""
run_ssh() {
    local label="$1" timeout_s="$2"; shift 2
    local -a extra_args=()
    while [[ "$1" != "--" ]]; do
        extra_args+=("$1")
        shift
    done
    shift # consume --
    # A small gap before every connection attempt: confirmed on real
    # hardware, both (a) the board's graceful session shutdown
    # (wolfSSH_shutdown() waiting for the peer's own close acknowledgment,
    # pinned src/ssh.c) can legitimately still be finishing for up to
    # roughly 200ms after the *previous* connection's client-visible round
    # trip completed, and (b) a raw TCP connect a caller just confirmed
    # succeeded (e.g. test_second_connection_rejected()'s `nc` holder) can
    # itself take a little longer to be reflected in the board's own
    # accept()/session-state bookkeeping than the client-side connect
    # confirmation implies. Either way, an immediate next connection
    # attempt can be spuriously treated as colliding with a session that is
    # (from the client's point of view) already over, or not yet counted as
    # started. 0.5s is a comfortable margin over the measured ~200ms
    # threshold; see also run_soak()'s equivalent gaps.
    sleep 0.5
    # printf, not echo: echo's trailing newline would otherwise get
    # translated by `tr -c` into a literal trailing underscore, breaking
    # every filename this produces.
    local out="$SCRATCH_DIR/$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_').out"
    set +e
    run_with_timeout "$timeout_s" ssh "${SSH_COMMON_OPTS[@]}" "${extra_args[@]}" "$SSH_USER@$HOST" "$@" \
        > "$out" 2>&1
    RUN_SSH_RC=$?
    set -e
    RUN_SSH_OUT="$out"
    RUN_SSH_CLASS="$(classify_ssh_result "$out" "$RUN_SSH_RC")"
    cp "$out" "$EVIDENCE_DIR/$(basename "$out")" 2>/dev/null || true
}

test_ping_success() {
    # ssh -v's own debug lines, plus its post-command "Transferred:"/"Bytes
    # per second:" summary, go into the same captured transcript as the
    # actual command output -- an exact-equality check on the whole
    # transcript would spuriously fail. The real "pong" line is the only
    # stdout content ssh(1) ever produces for this exec command; isolate it
    # with extract_last_output_line() instead of comparing the whole
    # capture.
    local last_line
    run_ssh "ping_success" "$COMMAND_TIMEOUT" -i "$IDENTITY" -- ping
    last_line="$(extract_last_output_line "$RUN_SSH_OUT")"
    if [[ "$RUN_SSH_CLASS" == "success" && "$last_line" == "$EXPECTED_PING_OUTPUT" ]]; then
        pass "exec ping -> exact 'pong' output, exit $RUN_SSH_RC"
        return 0
    fi
    fail "exec ping -> expected exit $EXPECTED_PING_EXIT and output '$EXPECTED_PING_OUTPUT', got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC last_line='$last_line'"
    return 1
}

test_algorithms() {
    local rc
    run_ssh "algorithms" "$COMMAND_TIMEOUT" -vvv -i "$IDENTITY" -- ping
    rc="$RUN_SSH_RC"
    local transcript="$RUN_SSH_OUT"
    if [[ "$RUN_SSH_CLASS" != "success" ]]; then
        fail "negotiated-algorithm check: the underlying ping did not succeed (class=$RUN_SSH_CLASS, exit=$rc) -- algorithm negotiation happens before this, but a failed session is not solid evidence to report algorithms from"
        return
    fi
    local kex hostkey cipher
    # OpenSSH's debug output is CRLF-terminated on at least some platforms;
    # tr -d '\r' before extracting the last field, or a trailing \r ends up
    # silently appended to the captured value and every comparison below
    # fails even though the printed values look identical.
    kex="$(grep -m1 -E 'kex: algorithm:' "$transcript" | tr -d '\r' | awk '{print $NF}' || true)"
    hostkey="$(grep -m1 -E 'kex: host key algorithm:' "$transcript" | tr -d '\r' | awk '{print $NF}' || true)"
    cipher="$(grep -m1 -E 'kex: (server->client|client->server) cipher:' "$transcript" | tr -d '\r' | awk '{print $5}' || true)"
    local ok=1
    [[ "$kex" == "$EXPECTED_KEX" ]] || { fail "negotiated kex algorithm: expected $EXPECTED_KEX, got ${kex:-<none>}"; ok=0; }
    [[ "$hostkey" == "$EXPECTED_HOSTKEY_ALGO" ]] || { fail "negotiated host-key algorithm: expected $EXPECTED_HOSTKEY_ALGO, got ${hostkey:-<none>}"; ok=0; }
    [[ "$cipher" == "$EXPECTED_CIPHER" ]] || { fail "negotiated cipher: expected $EXPECTED_CIPHER, got ${cipher:-<none>}"; ok=0; }
    [[ "$ok" -eq 1 ]] && pass "negotiated algorithms match: kex=$kex hostkey=$hostkey cipher=$cipher"
}

test_wrong_key_rejected() {
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        skip_required "wrong-key rejection (ssh-keygen not available to generate a throwaway key)"
        return
    fi
    local wrong_key="$SCRATCH_DIR/throwaway_key"
    ssh-keygen -q -t ecdsa -b 256 -N "" -f "$wrong_key" >/dev/null 2>&1
    run_ssh "wrong_key" "$COMMAND_TIMEOUT" -i "$wrong_key" -- ping
    if [[ "$RUN_SSH_CLASS" == "auth_rejected" ]]; then
        pass "unrecognized public key is rejected (auth_rejected, exit $RUN_SSH_RC)"
    else
        fail "unrecognized public key: expected auth_rejected, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC -- either it was ACCEPTED (auth not fail-closed) or the failure is inconclusive (see $RUN_SSH_OUT)"
    fi
}

# run_ssh always targets $SSH_USER@$HOST; this check needs a different
# username, so it can't reuse run_ssh's fixed target unless the target is
# made an explicit argument. Implement it directly instead of layering
# more flags onto run_ssh for a single caller.
test_wrong_user_rejected() {
    # Doesn't go through run_ssh() (different target user), so it needs the
    # same pre-connection gap directly -- see run_ssh()'s comment.
    sleep 0.5
    local out="$SCRATCH_DIR/wrong_user.out"
    set +e
    run_with_timeout "$COMMAND_TIMEOUT" ssh "${SSH_COMMON_OPTS[@]}" -i "$IDENTITY" "not-$SSH_USER@$HOST" ping \
        > "$out" 2>&1
    local rc=$?
    set -e
    cp "$out" "$EVIDENCE_DIR/wrong_user.out" 2>/dev/null || true
    local class
    class="$(classify_ssh_result "$out" "$rc")"
    if [[ "$class" == "auth_rejected" ]]; then
        pass "unknown username is rejected (auth_rejected, exit $rc)"
    else
        fail "unknown username: expected auth_rejected, got class=$class exit=$rc -- either it was ACCEPTED (auth not fail-closed) or the failure is inconclusive (see $out)"
    fi
}

test_password_rejected() {
    run_ssh "password_auth" "$COMMAND_TIMEOUT" \
        -o PreferredAuthentications=password,keyboard-interactive \
        -o PubkeyAuthentication=no -- ping
    if [[ "$RUN_SSH_CLASS" == "auth_rejected" ]] && \
            advertised_auth_methods_excludes "$RUN_SSH_OUT" "password" "keyboard-interactive"; then
        pass "password/keyboard-interactive authentication is unavailable (auth_rejected, exit $RUN_SSH_RC, server's advertised continuation methods exclude password and keyboard-interactive)"
    else
        fail "password/keyboard-interactive auth: expected auth_rejected with the server's advertised continuation methods excluding password/keyboard-interactive, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC -- either it unexpectedly SUCCEEDED, the server still advertises one of those methods, or the failure is inconclusive (see $RUN_SSH_OUT)"
    fi
}

test_unknown_command_rejected() {
    local out
    run_ssh "unknown_command" "$COMMAND_TIMEOUT" -i "$IDENTITY" -- "not-a-real-command"
    out="$(cat "$RUN_SSH_OUT" 2>/dev/null || true)"
    if [[ "$RUN_SSH_CLASS" == "protocol_rejected" ]] && \
            channel_request_failed "$RUN_SSH_OUT" "exec" && \
            [[ "$out" != *"$EXPECTED_PING_OUTPUT"* ]]; then
        pass "unsupported exec command is rejected ('exec request failed on channel', exit $RUN_SSH_RC, no '$EXPECTED_PING_OUTPUT' in output)"
    else
        fail "unsupported exec command: expected an 'exec request failed on channel' refusal with no '$EXPECTED_PING_OUTPUT' in output, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC (see $RUN_SSH_OUT) -- a command that was actually executed and merely exited non-zero would not satisfy this"
    fi
}

test_shell_rejected() {
    run_ssh "shell_request" "$COMMAND_TIMEOUT" -i "$IDENTITY" --
    if [[ "$RUN_SSH_CLASS" == "protocol_rejected" ]] && \
            channel_request_failed "$RUN_SSH_OUT" "shell"; then
        pass "interactive shell request is rejected ('shell request failed on channel', exit $RUN_SSH_RC)"
    else
        fail "interactive shell request: expected a 'shell request failed on channel' refusal, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC -- either it unexpectedly SUCCEEDED or the failure is inconclusive (see $RUN_SSH_OUT)"
    fi
}

test_pty_rejected() {
    local out
    run_ssh "pty_request" "$COMMAND_TIMEOUT" -tt -i "$IDENTITY" -- ping
    out="$(cat "$RUN_SSH_OUT" 2>/dev/null || true)"
    # The pinned wolfSSH has no pty-req rejection callback to hook, so a
    # pty-req is protocol-acknowledged (SSH_MSG_CHANNEL_SUCCESS) -- there is
    # deliberately no "pty-req request failed on channel" line to look for
    # here, and treating the absence of one as a failure would misdescribe
    # what this implementation actually does (see docs/design/
    # ssh-feasibility-spike.md sections 6-7). The real, durable security
    # invariant enforced by this spike's exec callback
    # (wolfSSH_ChannelIsPty()) is one level later: the *subsequent* "ping"
    # exec request on that PTY'd channel is refused -- a genuine
    # SSH_MSG_CHANNEL_FAILURE for the "exec" request, the same evidence
    # channel_request_failed() checks for test_unknown_command_rejected()
    # above -- and no interactive shell or supported command ever runs
    # through the allocated PTY.
    if [[ "$RUN_SSH_CLASS" == "protocol_rejected" ]] && \
            channel_request_failed "$RUN_SSH_OUT" "exec" && \
            [[ "$out" != *"$EXPECTED_PING_OUTPUT"* ]]; then
        pass "pty-req is acknowledged but the subsequent exec is refused ('exec request failed on channel', exit $RUN_SSH_RC, no '$EXPECTED_PING_OUTPUT' in output) -- no command runs through the allocated PTY"
    else
        fail "PTY'd exec request: expected pty-req acknowledged followed by an 'exec request failed on channel' refusal with no '$EXPECTED_PING_OUTPUT' in output, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC (see $RUN_SSH_OUT)"
    fi
}

test_subsystem_rejected() {
    run_ssh "subsystem_request" "$COMMAND_TIMEOUT" -i "$IDENTITY" -s -- sftp
    if [[ "$RUN_SSH_CLASS" == "protocol_rejected" ]] && \
            channel_request_failed "$RUN_SSH_OUT" "subsystem"; then
        pass "subsystem request is rejected ('subsystem request failed on channel', exit $RUN_SSH_RC)"
    else
        fail "subsystem request: expected a 'subsystem request failed on channel' refusal, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC -- either it unexpectedly SUCCEEDED or the failure is inconclusive (see $RUN_SSH_OUT)"
    fi
}

test_forwarding_rejected() {
    # `-W host:port` makes ssh(1) issue a real direct-tcpip channel-open
    # request to the server and use it for stdio -- unlike `-L ...:0...`,
    # which OpenSSH rejects locally as an invalid forwarding specification
    # before ever contacting the server (a local_invocation_failure, not
    # evidence of anything the board did).
    #
    # This component compiles with WOLFSSH_FWD undefined (see
    # components/wolfssh_spike/user_settings/user_settings.h), so the pinned
    # wolfSSH's DoChannelOpen() (src/internal.c) never reaches its
    # (compiled-out) ID_CHANTYPE_TCPIP_DIRECT case for a "direct-tcpip"
    # channel-open request -- it falls to that switch's `default:` case,
    # setting fail_reason = OPEN_UNKNOWN_CHANNEL_TYPE and description =
    # "Channel type not supported.", which SendChannelOpenFail() sends as a
    # genuine SSH_MSG_CHANNEL_OPEN_FAILURE. This is wolfSSH's own
    # unknown-channel-type path rejecting the request before the
    # application channel-open callback ever runs for it -- the callback
    # (which also refuses a second channel on an active session) remains
    # defense in depth should the set of compiled-in channel types ever
    # change. On the client side this renders as
    # "channel N: open failed: unknown channel type: Channel type not
    # supported." -- checked explicitly via channel_open_failed() with that
    # exact reason so that a forwarding request the board *accepted* (a
    # channel-open with some other, or no, failure reason), whose
    # destination connection then failed for an unrelated reason, cannot be
    # mistaken for this spike's forwarding policy rejecting the request.
    # (A real, forwarding-enabled OpenSSH server rejecting an unreachable
    # destination instead prints "channel N: open failed: connect failed:
    # ..." -- confirmed live -- which is a real SSH_MSG_CHANNEL_OPEN_FAILURE
    # but the wrong reason, and correctly does not satisfy this check.)
    run_ssh "forwarding_request" "$COMMAND_TIMEOUT" -i "$IDENTITY" \
        -W "127.0.0.1:$HTTP_PORT" --
    if [[ "$RUN_SSH_CLASS" == "protocol_rejected" ]] && \
            channel_open_failed "$RUN_SSH_OUT" "unknown channel type"; then
        pass "direct-tcpip channel-open (forwarding) request is rejected ('open failed: unknown channel type', exit $RUN_SSH_RC)"
    else
        fail "direct-tcpip channel-open request: expected a 'channel N: open failed: unknown channel type' refusal, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC -- either it unexpectedly SUCCEEDED, was accepted/refused for an unrelated reason (e.g. a destination-connect failure), or the failure is inconclusive (see $RUN_SSH_OUT)"
    fi
}

test_second_connection_rejected() {
    if ! command -v nc >/dev/null 2>&1; then
        skip_required "second-simultaneous-connection rejection (nc not available to hold a raw connection open)"
        return
    fi
    # g_session_active is set the instant accept() returns, before the SSH
    # handshake even begins -- so a raw, silent TCP connection is enough to
    # occupy the one allowed slot for the hold duration. Use `nc -v` (BSD
    # and GNU nc both support it) so the holder's own stderr proves the
    # connection was actually established, rather than assuming it was.
    local holder_log="$SCRATCH_DIR/holder_nc.log"
    ( sleep "$HOLD_SECONDS" | nc -v "$HOST" "$PORT" > /dev/null 2> "$holder_log" ) &
    local holder_pid=$!

    local connected=0 tries=0
    while [[ "$tries" -lt 10 ]]; do
        if grep -qiE 'succeeded|open|connected' "$holder_log" 2>/dev/null; then
            connected=1
            break
        fi
        sleep 0.3
        tries=$((tries + 1))
    done
    if [[ "$connected" -ne 1 ]]; then
        fail "second-simultaneous-connection rejection: could not confirm the held connection was actually established (see $holder_log) -- inconclusive, not attempting the second connection"
        wait "$holder_pid" 2>/dev/null || true
        return
    fi

    # The board's own expected behavior here (accept, then immediately
    # close, before any SSH protocol exchange) looks like an early
    # connection close from the client's point of view -- classified as
    # transport_failure by classify_ssh_result(), not protocol_rejected,
    # since no "Authenticated to" line will ever appear. Both classes (and
    # auth_rejected, in case the board instead responds by refusing auth
    # outright) count as evidence the second connection did not succeed;
    # success/timeout/local_invocation_failure/host_key_failure do not.
    run_ssh "second_connection" "$COMMAND_TIMEOUT" -i "$IDENTITY" -- ping
    if class_in "$RUN_SSH_CLASS" transport_failure protocol_rejected auth_rejected; then
        pass "second simultaneous connection is rejected while the first is active (class=$RUN_SSH_CLASS)"
    else
        fail "second simultaneous connection: expected transport_failure/protocol_rejected/auth_rejected, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC -- either it unexpectedly SUCCEEDED or the failure is inconclusive (see $RUN_SSH_OUT)"
    fi

    wait "$holder_pid" 2>/dev/null || true
}

test_reconnect_after_close() {
    sleep 1
    local last_line
    run_ssh "reconnect" "$COMMAND_TIMEOUT" -i "$IDENTITY" -- ping
    last_line="$(extract_last_output_line "$RUN_SSH_OUT")"
    if [[ "$RUN_SSH_CLASS" == "success" && "$last_line" == "$EXPECTED_PING_OUTPUT" ]]; then
        pass "reconnect after the previous connection closed succeeds"
    else
        fail "reconnect after close: expected success with '$EXPECTED_PING_OUTPUT' output, got class=$RUN_SSH_CLASS exit=$RUN_SSH_RC last_line='$last_line'"
    fi
}

probe_tcp_open() {
    local label="$1" port="$2"
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w "$CONNECT_TIMEOUT" "$HOST" "$port" 2>/dev/null; then
            pass "$label reachable on port $port"
        else
            fail "$label NOT reachable on port $port"
        fi
        return
    fi
    if run_with_timeout "$CONNECT_TIMEOUT" bash -c "exec 3<>\"/dev/tcp/$HOST/$port\"" 2>/dev/null; then
        pass "$label reachable on port $port"
    else
        fail "$label NOT reachable on port $port"
    fi
}

probe_coexistence() {
    # Best-effort and explicitly optional: never contributes to
    # REQUIRED_SKIP_COUNT, since these are reachability probes supporting
    # the manual coexistence checklist, not part of the SSH policy
    # evidence itself.
    if [[ "$SKIP_COEXISTENCE" -eq 1 ]]; then
        skip "coexistence probes (--skip-coexistence given)"
        return
    fi
    if command -v curl >/dev/null 2>&1; then
        if curl -fsS --max-time "$CONNECT_TIMEOUT" "http://$HOST:$HTTP_PORT/" -o "$EVIDENCE_DIR/http_root.html" 2>/dev/null; then
            pass "HTTP landing page reachable at http://$HOST:$HTTP_PORT/"
        else
            fail "HTTP landing page NOT reachable at http://$HOST:$HTTP_PORT/"
        fi
        if curl -fsS --max-time "$CONNECT_TIMEOUT" "http://$HOST:$HTTP_PORT/api/v1/system/ping" -o "$EVIDENCE_DIR/http_api_ping.json" 2>/dev/null; then
            pass "HTTP /api/v1/system/ping reachable"
        else
            fail "HTTP /api/v1/system/ping NOT reachable"
        fi
    else
        skip "HTTP coexistence probes (curl not available)"
    fi
    probe_tcp_open "GDB TCP listener" "$GDB_PORT"
    probe_tcp_open "raw UART TCP listener" "$UART_PORT"
    log "manual-only coexistence phases NOT automated by this script: the Svelte /config UI's interactive behavior, Wi-Fi loss/recovery, and USB CLI/debugging behavior -- see the PR operator checklist."
}

run_soak() {
    if [[ "$CYCLES" -eq 0 ]]; then
        skip "soak phase (--cycles 0)"
        return
    fi
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        skip_required "soak phase (ssh-keygen not available to generate the per-cycle throwaway key)"
        return
    fi
    local wrong_key="$SCRATCH_DIR/soak_throwaway_key"
    ssh-keygen -q -t ecdsa -b 256 -N "" -f "$wrong_key" >/dev/null 2>&1

    local soak_pass=0 soak_fail=0
    log "starting soak phase: $CYCLES cycles of (successful ping, expected auth_rejected wrong key)"
    for ((i = 1; i <= CYCLES; i++)); do
        local out rc class last_line
        out="$SCRATCH_DIR/soak_${i}_ok.out"
        set +e
        run_with_timeout "$COMMAND_TIMEOUT" ssh "${SSH_COMMON_OPTS[@]}" -i "$IDENTITY" "$SSH_USER@$HOST" ping \
            > "$out" 2>&1
        rc=$?
        set -e
        class="$(classify_ssh_result "$out" "$rc")"
        last_line="$(extract_last_output_line "$out")"
        if [[ "$class" == "success" && "$last_line" == "$EXPECTED_PING_OUTPUT" ]]; then
            soak_pass=$((soak_pass + 1))
        else
            fail "soak cycle $i: successful-ping leg expected success/'$EXPECTED_PING_OUTPUT', got class=$class exit=$rc"
            cp "$out" "$EVIDENCE_DIR/soak_${i}_ok.out" 2>/dev/null || true
        fi

        # A small gap between consecutive connection attempts: the board's
        # own graceful shutdown (wolfSSH_shutdown() -- SendChannelEof/
        # SendChannelExit/SendChannelClose, then wolfSSH_worker() waiting
        # for the peer's own close acknowledgment, src/ssh.c) is a real
        # protocol exchange that legitimately outlasts the client-visible
        # round trip by up to roughly 200ms on this hardware; the one
        # session/channel-at-a-time policy correctly treats a connection
        # attempt inside that window as still-active and rejects it -- that
        # is not a leak or degradation. Confirmed empirically: back-to-back
        # attempts with no gap intermittently collide with this window,
        # while a 200ms+ gap reliably avoids it every time; see
        # test_reconnect_after_close(), which already sleeps 1s before its
        # own single reconnect attempt for the same reason.
        sleep 0.5

        out="$SCRATCH_DIR/soak_${i}_bad.out"
        set +e
        run_with_timeout "$COMMAND_TIMEOUT" ssh "${SSH_COMMON_OPTS[@]}" -i "$wrong_key" "$SSH_USER@$HOST" ping \
            > "$out" 2>&1
        rc=$?
        set -e
        class="$(classify_ssh_result "$out" "$rc")"
        if [[ "$class" == "auth_rejected" ]]; then
            soak_fail=$((soak_fail + 1))
        else
            fail "soak cycle $i: expected-failure leg expected auth_rejected, got class=$class exit=$rc"
            cp "$out" "$EVIDENCE_DIR/soak_${i}_bad.out" 2>/dev/null || true
        fi

        # Same rationale as the gap above, before the next cycle's leg.
        sleep 0.5
    done

    {
        echo "soak_cycles_requested=$CYCLES"
        echo "soak_successful_pings_observed=$soak_pass"
        echo "soak_expected_auth_rejections_observed=$soak_fail"
    } > "$EVIDENCE_DIR/soak_summary.txt"

    if [[ "$soak_pass" -eq "$CYCLES" && "$soak_fail" -eq "$CYCLES" ]]; then
        pass "soak phase: $CYCLES/$CYCLES successful-ping cycles and $CYCLES/$CYCLES auth_rejected wrong-key cycles all behaved as expected"
    else
        fail "soak phase: only $soak_pass/$CYCLES successful-ping and $soak_fail/$CYCLES auth_rejected cycles behaved as expected -- see soak_summary.txt and per-cycle transcripts in $EVIDENCE_DIR"
    fi
    log "This script does NOT itself observe device-side heap/stack telemetry during the soak; pair it with --monitor-log from a serial capture taken over the same run to fill in the resource-degradation evidence (see docs/design/ssh-feasibility-spike.md section 8)."
}

summarize_monitor_log() {
    if [[ -z "$MONITOR_LOG" ]]; then
        skip "serial monitor log summary (--monitor-log not given)"
        return
    fi
    if [[ ! -f "$MONITOR_LOG" ]]; then
        fail "serial monitor log summary (--monitor-log path does not exist: $MONITOR_LOG)"
        return
    fi
    local out="$EVIDENCE_DIR/monitor_log_summary.txt"
    {
        echo "# Extracted from: $MONITOR_LOG"
        echo "# Resource checkpoints (never contain key material by construction):"
        grep -E 'checkpoint=[A-Za-z_]+ free_heap=[0-9]+ min_free_heap_since_boot=[0-9]+ largest_free_block=[0-9]+ stack_hwm=[0-9]+' \
            "$MONITOR_LOG" || echo "(none found)"
        echo
        echo "# Handshake/auth durations:"
        grep -E 'handshake_auth_duration_ms=[0-9]+ result=(success|failure)' \
            "$MONITOR_LOG" || echo "(none found)"
    } > "$out"

    # A supplied capture must contain complete, representative evidence --
    # not merely "at least one matching line somewhere" -- before it is
    # "ready to copy into design doc section 8": one line for each
    # documented lifecycle checkpoint, plus at least one successful and one
    # failed handshake/auth duration. Each category is matched against the
    # full strict metric-line format (as extracted above), so a malformed
    # line missing a field cannot satisfy it. Omitting --monitor-log
    # entirely remains an optional SKIP (above); a *supplied* capture that
    # is merely partial is a FAIL, not a PASS.
    local -a missing=()
    local cp
    for cp in before_ssh_init after_listener_init before_handshake \
              after_auth after_failed_handshake after_disconnect; do
        if ! grep -qE "checkpoint=${cp} free_heap=[0-9]+ min_free_heap_since_boot=[0-9]+ largest_free_block=[0-9]+ stack_hwm=[0-9]+" "$MONITOR_LOG"; then
            missing+=("checkpoint=$cp")
        fi
    done
    if ! grep -qE 'handshake_auth_duration_ms=[0-9]+ result=success' "$MONITOR_LOG"; then
        missing+=("handshake_auth_duration_ms ... result=success")
    fi
    if ! grep -qE 'handshake_auth_duration_ms=[0-9]+ result=failure' "$MONITOR_LOG"; then
        missing+=("handshake_auth_duration_ms ... result=failure")
    fi

    if [[ "${#missing[@]}" -eq 0 ]]; then
        pass "serial monitor log summary written to $out (complete lifecycle-checkpoint and success/failure duration evidence) -- copy these into design doc section 8 in place of 'Pending hardware measurement'"
    else
        fail "serial monitor log summary incomplete -- missing evidence for: ${missing[*]} (see $out); a partial capture is not sufficient evidence for design doc section 8"
    fi
}

main() {

# ---- argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --http-port) HTTP_PORT="$2"; shift 2 ;;
        --gdb-port) GDB_PORT="$2"; shift 2 ;;
        --uart-port) UART_PORT="$2"; shift 2 ;;
        --user) SSH_USER="$2"; shift 2 ;;
        --identity) IDENTITY="$2"; shift 2 ;;
        --host-key-fingerprint) HOST_KEY_FINGERPRINT="$2"; shift 2 ;;
        --firmware-image) FIRMWARE_IMAGE="$2"; shift 2 ;;
        --cycles) CYCLES="$2"; shift 2 ;;
        --monitor-log) MONITOR_LOG="$2"; shift 2 ;;
        --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
        --connect-timeout) CONNECT_TIMEOUT="$2"; shift 2 ;;
        --hold-seconds) HOLD_SECONDS="$2"; shift 2 ;;
        --skip-coexistence) SKIP_COEXISTENCE=1; shift ;;
        --allow-incomplete-evidence) ALLOW_INCOMPLETE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$MODE" != "default" && "$MODE" != "experimental" ]]; then
    echo "error: --mode must be 'default' or 'experimental'" >&2
    exit 2
fi
if [[ -z "$HOST" ]]; then
    echo "error: --host is required" >&2
    exit 2
fi
if [[ "$DRY_RUN" -eq 0 && -z "$FIRMWARE_IMAGE" ]]; then
    echo "error: --firmware-image is required (unless --dry-run) -- this run's evidence must be attributable to an exact firmware artifact" >&2
    exit 2
fi
if [[ "$MODE" == "experimental" ]]; then
    if [[ -z "$SSH_USER" || -z "$IDENTITY" || -z "$HOST_KEY_FINGERPRINT" ]]; then
        echo "error: --mode experimental requires --user, --identity, and --host-key-fingerprint" >&2
        exit 2
    fi
    if [[ "$DRY_RUN" -eq 0 && ! -f "$IDENTITY" ]]; then
        echo "error: --identity path does not exist: $IDENTITY" >&2
        exit 2
    fi
fi
if ! [[ "$CYCLES" =~ ^[0-9]+$ ]]; then
    echo "error: --cycles must be a non-negative integer" >&2
    exit 2
fi

if [[ -z "$EVIDENCE_DIR" ]]; then
    EVIDENCE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ssh-spike-evidence.XXXXXX")"
fi
mkdir -p "$EVIDENCE_DIR"

SCRATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ssh-spike-validation.XXXXXX")"
cleanup() {
    local status=$?
    rm -rf "$SCRATCH_DIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

KNOWN_HOSTS="$SCRATCH_DIR/known_hosts"
: > "$KNOWN_HOSTS"

build_ssh_common_opts

# ---- dry-run: print the plan, touch nothing else --------------------------
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry run: arguments valid. Planned phases for --mode $MODE:"
    echo "  0. Record firmware provenance (Git HEAD, tracked-worktree/index"
    echo "     cleanliness, and --firmware-image SHA-256) before any network"
    echo "     check -- not performed in --dry-run: no image path is read or"
    echo "     hashed here, even if one was given."
    if [[ "$MODE" == "default" ]]; then
        cat <<EOF
  1. Confirm the board is reachable and identifiable via HTTP
     (http://$HOST:$HTTP_PORT/api/v1/system/ping) -- an unreachable/offline
     board must not be confused with "SSH correctly disabled".
  2. Verify TCP port $PORT is NOT accepting connections on $HOST.
EOF
    else
        cat <<EOF
  1. ssh-keyscan the host key on $HOST:$PORT and verify it matches
     --host-key-fingerprint before trusting anything further (fail closed
     on mismatch).
  2. exec ping -> expect exact "pong" output and exit $EXPECTED_PING_EXIT.
  3. Verify negotiated algorithms (kex=$EXPECTED_KEX,
     hostkey=$EXPECTED_HOSTKEY_ALGO, cipher=$EXPECTED_CIPHER) via ssh -vvv.
  4. Wrong (ephemeral, freshly generated) key -> expect auth_rejected.
  5. Wrong username -> expect auth_rejected.
  6. Password/keyboard-interactive auth (no valid password exists) ->
     expect auth_rejected (server advertises publickey only).
  7. Unknown exec command -> expect protocol_rejected, no "pong" output.
  8. Shell request (no command) -> expect protocol_rejected.
  9. PTY'd exec (-tt) -> pty-req is acknowledged; the subsequent exec must
     fail (protocol_rejected, "exec request failed on channel"), no "pong"
     output.
  10. Subsystem request -> expect protocol_rejected.
  11. Port forwarding via -W (a real direct-tcpip channel-open request,
      not a locally-rejected -L specification) -> expect protocol_rejected.
  12. Verify a held raw TCP connection actually connects, then verify a
      second connection is rejected (transport_failure or
      protocol_rejected -- the board's accept-then-immediately-close
      behavior looks like an early close either way) while the first is
      active, then verify reconnect succeeds after the first closes.
  13. Coexistence probes: HTTP :$HTTP_PORT, GDB :$GDB_PORT, UART :$UART_PORT TCP reachability$( [[ "$SKIP_COEXISTENCE" -eq 1 ]] && echo " (skipped by flag)" ) -- optional, does not affect the required-evidence exit status.
  14. Soak phase: $CYCLES cycles of (successful ping, expected auth_rejected wrong key).
  15. If --monitor-log was given, extract and summarize checkpoint/heap/
      duration evidence lines.
  A run with any required check skipped (missing ssh-keygen/nc/curl) exits
  non-zero unless --allow-incomplete-evidence is given.
EOF
    fi
    echo "Evidence directory (would be used): $EVIDENCE_DIR"
    echo "Dry run complete -- no network, hardware, or key files were touched."
    exit 0
fi


# ---- run ---------------------------------------------------------------
log "evidence directory: $EVIDENCE_DIR"

if [[ "$MODE" == "default" ]]; then
    if record_firmware_provenance "$MODE"; then
        check_port_closed
    else
        log "firmware provenance recording failed -- skipping remaining checks rather than proceeding without evidence attributable to a specific firmware artifact"
    fi
else
    if record_firmware_provenance "$MODE"; then
        if verify_host_key_fingerprint; then
            test_ping_success || true
            test_algorithms || true
            test_wrong_key_rejected || true
            test_wrong_user_rejected || true
            test_password_rejected || true
            test_unknown_command_rejected || true
            test_shell_rejected || true
            test_pty_rejected || true
            test_subsystem_rejected || true
            test_forwarding_rejected || true
            test_second_connection_rejected || true
            test_reconnect_after_close || true
            probe_coexistence || true
            run_soak || true
        else
            log "host-key fingerprint verification failed -- skipping all remaining checks rather than proceeding against an unverified host"
        fi
    else
        log "firmware provenance recording failed -- skipping remaining checks rather than proceeding without evidence attributable to a specific firmware artifact"
    fi
    summarize_monitor_log || true
fi

echo
log "SUMMARY: pass=$PASS_COUNT fail=$FAIL_COUNT skip=$SKIP_COUNT required_skip=$REQUIRED_SKIP_COUNT (evidence: $EVIDENCE_DIR)"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
if [[ "$REQUIRED_SKIP_COUNT" -gt 0 && "$ALLOW_INCOMPLETE" -eq 0 ]]; then
    log "INCOMPLETE EVIDENCE: $REQUIRED_SKIP_COUNT required check(s) were skipped -- this run cannot satisfy the merge gate. Install the missing tool(s) and re-run, or pass --allow-incomplete-evidence to acknowledge this for diagnostic use only."
    exit 1
fi
exit 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
