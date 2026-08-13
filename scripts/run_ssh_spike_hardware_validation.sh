#!/usr/bin/env bash
# Reproducible, fail-closed hardware validation for the wolfSSH feasibility
# spike (CONFIG_EXPERIMENTAL_WOLFSSH_SERVER). See AGENTS.md and
# docs/design/ssh-feasibility-spike.md sections 8-9.
#
# This script is host-side only: it drives a real board over the network
# with the standard OpenSSH client and a handful of common Unix tools. It
# does not flash, monitor a serial port, or claim any result it did not
# itself observe. Every check is either PASS, FAIL, or SKIP (prerequisite
# tool/log not available); any FAIL makes the whole run exit non-zero.
#
# Usage:
#   run_ssh_spike_hardware_validation.sh --mode default --host <ip>
#   run_ssh_spike_hardware_validation.sh --mode experimental --host <ip> \
#       --user flipper --identity <path> \
#       --host-key-fingerprint SHA256:xxxxx [--cycles 100] \
#       [--monitor-log <path>] [--evidence-dir <path>]
#
# --dry-run validates arguments and prints the planned phase order without
# touching the network, hardware, or any real key file.
#
# Never embeds, copies, or prints private-key material: the identity file
# is only ever passed by path to `ssh -i`.
set -euo pipefail
IFS=$'\n\t'

PROG=$(basename "$0")

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
CYCLES=100
MONITOR_LOG=""
EVIDENCE_DIR=""
DRY_RUN=0
SKIP_COEXISTENCE=0
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

usage() {
    cat <<'EOF'
Usage:
  run_ssh_spike_hardware_validation.sh --mode default --host <ip> [options]
  run_ssh_spike_hardware_validation.sh --mode experimental --host <ip> \
      --user <name> --identity <path> --host-key-fingerprint <SHA256:...> \
      [--cycles N] [--monitor-log <path>] [--evidence-dir <path>] [options]

Required for every mode:
  --mode {default|experimental}   Which firmware configuration is on the board.
  --host <ip-or-hostname>         Board address.

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
  --http-port <n>                 HTTP port for coexistence probes (default: 80).
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
  --skip-coexistence               Skip HTTP/GDB/UART coexistence probes.
  --dry-run                        Validate arguments and print the planned
                                   phase order; no network/hardware access,
                                   no real key files required.
  -h, --help                       Show this help and exit.

Exit status: 0 only if every executed check PASSed (SKIPs are reported but
do not fail the run by themselves -- they mean a prerequisite tool or input
was unavailable, not that the behavior was verified).
EOF
}

log()   { printf '[%s] %s\n' "$PROG" "$*" >&2; }
pass()  { PASS_COUNT=$((PASS_COUNT + 1)); log "PASS: $*"; }
fail()  { FAIL_COUNT=$((FAIL_COUNT + 1)); log "FAIL: $*"; }
skip()  { SKIP_COUNT=$((SKIP_COUNT + 1)); log "SKIP: $*"; }

# `timeout` is a GNU coreutils command, not a standard macOS/BSD one --
# Homebrew's coreutils installs it as `gtimeout` to avoid clobbering the
# system, but neither is guaranteed present on a plain macOS install (the
# expected environment for the operator checklist this script implements).
# Prefer a real timeout binary when available (more precise: it kills the
# whole process group), otherwise fall back to a portable background-job
# watchdog so this script has no hard external dependency beyond `ssh`
# itself and common Unix tools.
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
    "$@" &
    local cmd_pid=$!
    ( sleep "$secs" 2>/dev/null; kill -TERM "$cmd_pid" 2>/dev/null ) &
    local watchdog_pid=$!
    local rc=0
    wait "$cmd_pid" 2>/dev/null || rc=$?
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    return "$rc"
}

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
        --cycles) CYCLES="$2"; shift 2 ;;
        --monitor-log) MONITOR_LOG="$2"; shift 2 ;;
        --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
        --connect-timeout) CONNECT_TIMEOUT="$2"; shift 2 ;;
        --hold-seconds) HOLD_SECONDS="$2"; shift 2 ;;
        --skip-coexistence) SKIP_COEXISTENCE=1; shift ;;
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

# Plain array assignment rather than a function-that-prints-lines-captured-
# with-mapfile: `mapfile`/`readarray` need bash 4+, but macOS ships bash 3.2
# at /bin/bash by default, and this script otherwise has no bash-version
# requirement worth imposing. Call build_ssh_common_opts() once argument
# parsing/validation has finished and $KNOWN_HOSTS exists; every helper
# below just reads the SSH_COMMON_OPTS array it fills in.
SSH_COMMON_OPTS=()
build_ssh_common_opts() {
    SSH_COMMON_OPTS=(
        -o "UserKnownHostsFile=$KNOWN_HOSTS"
        -o "StrictHostKeyChecking=yes"
        -o "ConnectTimeout=$CONNECT_TIMEOUT"
        -o "BatchMode=yes"
        -o "LogLevel=ERROR"
        -p "$PORT"
    )
}
build_ssh_common_opts

# ---- dry-run: print the plan, touch nothing else --------------------------
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry run: arguments valid. Planned phases for --mode $MODE:"
    if [[ "$MODE" == "default" ]]; then
        cat <<EOF
  1. Verify TCP port $PORT is NOT accepting connections on $HOST.
EOF
    else
        cat <<EOF
  1. ssh-keyscan the host key on $HOST:$PORT and verify it matches
     --host-key-fingerprint before trusting anything further (fail closed
     on mismatch).
  2. exec ping -> expect exact "pong" output and exit $EXPECTED_PING_EXIT.
  3. Verify negotiated algorithms (kex=$EXPECTED_KEX,
     hostkey=$EXPECTED_HOSTKEY_ALGO, cipher=$EXPECTED_CIPHER) via ssh -vvv.
  4. Wrong (ephemeral, freshly generated) key -> expect rejection.
  5. Wrong username -> expect rejection.
  6. Password/keyboard-interactive auth (no valid password exists) ->
     expect rejection (server advertises publickey only).
  7. Unknown exec command -> expect rejection.
  8. Shell request (no command) -> expect rejection, bounded by timeout.
  9. PTY allocation (-tt) -> expect rejection.
  10. Subsystem request -> expect rejection.
  11. Port forwarding (-L) -> expect rejection, bounded by timeout.
  12. Hold one raw TCP connection open, verify a second connection is
      rejected while the first is active, then verify reconnect succeeds
      after the first closes.
  13. Coexistence probes: HTTP :$HTTP_PORT, GDB :$GDB_PORT, UART :$UART_PORT TCP reachability$( [[ "$SKIP_COEXISTENCE" -eq 1 ]] && echo " (skipped by flag)" ).
  14. Soak phase: $CYCLES cycles of (successful ping, expected-failure wrong key).
  15. If --monitor-log was given, extract and summarize checkpoint/heap/
      duration evidence lines.
EOF
    fi
    echo "Evidence directory (would be used): $EVIDENCE_DIR"
    echo "Dry run complete -- no network, hardware, or key files were touched."
    exit 0
fi

# ---- mode: default ----------------------------------------------------------
check_port_closed() {
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

# ---- shared helpers for experimental mode ----------------------------------

verify_host_key_fingerprint() {
    local scan_out="$SCRATCH_DIR/keyscan.txt"
    if ! command -v ssh-keyscan >/dev/null 2>&1; then
        fail "host-key fingerprint verification (ssh-keyscan not available -- cannot proceed safely)"
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

run_ssh() {
    # run_ssh <label> <timeout-seconds> <extra ssh args...> -- <remote command...>
    local label="$1" timeout_s="$2"; shift 2
    local -a extra_args=()
    while [[ "$1" != "--" ]]; do
        extra_args+=("$1")
        shift
    done
    shift # consume --
    # printf, not echo: echo's trailing newline would otherwise get
    # translated by `tr -c` into a literal trailing underscore, breaking
    # every filename this produces.
    local out="$SCRATCH_DIR/$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_').out"
    set +e
    run_with_timeout "$timeout_s" ssh "${SSH_COMMON_OPTS[@]}" "${extra_args[@]}" "$SSH_USER@$HOST" "$@" \
        > "$out" 2>&1
    local rc=$?
    set -e
    cp "$out" "$EVIDENCE_DIR/$(basename "$out")" 2>/dev/null || true
    printf '%s' "$rc"
}

test_ping_success() {
    local rc out
    rc=$(run_ssh "ping_success" "$COMMAND_TIMEOUT" -i "$IDENTITY" -- ping)
    out="$(cat "$SCRATCH_DIR/ping_success.out" 2>/dev/null || true)"
    if [[ "$rc" -eq "$EXPECTED_PING_EXIT" && "$out" == "$EXPECTED_PING_OUTPUT" ]]; then
        pass "exec ping -> exact 'pong' output, exit $rc"
        return 0
    fi
    fail "exec ping -> expected exit $EXPECTED_PING_EXIT and output '$EXPECTED_PING_OUTPUT', got exit $rc output '$out'"
    return 1
}

test_algorithms() {
    local rc
    rc=$(run_ssh "algorithms" "$COMMAND_TIMEOUT" -vvv -i "$IDENTITY" -- ping)
    local transcript="$SCRATCH_DIR/algorithms.out"
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
        skip "wrong-key rejection (ssh-keygen not available to generate a throwaway key)"
        return
    fi
    local wrong_key="$SCRATCH_DIR/throwaway_key"
    ssh-keygen -q -t ecdsa -b 256 -N "" -f "$wrong_key" >/dev/null 2>&1
    local rc
    rc=$(run_ssh "wrong_key" "$COMMAND_TIMEOUT" -i "$wrong_key" -- ping)
    if [[ "$rc" -ne 0 ]]; then
        pass "unrecognized public key is rejected (exit $rc)"
    else
        fail "unrecognized public key was ACCEPTED -- authentication is not fail-closed"
    fi
}

test_wrong_user_rejected() {
    local out="$SCRATCH_DIR/wrong_user.out"
    set +e
    run_with_timeout "$COMMAND_TIMEOUT" ssh "${SSH_COMMON_OPTS[@]}" -i "$IDENTITY" "not-flipper@$HOST" ping \
        > "$out" 2>&1
    local rc=$?
    set -e
    cp "$out" "$EVIDENCE_DIR/wrong_user.out" 2>/dev/null || true
    if [[ "$rc" -ne 0 ]]; then
        pass "unknown username is rejected (exit $rc)"
    else
        fail "unknown username was ACCEPTED -- authentication is not fail-closed"
    fi
}

test_password_rejected() {
    local rc
    rc=$(run_ssh "password_auth" "$COMMAND_TIMEOUT" \
        -o PreferredAuthentications=password,keyboard-interactive \
        -o PubkeyAuthentication=no -- ping)
    if [[ "$rc" -ne 0 ]]; then
        pass "password/keyboard-interactive authentication is unavailable (exit $rc)"
    else
        fail "password/keyboard-interactive authentication unexpectedly SUCCEEDED"
    fi
}

test_unknown_command_rejected() {
    local rc out
    rc=$(run_ssh "unknown_command" "$COMMAND_TIMEOUT" -i "$IDENTITY" -- "not-a-real-command")
    out="$(cat "$SCRATCH_DIR/unknown_command.out" 2>/dev/null || true)"
    if [[ "$rc" -ne 0 && "$out" != *"$EXPECTED_PING_OUTPUT"* ]]; then
        pass "unsupported exec command is rejected (exit $rc)"
    else
        fail "unsupported exec command was NOT rejected (exit $rc, output '$out')"
    fi
}

test_shell_rejected() {
    local rc
    rc=$(run_ssh "shell_request" "$COMMAND_TIMEOUT" -i "$IDENTITY" --)
    if [[ "$rc" -ne 0 ]]; then
        pass "interactive shell request is rejected (exit $rc)"
    else
        fail "interactive shell request unexpectedly SUCCEEDED"
    fi
}

test_pty_rejected() {
    local rc
    rc=$(run_ssh "pty_request" "$COMMAND_TIMEOUT" -tt -i "$IDENTITY" -- ping)
    if [[ "$rc" -ne 0 ]]; then
        pass "PTY allocation is rejected (exit $rc)"
    else
        fail "PTY allocation unexpectedly SUCCEEDED"
    fi
}

test_subsystem_rejected() {
    local rc
    rc=$(run_ssh "subsystem_request" "$COMMAND_TIMEOUT" -i "$IDENTITY" -s -- sftp)
    if [[ "$rc" -ne 0 ]]; then
        pass "subsystem request is rejected (exit $rc)"
    else
        fail "subsystem request unexpectedly SUCCEEDED"
    fi
}

test_forwarding_rejected() {
    local rc
    rc=$(run_ssh "forwarding_request" "$COMMAND_TIMEOUT" -N -i "$IDENTITY" \
        -L "127.0.0.1:0:127.0.0.1:80" -- )
    if [[ "$rc" -ne 0 ]]; then
        pass "TCP port forwarding is rejected (exit $rc)"
    else
        fail "TCP port forwarding unexpectedly SUCCEEDED"
    fi
}

test_second_connection_rejected() {
    if ! command -v nc >/dev/null 2>&1; then
        skip "second-simultaneous-connection rejection (nc not available to hold a raw connection open)"
        return
    fi
    # g_session_active is set the instant accept() returns, before the SSH
    # handshake even begins -- so a raw, silent TCP connection is enough to
    # occupy the one allowed slot for the hold duration.
    ( sleep "$HOLD_SECONDS" | nc "$HOST" "$PORT" >/dev/null 2>&1 ) &
    local holder_pid=$!
    sleep 1

    local rc
    rc=$(run_ssh "second_connection" "$COMMAND_TIMEOUT" -i "$IDENTITY" -- ping)
    if [[ "$rc" -ne 0 ]]; then
        pass "second simultaneous connection is rejected while the first is active"
    else
        fail "second simultaneous connection unexpectedly SUCCEEDED while the first was active"
    fi

    wait "$holder_pid" 2>/dev/null || true
}

test_reconnect_after_close() {
    sleep 1
    local rc out
    rc=$(run_ssh "reconnect" "$COMMAND_TIMEOUT" -i "$IDENTITY" -- ping)
    out="$(cat "$SCRATCH_DIR/reconnect.out" 2>/dev/null || true)"
    if [[ "$rc" -eq 0 && "$out" == "$EXPECTED_PING_OUTPUT" ]]; then
        pass "reconnect after the previous connection closed succeeds"
    else
        fail "reconnect after close failed (exit $rc, output '$out')"
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
        skip "soak phase (ssh-keygen not available to generate the per-cycle throwaway key)"
        return
    fi
    local wrong_key="$SCRATCH_DIR/soak_throwaway_key"
    ssh-keygen -q -t ecdsa -b 256 -N "" -f "$wrong_key" >/dev/null 2>&1

    local soak_pass=0 soak_fail=0
    log "starting soak phase: $CYCLES cycles of (successful ping, expected-failure wrong key)"
    for ((i = 1; i <= CYCLES; i++)); do
        local out rc
        out="$SCRATCH_DIR/soak_${i}_ok.out"
        set +e
        run_with_timeout "$COMMAND_TIMEOUT" ssh "${SSH_COMMON_OPTS[@]}" -i "$IDENTITY" "$SSH_USER@$HOST" ping \
            > "$out" 2>&1
        rc=$?
        set -e
        if [[ "$rc" -eq 0 && "$(cat "$out")" == "$EXPECTED_PING_OUTPUT" ]]; then
            soak_pass=$((soak_pass + 1))
        else
            fail "soak cycle $i: successful-ping leg failed (exit $rc)"
            cp "$out" "$EVIDENCE_DIR/soak_${i}_ok.out" 2>/dev/null || true
        fi

        out="$SCRATCH_DIR/soak_${i}_bad.out"
        set +e
        run_with_timeout "$COMMAND_TIMEOUT" ssh "${SSH_COMMON_OPTS[@]}" -i "$wrong_key" "$SSH_USER@$HOST" ping \
            > "$out" 2>&1
        rc=$?
        set -e
        if [[ "$rc" -ne 0 ]]; then
            soak_fail=$((soak_fail + 1))
        else
            fail "soak cycle $i: expected-failure leg unexpectedly SUCCEEDED"
            cp "$out" "$EVIDENCE_DIR/soak_${i}_bad.out" 2>/dev/null || true
        fi
    done

    {
        echo "soak_cycles_requested=$CYCLES"
        echo "soak_successful_pings_observed=$soak_pass"
        echo "soak_expected_failures_observed=$soak_fail"
    } > "$EVIDENCE_DIR/soak_summary.txt"

    if [[ "$soak_pass" -eq "$CYCLES" && "$soak_fail" -eq "$CYCLES" ]]; then
        pass "soak phase: $CYCLES/$CYCLES successful-ping cycles and $CYCLES/$CYCLES expected-failure cycles all behaved as expected"
    else
        fail "soak phase: only $soak_pass/$CYCLES successful-ping and $soak_fail/$CYCLES expected-failure cycles behaved as expected -- see soak_summary.txt and per-cycle transcripts in $EVIDENCE_DIR"
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
    local n
    n=$(grep -cE 'checkpoint=|handshake_auth_duration_ms=' "$out" || true)
    if [[ "$n" -gt 0 ]]; then
        pass "serial monitor log summary written to $out ($n matching lines) -- copy these into design doc section 8 in place of 'Pending hardware measurement'"
    else
        fail "serial monitor log given but no checkpoint/handshake-duration lines found in it -- was SSH actually exercised during this capture?"
    fi
}

# ---- run ---------------------------------------------------------------
log "evidence directory: $EVIDENCE_DIR"

if [[ "$MODE" == "default" ]]; then
    check_port_closed
else
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
        SKIP_COUNT=$((SKIP_COUNT + 12))
    fi
    summarize_monitor_log || true
fi

echo
log "SUMMARY: pass=$PASS_COUNT fail=$FAIL_COUNT skip=$SKIP_COUNT (evidence: $EVIDENCE_DIR)"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
