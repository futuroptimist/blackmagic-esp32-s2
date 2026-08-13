#!/usr/bin/env bash
# Regression tests for scripts/run_ssh_spike_hardware_validation.sh.
#
# No real network, hardware, or SSH server is used. Two techniques:
#
#   1. Source the validator script (its BASH_SOURCE guard means sourcing it
#      only defines functions/defaults, it does not run a validation pass)
#      and call individual functions directly against canned transcripts or
#      minimal manually-initialized state.
#   2. For a few end-to-end behaviors (the --mode default liveness gate,
#      --dry-run), invoke the validator as a real subprocess with PATH-
#      injected fake `curl`/`nc` commands standing in for the real tools.
#
# Run: scripts/test_ssh_spike_hardware_validation.sh
set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$REPO_ROOT/scripts/run_ssh_spike_hardware_validation.sh"

TESTS_RUN=0
FAILURES=0

CHECK() {
    # CHECK <description> <expected> <actual>
    local desc="$1" expected="$2" actual="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$expected" == "$actual" ]]; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc (expected '$expected', got '$actual')"
        FAILURES=$((FAILURES + 1))
    fi
}

CHECK_TRUE() {
    # CHECK_TRUE <description> <0-if-true-nonzero-if-false>
    local desc="$1" result="$2"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$result" -eq 0 ]]; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"
        FAILURES=$((FAILURES + 1))
    fi
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ssh-spike-validation-test.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

write_transcript() {
    local file="$1"; shift
    printf '%s\n' "$@" > "$file"
}

# Sourcing (not executing) the validator: its BASH_SOURCE guard means this
# only defines functions and the top-level defaults, it does not parse
# arguments or run a validation pass.
# shellcheck source=./run_ssh_spike_hardware_validation.sh
source "$VALIDATOR"

echo "== classify_ssh_result() =="

t="$WORKDIR/t_success.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'pong'
CHECK "successful session -> success" "success" "$(classify_ssh_result "$t" 0)"

t="$WORKDIR/t_auth.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'user@host: Permission denied (publickey).'
CHECK "OpenSSH's standard denial -> auth_rejected" "auth_rejected" "$(classify_ssh_result "$t" 255)"

t="$WORKDIR/t_refused.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'ssh: connect to host host port 2222: Connection refused'
CHECK "connection refused before auth -> transport_failure" "transport_failure" "$(classify_ssh_result "$t" 255)"

t="$WORKDIR/t_dns.out"
write_transcript "$t" \
    'ssh: Could not resolve hostname bogus.invalid: nodename nor servname provided, or not known'
CHECK "DNS resolution failure (no 'Connecting to' line at all) -> transport_failure, not local_invocation_failure" \
    "transport_failure" "$(classify_ssh_result "$t" 255)"

t="$WORKDIR/t_hostkey.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Host key verification failed.'
CHECK "host key mismatch -> host_key_failure" "host_key_failure" "$(classify_ssh_result "$t" 255)"

t="$WORKDIR/t_protorej.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'channel 0: open failed: administratively prohibited: open failed'
CHECK "post-auth channel-open refusal -> protocol_rejected" "protocol_rejected" "$(classify_ssh_result "$t" 255)"

t="$WORKDIR/t_protorej_closelike.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'Connection closed by remote host'
CHECK "post-auth abrupt close (text overlaps a transport-failure pattern) -> protocol_rejected, ordering matters" \
    "protocol_rejected" "$(classify_ssh_result "$t" 255)"

t="$WORKDIR/t_local.out"
write_transcript "$t" \
    "Bad local forwarding specification '127.0.0.1:0:127.0.0.1:80'"
CHECK "bad local ssh(1) argument, network never attempted -> local_invocation_failure" \
    "local_invocation_failure" "$(classify_ssh_result "$t" 255)"

CHECK "rc=124 -> timeout regardless of transcript content" "timeout" "$(classify_ssh_result "$t" 124)"

t="$WORKDIR/t_unknown.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'some unrecognized message this classifier has no pattern for'
CHECK "connected, never authenticated, no recognized pattern -> unknown_failure (never valid rejection evidence)" \
    "unknown_failure" "$(classify_ssh_result "$t" 255)"

echo
echo "== channel_request_failed() / channel_open_failed() / advertised_auth_methods_excludes() =="

t="$WORKDIR/t_execfail.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'debug1: Sending command: not-a-real-command' \
    'exec request failed on channel 0'
if channel_request_failed "$t" "exec"; then r=0; else r=1; fi
CHECK_TRUE "genuine 'exec request failed on channel' line is detected" "$r"
if channel_request_failed "$t" "shell"; then r=1; else r=0; fi
CHECK_TRUE "'exec request failed' does not also satisfy a 'shell' evidence check" "$r"

t="$WORKDIR/t_execran.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'some-command-that-was-actually-run-and-exited-nonzero'
if channel_request_failed "$t" "exec"; then r=1; else r=0; fi
CHECK_TRUE "a command that ran and merely exited non-zero (no refusal line) is NOT deceptively treated as a refusal" "$r"

t="$WORKDIR/t_openfail.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'channel 0: open failed: administratively prohibited: open failed'
if channel_open_failed "$t"; then r=0; else r=1; fi
CHECK_TRUE "genuine 'channel N: open failed' line is detected" "$r"
if channel_request_failed "$t" "exec"; then r=1; else r=0; fi
CHECK_TRUE "a channel-open failure does NOT also satisfy an exec channel-request evidence check" "$r"

t="$WORKDIR/t_openaccepted_laterfail.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'Connection closed by remote host'
if channel_open_failed "$t"; then r=1; else r=0; fi
CHECK_TRUE "an accepted channel whose destination later fails (no 'open failed' line) is NOT deceptively treated as a refusal" "$r"

t="$WORKDIR/t_authmethods_excl.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'debug1: Authentications that can continue: publickey' \
    'user@host: Permission denied (publickey).'
if advertised_auth_methods_excludes "$t" "password" "keyboard-interactive"; then r=0; else r=1; fi
CHECK_TRUE "advertised methods excluding password/keyboard-interactive is detected" "$r"

t="$WORKDIR/t_authmethods_incl.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'debug1: Authentications that can continue: publickey,password' \
    'user@host: Permission denied (publickey,password).'
if advertised_auth_methods_excludes "$t" "password" "keyboard-interactive"; then r=1; else r=0; fi
CHECK_TRUE "advertised methods that DO include password is correctly NOT reported as excluded" "$r"

t="$WORKDIR/t_authmethods_missing.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'user@host: Permission denied (publickey).'
if advertised_auth_methods_excludes "$t" "password" "keyboard-interactive"; then r=1; else r=0; fi
CHECK_TRUE "a missing 'Authentications that can continue' line is inconclusive, not treated as excluded" "$r"

echo
echo "== class_in() =="

if class_in "protocol_rejected" transport_failure protocol_rejected auth_rejected; then r=0; else r=1; fi
CHECK_TRUE "class_in: membership match" "$r"
if class_in "success" transport_failure protocol_rejected auth_rejected; then r=1; else r=0; fi
CHECK_TRUE "class_in: non-membership correctly rejected" "$r"

echo
echo "== extract_last_output_line() =="

t="$WORKDIR/t_extract.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'pong' \
    'debug1: client_input_channel_req: channel 0 rtype exit-status reply 0' \
    'Transferred: sent 2688, received 2560 bytes, in 0.0 seconds' \
    'Bytes per second: sent 212272.0, received 202163.8'
CHECK "isolates the real 'pong' output from ssh -v's debug lines and post-command summary" \
    "pong" "$(extract_last_output_line "$t")"

echo
echo "== --mode default: board-liveness gate (subprocess, fake curl/nc) =="

FAKE_BIN="$WORKDIR/fakebin"
mkdir -p "$FAKE_BIN"

# Scenario: board unreachable (curl fails) -- must FAIL, and must never even
# invoke the port-closed probe (an unreachable board must not be treated as
# "SSH is correctly disabled").
cat > "$FAKE_BIN/curl" <<'FAKE_CURL_EOF'
#!/usr/bin/env bash
exit 7
FAKE_CURL_EOF
chmod +x "$FAKE_BIN/curl"
cat > "$FAKE_BIN/nc" <<'FAKE_NC_EOF'
#!/usr/bin/env bash
echo "nc should not have been invoked when the board is unreachable" >&2
exit 1
FAKE_NC_EOF
chmod +x "$FAKE_BIN/nc"

set +e
PATH="$FAKE_BIN:$PATH" "$VALIDATOR" --mode default --host 192.0.2.1 --http-port 80 \
    --connect-timeout 1 > "$WORKDIR/out_unreachable.log" 2>&1
rc=$?
set -e
CHECK "unreachable board -> non-zero exit, not a false PASS" "1" "$rc"
if grep -q "nc should not have been invoked" "$WORKDIR/out_unreachable.log"; then r=1; else r=0; fi
CHECK_TRUE "unreachable board: port-closed probe is never run" "$r"
if grep -q "FAIL:.*NOT reachable via HTTP" "$WORKDIR/out_unreachable.log"; then r=0; else r=1; fi
CHECK_TRUE "unreachable board: reported as an explicit FAIL" "$r"

# Scenario: board reachable, port genuinely closed -- must PASS/exit 0.
cat > "$FAKE_BIN/curl" <<'FAKE_CURL_OK_EOF'
#!/usr/bin/env bash
# Simulate `curl -fsS ... -o <file> URL`: touch whatever -o points at.
prev=""
for arg in "$@"; do
    if [[ "$prev" == "-o" ]]; then
        touch "$arg"
    fi
    prev="$arg"
done
exit 0
FAKE_CURL_OK_EOF
chmod +x "$FAKE_BIN/curl"
cat > "$FAKE_BIN/nc" <<'FAKE_NC_CLOSED_EOF'
#!/usr/bin/env bash
# -z liveness-style probe: report the port as closed.
exit 1
FAKE_NC_CLOSED_EOF
chmod +x "$FAKE_BIN/nc"

set +e
PATH="$FAKE_BIN:$PATH" "$VALIDATOR" --mode default --host 192.0.2.1 --http-port 80 \
    --connect-timeout 1 > "$WORKDIR/out_closed.log" 2>&1
rc=$?
set -e
CHECK "reachable board + genuinely closed port -> exit 0" "0" "$rc"

# Scenario: board reachable, port OPEN -- must FAIL, not silently pass.
cat > "$FAKE_BIN/nc" <<'FAKE_NC_OPEN_EOF'
#!/usr/bin/env bash
exit 0
FAKE_NC_OPEN_EOF
chmod +x "$FAKE_BIN/nc"

set +e
PATH="$FAKE_BIN:$PATH" "$VALIDATOR" --mode default --host 192.0.2.1 --http-port 80 \
    --connect-timeout 1 > "$WORKDIR/out_open.log" 2>&1
rc=$?
set -e
CHECK "reachable board + OPEN port 2222 -> non-zero exit (FAIL, not a false pass)" "1" "$rc"

echo
echo "== test_forwarding_rejected(): uses -W, not the invalid -L port-0 form =="

# Manually initialize the state main() would normally set up from argument
# parsing, since we called neither main() nor the CLI.
HOST="127.0.0.1"
PORT="2222"
SSH_USER="testuser"
IDENTITY="$WORKDIR/fake_identity"
: > "$IDENTITY"
COMMAND_TIMEOUT=5
CONNECT_TIMEOUT=5
SCRATCH_DIR="$WORKDIR/scratch"; mkdir -p "$SCRATCH_DIR"
EVIDENCE_DIR="$WORKDIR/evidence"; mkdir -p "$EVIDENCE_DIR"
KNOWN_HOSTS="$SCRATCH_DIR/known_hosts"; : > "$KNOWN_HOSTS"
build_ssh_common_opts
PASS_COUNT=0
FAIL_COUNT=0

cat > "$FAKE_BIN/ssh" <<FAKE_SSH_FWD_EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" > "$WORKDIR/ssh_argv_capture.txt"
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'channel 0: open failed: administratively prohibited: open failed'
exit 255
FAKE_SSH_FWD_EOF
chmod +x "$FAKE_BIN/ssh"

PATH="$FAKE_BIN:$PATH" test_forwarding_rejected

if grep -q -- "-W" "$WORKDIR/ssh_argv_capture.txt"; then r=0; else r=1; fi
CHECK_TRUE "forwarding test invokes ssh with -W (a real server-reaching request)" "$r"
if grep -q -- "-L" "$WORKDIR/ssh_argv_capture.txt"; then r=1; else r=0; fi
CHECK_TRUE "forwarding test does NOT use the locally-invalid '-L ...:0...' form" "$r"
CHECK "forwarding test: genuine channel-open-failure evidence -> recorded as PASS" "1" "$PASS_COUNT"
CHECK "forwarding test: genuine channel-open-failure evidence -> no FAIL recorded" "0" "$FAIL_COUNT"

echo
echo "== deceptive-transcript regressions: generic protocol_rejected must not satisfy request-specific checks =="

# Scenario (a): the board actually ACCEPTED the forwarding channel-open (no
# "channel N: open failed" line) but the destination connection then failed
# for an unrelated reason -- classify_ssh_result() still reports
# protocol_rejected (authenticated, non-zero exit), but that must not be
# mistaken for a rejected forwarding request.
PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_FWD_ACCEPTED_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'Connection closed by remote host'
exit 255
FAKE_SSH_FWD_ACCEPTED_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_forwarding_rejected
CHECK "forwarding accepted + destination failure later (no 'open failed' line) -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "forwarding accepted + destination failure later (no 'open failed' line) -> recorded as FAIL (inconclusive)" "1" "$FAIL_COUNT"

# Scenario (b): an accepted, executed command that merely exited non-zero --
# no "exec request failed on channel" line -- must not pass
# test_unknown_command_rejected().
PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_EXEC_RAN_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'command-was-actually-run-and-exited-nonzero'
exit 1
FAKE_SSH_EXEC_RAN_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_unknown_command_rejected
CHECK "unknown-command test: authenticated + executed + non-zero exit (no refusal line) -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "unknown-command test: authenticated + executed + non-zero exit (no refusal line) -> recorded as FAIL (inconclusive)" "1" "$FAIL_COUNT"

# Scenario (c): a genuine "exec request failed on channel" refusal DOES pass.
PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_EXEC_REFUSED_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'exec request failed on channel 0'
exit 255
FAKE_SSH_EXEC_REFUSED_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_unknown_command_rejected
CHECK "unknown-command test: genuine 'exec request failed on channel' evidence -> recorded as PASS" "1" "$PASS_COUNT"
CHECK "unknown-command test: genuine 'exec request failed on channel' evidence -> no FAIL recorded" "0" "$FAIL_COUNT"

# Scenario (d): an abrupt post-auth close with no operation-specific marker
# at all must not satisfy test_shell_rejected() or test_subsystem_rejected().
PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_ABRUPT_CLOSE_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'Connection closed by remote host'
exit 255
FAKE_SSH_ABRUPT_CLOSE_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_shell_rejected
CHECK "shell test: abrupt post-auth close with no 'shell request failed' marker -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "shell test: abrupt post-auth close with no 'shell request failed' marker -> recorded as FAIL (inconclusive)" "1" "$FAIL_COUNT"

PASS_COUNT=0
FAIL_COUNT=0
PATH="$FAKE_BIN:$PATH" test_subsystem_rejected
CHECK "subsystem test: abrupt post-auth close with no 'subsystem request failed' marker -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "subsystem test: abrupt post-auth close with no 'subsystem request failed' marker -> recorded as FAIL (inconclusive)" "1" "$FAIL_COUNT"

# Scenario (e): genuine "shell"/"subsystem" refusals DO pass.
PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_SHELL_REFUSED_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'shell request failed on channel 0'
exit 255
FAKE_SSH_SHELL_REFUSED_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_shell_rejected
CHECK "shell test: genuine 'shell request failed on channel' evidence -> recorded as PASS" "1" "$PASS_COUNT"
CHECK "shell test: genuine 'shell request failed on channel' evidence -> no FAIL recorded" "0" "$FAIL_COUNT"

PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_SUBSYS_REFUSED_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'subsystem request failed on channel 0'
exit 255
FAKE_SSH_SUBSYS_REFUSED_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_subsystem_rejected
CHECK "subsystem test: genuine 'subsystem request failed on channel' evidence -> recorded as PASS" "1" "$PASS_COUNT"
CHECK "subsystem test: genuine 'subsystem request failed on channel' evidence -> no FAIL recorded" "0" "$FAIL_COUNT"

# Scenario (f): test_pty_rejected() -- pty-req acknowledged (no "pty-req
# request failed" line, by design), "ping" never serviced, exec refused ->
# PASS. A deceptive transcript where "ping" WAS serviced (the exec callback
# somehow let it through) must not pass despite protocol_rejected.
PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<FAKE_SSH_PTY_REFUSED_EOF
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'exec request failed on channel 0'
exit 255
FAKE_SSH_PTY_REFUSED_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_pty_rejected
CHECK "PTY test: pty-req acknowledged, subsequent 'exec request failed on channel', no pong -> recorded as PASS" "1" "$PASS_COUNT"
CHECK "PTY test: pty-req acknowledged, subsequent 'exec request failed on channel', no pong -> no FAIL recorded" "0" "$FAIL_COUNT"

PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<FAKE_SSH_PTY_DECEPTIVE_EOF
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'Connection closed by remote host'
exit 255
FAKE_SSH_PTY_DECEPTIVE_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_pty_rejected
CHECK "PTY test: abrupt post-auth close with no 'exec request failed' marker -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "PTY test: abrupt post-auth close with no 'exec request failed' marker -> recorded as FAIL (inconclusive)" "1" "$FAIL_COUNT"

echo
echo "== test_password_rejected(): requires advertised-methods evidence, not just auth_rejected =="

PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_PW_GENUINE_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'debug1: Authentications that can continue: publickey'
echo 'user@127.0.0.1: Permission denied (publickey).'
exit 255
FAKE_SSH_PW_GENUINE_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_password_rejected
CHECK "password test: advertised methods exclude password/keyboard-interactive -> recorded as PASS" "1" "$PASS_COUNT"
CHECK "password test: advertised methods exclude password/keyboard-interactive -> no FAIL recorded" "0" "$FAIL_COUNT"

# Deceptive: auth_rejected for some other reason, with no "Authentications
# that can continue" evidence at all -- must not pass.
PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_PW_NOEVIDENCE_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'user@127.0.0.1: Permission denied (publickey).'
exit 255
FAKE_SSH_PW_NOEVIDENCE_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_password_rejected
CHECK "password test: auth_rejected with no advertised-methods evidence -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "password test: auth_rejected with no advertised-methods evidence -> recorded as FAIL (inconclusive)" "1" "$FAIL_COUNT"

echo
echo "== test_second_connection_rejected(): requires a confirmed holder connection =="

PASS_COUNT=0
FAIL_COUNT=0
HOLD_SECONDS=1
cat > "$FAKE_BIN/nc" <<'FAKE_NC_NOCONNECT_EOF'
#!/usr/bin/env bash
# Simulate a holder that never actually connects: consume the piped stdin
# without ever reporting success, and never touch the network.
cat > /dev/null
exit 1
FAKE_NC_NOCONNECT_EOF
chmod +x "$FAKE_BIN/nc"

PATH="$FAKE_BIN:$PATH" test_second_connection_rejected

CHECK "unconfirmed holder connection -> never recorded as PASS" "0" "$PASS_COUNT"
CHECK "unconfirmed holder connection -> recorded as FAIL (inconclusive evidence)" "1" "$FAIL_COUNT"

echo
echo "== test_second_connection_rejected(): confirmed holder + rejected second connection =="

PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/nc" <<'FAKE_NC_CONNECT_EOF'
#!/usr/bin/env bash
if [[ "$1" == "-v" ]]; then
    echo "Connection to $2 port $3 [tcp/*] succeeded!" >&2
    cat > /dev/null
    exit 0
fi
exit 1
FAKE_NC_CONNECT_EOF
chmod +x "$FAKE_BIN/nc"
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_2ND_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Connection closed by remote host'
exit 255
FAKE_SSH_2ND_EOF
chmod +x "$FAKE_BIN/ssh"

PATH="$FAKE_BIN:$PATH" test_second_connection_rejected

CHECK "confirmed holder + rejected second connection -> PASS" "1" "$PASS_COUNT"
CHECK "confirmed holder + rejected second connection -> no FAIL" "0" "$FAIL_COUNT"

echo
echo "== timeouts never satisfy a rejection check =="

PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_HANG_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
sleep 30
FAKE_SSH_HANG_EOF
chmod +x "$FAKE_BIN/ssh"

PATH="$FAKE_BIN:$PATH" bash -c "
    source '$VALIDATOR'
    HOST='127.0.0.1'; PORT='2222'; SSH_USER='testuser'
    IDENTITY='$IDENTITY'
    COMMAND_TIMEOUT=1; CONNECT_TIMEOUT=1
    SCRATCH_DIR='$SCRATCH_DIR'; EVIDENCE_DIR='$EVIDENCE_DIR'
    KNOWN_HOSTS='$KNOWN_HOSTS'
    build_ssh_common_opts
    PASS_COUNT=0; FAIL_COUNT=0
    test_wrong_key_rejected_TIMEOUT_STANDIN() {
        run_ssh 'timeout_probe' \"\$COMMAND_TIMEOUT\" -i \"\$IDENTITY\" -- ping
        [[ \"\$RUN_SSH_CLASS\" == timeout ]] && echo TIMEOUT_CLASS_OK || echo TIMEOUT_CLASS_WRONG:\$RUN_SSH_CLASS
    }
    test_wrong_key_rejected_TIMEOUT_STANDIN
" > "$WORKDIR/out_timeout.log" 2>&1 || true
if grep -q "TIMEOUT_CLASS_OK" "$WORKDIR/out_timeout.log"; then r=0; else r=1; fi
CHECK_TRUE "a hung ssh invocation classifies as timeout, not any rejection class" "$r"

echo
echo "== --dry-run is network- and key-independent =="

set +e
"$VALIDATOR" --dry-run --mode experimental --host 203.0.113.1 --user flipper \
    --identity /this/path/does/not/exist --host-key-fingerprint SHA256:whatever --cycles 5 \
    > "$WORKDIR/out_dryrun.log" 2>&1
rc=$?
set -e
CHECK "dry-run succeeds with a nonexistent identity file and an unroutable host" "0" "$rc"

set +e
"$VALIDATOR" --dry-run --mode default --host 203.0.113.1 > "$WORKDIR/out_dryrun_default.log" 2>&1
rc=$?
set -e
CHECK "dry-run (default mode) succeeds with an unroutable host" "0" "$rc"

echo
if [[ "$FAILURES" -eq 0 ]]; then
    echo "All $TESTS_RUN hardware-validation regression tests passed."
    exit 0
fi
echo "$FAILURES of $TESTS_RUN hardware-validation regression tests FAILED."
exit 1
