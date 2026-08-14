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

t="$WORKDIR/t_openfail_unknowntype.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'channel 0: open failed: unknown channel type: Channel type not supported.'
if channel_open_failed "$t" "unknown channel type"; then r=0; else r=1; fi
CHECK_TRUE "genuine 'channel N: open failed: unknown channel type' line is detected" "$r"
if channel_request_failed "$t" "exec"; then r=1; else r=0; fi
CHECK_TRUE "a channel-open failure does NOT also satisfy an exec channel-request evidence check" "$r"

t="$WORKDIR/t_openfail_connectfailed.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'channel 0: open failed: connect failed: Connection refused'
if channel_open_failed "$t" "unknown channel type"; then r=1; else r=0; fi
CHECK_TRUE "a genuine channel-open failure with an UNRELATED reason ('connect failed', a destination-connect failure) does NOT satisfy the 'unknown channel type' evidence check" "$r"

t="$WORKDIR/t_openaccepted_laterfail.out"
write_transcript "$t" \
    'debug1: Connecting to host [1.2.3.4] port 2222.' \
    'Authenticated to host ([1.2.3.4]:2222) using "publickey".' \
    'Connection closed by remote host'
if channel_open_failed "$t" "unknown channel type"; then r=1; else r=0; fi
CHECK_TRUE "an accepted channel whose destination later fails (no 'open failed' line at all) is NOT deceptively treated as a refusal" "$r"

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

# Several regressions below invoke the validator as a real subprocess in a
# non-dry-run mode, which (as of --firmware-image) always calls
# record_firmware_provenance() before anything else -- that function reads
# Git state from wherever the validator script itself lives (SCRIPT_DIR).
# Running the *actual* checked-out validator would tie these tests to
# whatever tracked/staged state this real working tree happens to be in at
# test time (which is not always clean during development) -- copy the
# validator into its own tiny, deterministic, single-commit throwaway repo
# instead, so provenance recording always succeeds the same way regardless
# of this actual repository's own state.
CLEAN_VALIDATOR_REPO="$WORKDIR/clean_validator_repo"
mkdir -p "$CLEAN_VALIDATOR_REPO"
cp "$VALIDATOR" "$CLEAN_VALIDATOR_REPO/run_ssh_spike_hardware_validation.sh"
chmod +x "$CLEAN_VALIDATOR_REPO/run_ssh_spike_hardware_validation.sh"
(
    cd "$CLEAN_VALIDATOR_REPO"
    git init -q
    git config user.email "test@example.invalid"
    git config user.name "test"
    git add run_ssh_spike_hardware_validation.sh
    git commit -q -m "snapshot for testing"
)
CLEAN_VALIDATOR="$CLEAN_VALIDATOR_REPO/run_ssh_spike_hardware_validation.sh"
DUMMY_FIRMWARE_IMAGE="$WORKDIR/dummy_firmware.bin"
printf 'dummy firmware bytes for testing\n' > "$DUMMY_FIRMWARE_IMAGE"

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
PATH="$FAKE_BIN:$PATH" "$CLEAN_VALIDATOR" --mode default --host 192.0.2.1 --http-port 80 \
    --firmware-image "$DUMMY_FIRMWARE_IMAGE" --connect-timeout 1 > "$WORKDIR/out_unreachable.log" 2>&1
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
PATH="$FAKE_BIN:$PATH" "$CLEAN_VALIDATOR" --mode default --host 192.0.2.1 --http-port 80 \
    --firmware-image "$DUMMY_FIRMWARE_IMAGE" --connect-timeout 1 > "$WORKDIR/out_closed.log" 2>&1
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
PATH="$FAKE_BIN:$PATH" "$CLEAN_VALIDATOR" --mode default --host 192.0.2.1 --http-port 80 \
    --firmware-image "$DUMMY_FIRMWARE_IMAGE" --connect-timeout 1 > "$WORKDIR/out_open.log" 2>&1
rc=$?
set -e
CHECK "reachable board + OPEN port 2222 -> non-zero exit (FAIL, not a false pass)" "1" "$rc"

echo
echo "== verify_host_key_fingerprint(): fail-closed missing-prerequisite handling =="

# A missing ssh-keyscan/ssh-keygen is incomplete evidence (the check's own
# prerequisite tool is unavailable), not an operational failure of the
# check -- it must record a required skip, not a FAIL, and never a PASS.
# Build a PATH-controlled sandbox so "command -v" genuinely fails to find
# the omitted tool, rather than trying to shadow real system binaries.
HOST="127.0.0.1"
PORT="2222"
CONNECT_TIMEOUT=5
HOST_KEY_FINGERPRINT="SHA256:doesnotmatter"
SCRATCH_DIR="$WORKDIR/scratch_hostkey"; mkdir -p "$SCRATCH_DIR"
KNOWN_HOSTS="$SCRATCH_DIR/known_hosts"; : > "$KNOWN_HOSTS"

EMPTY_TOOL_DIR="$WORKDIR/no_tools"
mkdir -p "$EMPTY_TOOL_DIR"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; REQUIRED_SKIP_COUNT=0
set +e
PATH="$EMPTY_TOOL_DIR" verify_host_key_fingerprint
fn_rc=$?
set -e
CHECK "missing ssh-keyscan -> function returns non-zero" "1" "$fn_rc"
CHECK "missing ssh-keyscan -> exactly one required skip" "1" "$REQUIRED_SKIP_COUNT"
CHECK "missing ssh-keyscan -> exactly one skip overall" "1" "$SKIP_COUNT"
CHECK "missing ssh-keyscan -> no PASS recorded" "0" "$PASS_COUNT"
CHECK "missing ssh-keyscan -> no ordinary FAIL recorded" "0" "$FAIL_COUNT"

# ssh-keyscan present but unused (only ssh-keygen is missing): a dummy that
# would prove itself invoked via a sentinel file, so the "never invokes the
# scan" requirement is checked directly rather than assumed.
KEYSCAN_ONLY_DIR="$WORKDIR/keyscan_only_tools"
mkdir -p "$KEYSCAN_ONLY_DIR"
KEYSCAN_INVOKED_SENTINEL="$WORKDIR/keyscan_invoked"
rm -f "$KEYSCAN_INVOKED_SENTINEL"
cat > "$KEYSCAN_ONLY_DIR/ssh-keyscan" <<EOF
#!/usr/bin/env bash
: > "$KEYSCAN_INVOKED_SENTINEL"
exit 0
EOF
chmod +x "$KEYSCAN_ONLY_DIR/ssh-keyscan"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; REQUIRED_SKIP_COUNT=0
set +e
PATH="$KEYSCAN_ONLY_DIR" verify_host_key_fingerprint
fn_rc=$?
set -e
CHECK "ssh-keyscan present, ssh-keygen missing -> function returns non-zero" "1" "$fn_rc"
CHECK "ssh-keyscan present, ssh-keygen missing -> exactly one required skip" "1" "$REQUIRED_SKIP_COUNT"
CHECK "ssh-keyscan present, ssh-keygen missing -> exactly one skip overall" "1" "$SKIP_COUNT"
CHECK "ssh-keyscan present, ssh-keygen missing -> no PASS recorded" "0" "$PASS_COUNT"
CHECK "ssh-keyscan present, ssh-keygen missing -> no ordinary FAIL recorded" "0" "$FAIL_COUNT"
if [[ -e "$KEYSCAN_INVOKED_SENTINEL" ]]; then r=1; else r=0; fi
CHECK_TRUE "ssh-keyscan present, ssh-keygen missing -> the scan is never actually invoked" "$r"

# End-to-end: without --allow-incomplete-evidence, a required skip from this
# same missing-prerequisite path must leave the whole run's exit status
# non-zero -- verified via a real subprocess invocation, not just the
# function-level accounting above. A subprocess launch of the validator
# needs its own ordinary startup tools (basename, mktemp, etc.) to still be
# resolvable, so build a sandbox PATH that keeps real symlinks to every
# other tool the script needs and omits only ssh-keyscan -- rather than an
# empty PATH, which would make the process fail before ever reaching
# verify_host_key_fingerprint() and falsely satisfy a bare "non-zero exit"
# check for the wrong reason.
SANDBOX_NO_KEYSCAN="$WORKDIR/sandbox_no_ssh_keyscan"
mkdir -p "$SANDBOX_NO_KEYSCAN"
for tool in env bash basename dirname mktemp mkdir cat grep awk cp sleep tr rm ssh nc curl \
        ssh-keygen timeout gtimeout git sha256sum shasum date; do
    real="$(command -v "$tool" 2>/dev/null || true)"
    [[ -n "$real" ]] && ln -sf "$real" "$SANDBOX_NO_KEYSCAN/$tool"
done
# ssh-keyscan is deliberately not linked into this sandbox. git/sha256sum
# (or shasum)/date are needed for record_firmware_provenance(), which now
# runs before verify_host_key_fingerprint() -- see the CLEAN_VALIDATOR note
# above for why $CLEAN_VALIDATOR (not the real checkout) is used here too.

IDENTITY_FOR_HOSTKEY_TEST="$WORKDIR/fake_identity_hostkey"
: > "$IDENTITY_FOR_HOSTKEY_TEST"
set +e
PATH="$SANDBOX_NO_KEYSCAN" "$CLEAN_VALIDATOR" --mode experimental --host 203.0.113.1 \
    --user flipper --identity "$IDENTITY_FOR_HOSTKEY_TEST" \
    --host-key-fingerprint SHA256:doesnotmatter \
    --firmware-image "$DUMMY_FIRMWARE_IMAGE" \
    > "$WORKDIR/out_missing_keyscan.log" 2>&1
rc=$?
set -e
CHECK "end-to-end: missing ssh-keyscan -> whole run exits non-zero without --allow-incomplete-evidence" "1" "$rc"
if grep -q "required_skip=1" "$WORKDIR/out_missing_keyscan.log"; then r=0; else r=1; fi
CHECK_TRUE "end-to-end: missing ssh-keyscan -> summary reports exactly one required skip" "$r"

echo
echo "== record_firmware_provenance(): binds evidence to Git HEAD + firmware SHA-256 =="

# make_test_git_repo <dir> -- a throwaway repo with exactly one tracked
# file and one commit, so tests below know the exact expected HEAD.
make_test_git_repo() {
    local dir="$1"
    mkdir -p "$dir"
    (
        cd "$dir"
        git init -q
        git config user.email "test@example.invalid"
        git config user.name "test"
        echo "tracked" > tracked_file.txt
        git add tracked_file.txt
        git commit -q -m "initial commit"
    )
}

PROV_REPO="$WORKDIR/prov_repo"
make_test_git_repo "$PROV_REPO"
PROV_EXPECTED_HEAD="$(cd "$PROV_REPO" && git rev-parse HEAD)"

PROV_IMAGE="$WORKDIR/prov_firmware.bin"
printf 'firmware bytes for provenance testing\n' > "$PROV_IMAGE"
if command -v sha256sum >/dev/null 2>&1; then
    PROV_EXPECTED_SHA256="$(sha256sum "$PROV_IMAGE" | awk '{print $1}')"
else
    PROV_EXPECTED_SHA256="$(shasum -a 256 "$PROV_IMAGE" | awk '{print $1}')"
fi

PROV_EVIDENCE_DIR="$WORKDIR/prov_evidence"; mkdir -p "$PROV_EVIDENCE_DIR"
EVIDENCE_DIR="$PROV_EVIDENCE_DIR"
SCRIPT_DIR="$PROV_REPO"

# A nonexistent --firmware-image must fail before doing anything else.
PASS_COUNT=0; FAIL_COUNT=0
FIRMWARE_IMAGE="$WORKDIR/this_image_does_not_exist.bin"
set +e
record_firmware_provenance "default"
fn_rc=$?
set -e
CHECK "nonexistent --firmware-image -> function returns non-zero" "1" "$fn_rc"
CHECK "nonexistent --firmware-image -> no PASS recorded" "0" "$PASS_COUNT"
CHECK "nonexistent --firmware-image -> recorded as FAIL" "1" "$FAIL_COUNT"

# A clean repo + a real image must PASS and record the exact expected
# Git HEAD and SHA-256 in the correct mode-specific evidence file.
PASS_COUNT=0; FAIL_COUNT=0
FIRMWARE_IMAGE="$PROV_IMAGE"
set +e
record_firmware_provenance "experimental"
fn_rc=$?
set -e
CHECK "clean repo -> function returns success" "0" "$fn_rc"
CHECK "clean repo -> recorded as PASS" "1" "$PASS_COUNT"
CHECK "clean repo -> no FAIL" "0" "$FAIL_COUNT"
PROV_OUT="$PROV_EVIDENCE_DIR/firmware_provenance_experimental.txt"
if [[ -f "$PROV_OUT" ]]; then r=0; else r=1; fi
CHECK_TRUE "clean repo -> mode-specific provenance file was written" "$r"
if grep -q "^git_head=$PROV_EXPECTED_HEAD\$" "$PROV_OUT"; then r=0; else r=1; fi
CHECK_TRUE "clean repo -> recorded git_head matches the repo's actual HEAD" "$r"
if grep -q "^firmware_image_sha256=$PROV_EXPECTED_SHA256\$" "$PROV_OUT"; then r=0; else r=1; fi
CHECK_TRUE "clean repo -> recorded SHA-256 matches the image's actual hash" "$r"
if grep -q "^mode=experimental\$" "$PROV_OUT"; then r=0; else r=1; fi
CHECK_TRUE "clean repo -> recorded mode matches the caller's mode argument" "$r"
if grep -q "^attestation=.*attests that" "$PROV_OUT"; then r=0; else r=1; fi
CHECK_TRUE "clean repo -> provenance file states the operator-attestation boundary explicitly" "$r"

# A dirty *tracked* (unstaged) file must fail closed.
echo "modified" >> "$PROV_REPO/tracked_file.txt"
PASS_COUNT=0; FAIL_COUNT=0
set +e
record_firmware_provenance "default"
fn_rc=$?
set -e
CHECK "dirty tracked (unstaged) file -> function returns non-zero" "1" "$fn_rc"
CHECK "dirty tracked (unstaged) file -> no PASS recorded" "0" "$PASS_COUNT"
CHECK "dirty tracked (unstaged) file -> recorded as FAIL" "1" "$FAIL_COUNT"

# A dirty *index* (staged but not committed) must also fail closed.
( cd "$PROV_REPO" && git add tracked_file.txt )
PASS_COUNT=0; FAIL_COUNT=0
set +e
record_firmware_provenance "default"
fn_rc=$?
set -e
CHECK "dirty index (staged, uncommitted) -> function returns non-zero" "1" "$fn_rc"
CHECK "dirty index (staged, uncommitted) -> no PASS recorded" "0" "$PASS_COUNT"
CHECK "dirty index (staged, uncommitted) -> recorded as FAIL" "1" "$FAIL_COUNT"
( cd "$PROV_REPO" && git checkout -q -- tracked_file.txt )

echo
echo "== missing --firmware-image fails before any network access =="

set +e
"$VALIDATOR" --mode default --host 203.0.113.1 --connect-timeout 1 \
    > "$WORKDIR/out_missing_firmware_image.log" 2>&1
rc=$?
set -e
CHECK "missing --firmware-image (non-dry-run) -> exit 2" "2" "$rc"
if grep -q "evidence directory:" "$WORKDIR/out_missing_firmware_image.log"; then r=1; else r=0; fi
CHECK_TRUE "missing --firmware-image -> no network/evidence phase was ever reached" "$r"
if grep -q "firmware-image is required" "$WORKDIR/out_missing_firmware_image.log"; then r=0; else r=1; fi
CHECK_TRUE "missing --firmware-image -> a clear error names the missing flag" "$r"

echo
echo "== summarize_monitor_log(): requires complete lifecycle/success/failure evidence =="

EVIDENCE_DIR="$WORKDIR/evidence_monitor"; mkdir -p "$EVIDENCE_DIR"

write_monitor_log() {
    local file="$1"; shift
    printf '%s\n' "$@" > "$file"
}

checkpoint_line() {
    # checkpoint_line <name> -- a well-formed metric line for that category.
    printf 'checkpoint=%s free_heap=100000 min_free_heap_since_boot=90000 largest_free_block=50000 stack_hwm=2000' "$1"
}

# A complete capture: all six lifecycle checkpoints plus one success and one
# failure handshake/auth duration line.
COMPLETE_MONITOR_LOG="$WORKDIR/monitor_complete.log"
write_monitor_log "$COMPLETE_MONITOR_LOG" \
    "$(checkpoint_line before_ssh_init)" \
    "$(checkpoint_line after_listener_init)" \
    "$(checkpoint_line before_handshake)" \
    "$(checkpoint_line after_auth)" \
    "$(checkpoint_line after_failed_handshake)" \
    "$(checkpoint_line after_disconnect)" \
    "handshake_auth_duration_ms=120 result=success" \
    "handshake_auth_duration_ms=5000 result=failure"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
MONITOR_LOG="$COMPLETE_MONITOR_LOG"
summarize_monitor_log
CHECK "complete capture (all 6 checkpoints + success/failure durations) -> PASS" "1" "$PASS_COUNT"
CHECK "complete capture -> no FAIL" "0" "$FAIL_COUNT"

# A one-line, checkpoint-only capture must not PASS.
ONE_LINE_MONITOR_LOG="$WORKDIR/monitor_one_line.log"
write_monitor_log "$ONE_LINE_MONITOR_LOG" "$(checkpoint_line before_ssh_init)"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
MONITOR_LOG="$ONE_LINE_MONITOR_LOG"
summarize_monitor_log
CHECK "one-line checkpoint-only capture -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "one-line checkpoint-only capture -> recorded as FAIL" "1" "$FAIL_COUNT"

# A capture missing exactly one required lifecycle category (here,
# after_disconnect) must still FAIL, one category at a time.
for missing_cp in before_ssh_init after_listener_init before_handshake \
        after_auth after_failed_handshake after_disconnect; do
    MISSING_ONE_LOG="$WORKDIR/monitor_missing_${missing_cp}.log"
    lines=()
    for cp in before_ssh_init after_listener_init before_handshake \
            after_auth after_failed_handshake after_disconnect; do
        [[ "$cp" == "$missing_cp" ]] && continue
        lines+=("$(checkpoint_line "$cp")")
    done
    lines+=("handshake_auth_duration_ms=120 result=success")
    lines+=("handshake_auth_duration_ms=5000 result=failure")
    write_monitor_log "$MISSING_ONE_LOG" "${lines[@]}"

    PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
    MONITOR_LOG="$MISSING_ONE_LOG"
    summarize_monitor_log
    CHECK "capture missing only '$missing_cp' -> NOT recorded as PASS" "0" "$PASS_COUNT"
    CHECK "capture missing only '$missing_cp' -> recorded as FAIL" "1" "$FAIL_COUNT"
done

# A capture with all six checkpoints but only a success (no failure)
# duration line must FAIL, and vice versa.
MISSING_FAILURE_LOG="$WORKDIR/monitor_missing_failure_duration.log"
write_monitor_log "$MISSING_FAILURE_LOG" \
    "$(checkpoint_line before_ssh_init)" \
    "$(checkpoint_line after_listener_init)" \
    "$(checkpoint_line before_handshake)" \
    "$(checkpoint_line after_auth)" \
    "$(checkpoint_line after_failed_handshake)" \
    "$(checkpoint_line after_disconnect)" \
    "handshake_auth_duration_ms=120 result=success"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
MONITOR_LOG="$MISSING_FAILURE_LOG"
summarize_monitor_log
CHECK "capture with only a success duration (no failure) -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "capture with only a success duration (no failure) -> recorded as FAIL" "1" "$FAIL_COUNT"

MISSING_SUCCESS_LOG="$WORKDIR/monitor_missing_success_duration.log"
write_monitor_log "$MISSING_SUCCESS_LOG" \
    "$(checkpoint_line before_ssh_init)" \
    "$(checkpoint_line after_listener_init)" \
    "$(checkpoint_line before_handshake)" \
    "$(checkpoint_line after_auth)" \
    "$(checkpoint_line after_failed_handshake)" \
    "$(checkpoint_line after_disconnect)" \
    "handshake_auth_duration_ms=5000 result=failure"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
MONITOR_LOG="$MISSING_SUCCESS_LOG"
summarize_monitor_log
CHECK "capture with only a failure duration (no success) -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "capture with only a failure duration (no success) -> recorded as FAIL" "1" "$FAIL_COUNT"

# Malformed metric lines (missing fields) must not satisfy a required
# category, even though the checkpoint name and "result=" text appear.
MALFORMED_LOG="$WORKDIR/monitor_malformed.log"
write_monitor_log "$MALFORMED_LOG" \
    "checkpoint=before_ssh_init free_heap=100000" \
    "checkpoint=after_listener_init free_heap=100000 min_free_heap_since_boot=90000" \
    "$(checkpoint_line before_handshake)" \
    "$(checkpoint_line after_auth)" \
    "$(checkpoint_line after_failed_handshake)" \
    "$(checkpoint_line after_disconnect)" \
    "handshake_auth_duration_ms=oops result=success" \
    "handshake_auth_duration_ms=5000 result=failure"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
MONITOR_LOG="$MALFORMED_LOG"
summarize_monitor_log
CHECK "malformed checkpoint/duration lines do not satisfy their category -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "malformed checkpoint/duration lines do not satisfy their category -> recorded as FAIL" "1" "$FAIL_COUNT"

# Omitting --monitor-log remains an optional SKIP, not a FAIL.
PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
MONITOR_LOG=""
summarize_monitor_log
CHECK "omitted --monitor-log -> no PASS" "0" "$PASS_COUNT"
CHECK "omitted --monitor-log -> no FAIL" "0" "$FAIL_COUNT"
CHECK "omitted --monitor-log -> exactly one (optional) skip" "1" "$SKIP_COUNT"

# A supplied but nonexistent path remains a FAIL, unchanged.
PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
MONITOR_LOG="$WORKDIR/this_monitor_log_does_not_exist.log"
summarize_monitor_log
CHECK "nonexistent --monitor-log path -> no PASS" "0" "$PASS_COUNT"
CHECK "nonexistent --monitor-log path -> recorded as FAIL" "1" "$FAIL_COUNT"

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
echo 'channel 0: open failed: unknown channel type: Channel type not supported.'
exit 255
FAKE_SSH_FWD_EOF
chmod +x "$FAKE_BIN/ssh"

PATH="$FAKE_BIN:$PATH" test_forwarding_rejected

if grep -q -- "-W" "$WORKDIR/ssh_argv_capture.txt"; then r=0; else r=1; fi
CHECK_TRUE "forwarding test invokes ssh with -W (a real server-reaching request)" "$r"
if grep -q -- "-L" "$WORKDIR/ssh_argv_capture.txt"; then r=1; else r=0; fi
CHECK_TRUE "forwarding test does NOT use the locally-invalid '-L ...:0...' form" "$r"
CHECK "forwarding test: genuine 'unknown channel type' evidence -> recorded as PASS" "1" "$PASS_COUNT"
CHECK "forwarding test: genuine 'unknown channel type' evidence -> no FAIL recorded" "0" "$FAIL_COUNT"

echo
echo "== deceptive-transcript regressions: generic protocol_rejected must not satisfy request-specific checks =="

# Scenario (a): the board actually ACCEPTED the forwarding channel-open (no
# "channel N: open failed" line at all) but the destination connection then
# failed for an unrelated reason -- classify_ssh_result() still reports
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

# Scenario (a'): the sharpest deceptive case -- a REAL
# SSH_MSG_CHANNEL_OPEN_FAILURE genuinely occurred (the board's forwarding
# target refused the destination connection, "connect failed"), but that is
# not evidence of THIS spike's forwarding policy rejecting the request: with
# WOLFSSH_FWD undefined, this spike's own rejection always carries the
# "unknown channel type" reason (see test_forwarding_rejected()'s comment).
# A naive "any channel N: open failed line" predicate would have wrongly
# passed this.
PASS_COUNT=0
FAIL_COUNT=0
cat > "$FAKE_BIN/ssh" <<'FAKE_SSH_FWD_CONNECTFAILED_EOF'
#!/usr/bin/env bash
echo 'debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.'
echo 'Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".'
echo 'channel 0: open failed: connect failed: Connection refused'
exit 255
FAKE_SSH_FWD_CONNECTFAILED_EOF
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" test_forwarding_rejected
CHECK "forwarding: genuine channel-open failure with the WRONG reason ('connect failed') -> NOT recorded as PASS" "0" "$PASS_COUNT"
CHECK "forwarding: genuine channel-open failure with the WRONG reason ('connect failed') -> recorded as FAIL (inconclusive)" "1" "$FAIL_COUNT"

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
    --firmware-image /this/firmware/path/does/not/exist.bin \
    > "$WORKDIR/out_dryrun.log" 2>&1
rc=$?
set -e
CHECK "dry-run succeeds with a nonexistent identity file, nonexistent firmware image, and an unroutable host" "0" "$rc"

# The experimental --dry-run plan's PTY entry must describe the same
# contract test_pty_rejected() actually enforces: pty-req is acknowledged,
# and it is the *subsequent exec* that must fail -- not "PTY allocation"
# itself. See docs/design/ssh-feasibility-spike.md sections 6-7.
if grep -q "pty-req is acknowledged" "$WORKDIR/out_dryrun.log"; then r=0; else r=1; fi
CHECK_TRUE "experimental dry-run plan states pty-req is acknowledged" "$r"
if grep -q "PTY allocation (-tt) -> expect protocol_rejected" "$WORKDIR/out_dryrun.log"; then r=1; else r=0; fi
CHECK_TRUE "experimental dry-run plan no longer claims 'PTY allocation ... expect protocol_rejected'" "$r"

# Dry-run must explain the firmware-provenance phase without ever reading
# or hashing the (here, nonexistent) --firmware-image path -- succeeding
# above already proves the nonexistent path wasn't required to exist; the
# absence of any error mentioning it, plus the exit-0 CHECK above, is the
# evidence that it was never read.
if grep -q "Record firmware provenance" "$WORKDIR/out_dryrun.log"; then r=0; else r=1; fi
CHECK_TRUE "dry-run plan explains the firmware-provenance phase" "$r"
if grep -q "this firmware path does not exist\|/this/firmware/path/does/not/exist.bin" "$WORKDIR/out_dryrun.log"; then r=1; else r=0; fi
CHECK_TRUE "dry-run never mentions/reads the nonexistent --firmware-image path" "$r"

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
