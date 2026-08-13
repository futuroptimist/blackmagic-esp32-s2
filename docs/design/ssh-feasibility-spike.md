# wolfSSH Feasibility Spike (ESP32-S2)

**Status:** Experimental feasibility spike. Not production-ready.

This document is a decision record for the "SSH library and supported
algorithms" open item in [`ssh-access.md`](./ssh-access.md#ssh-library-decision).
It complements that design rather than replacing it: `ssh-access.md` describes
the target architecture for production SSH access; this document records the
evidence gathered by building a minimal, disabled-by-default prototype against
that target, and the go/no-go conclusion.

## 1. Status and scope

- This is an experimental feasibility spike, gated behind
  `CONFIG_EXPERIMENTAL_WOLFSSH_SERVER` (default `n`). It is not enabled in any
  shipped configuration.
- SSH terminates on the **ESP32-S2 Wi-Fi board**. It does not provide a Unix
  shell, and it does not automatically provide access to the Flipper Zero MCU
  attached to that board. The Flipper MCU is a separate device reachable only
  through the existing UART byte-bridge paths this repository already has
  (`main/usb-uart.c`, `main/network-uart.c`) — SSH does not change that.
- The prototype authenticates exactly one public key, permits exactly one
  connection at a time, and accepts exactly one exec command (`ping`, which
  replies `pong\n`). Every other SSH capability — shell, subsystems, SFTP,
  SCP, forwarding, agent/X11 forwarding, password/keyboard-interactive auth
  — is explicitly rejected. A PTY allocation request is protocol-acknowledged
  rather than rejected, but grants nothing: no exec/shell request is ever
  serviced through it. See [§7](#7-threat-and-safety-boundaries).

## 2. Questions this spike must answer

1. Can current wolfSSH/wolfSSL build against this repository's exact
   ESP-IDF v4.4.8 toolchain for the ESP32-S2 target? — see [§8](#8-measured-results).
2. Does the experimental build fit in the current 2 MB factory application
   partition with reasonable headroom? — see [§8](#8-measured-results).
3. What are the incremental flash, internal heap, largest free block,
   task-stack, and handshake costs? — see [§8](#8-measured-results) (hardware
   figures marked `Pending hardware measurement`).
4. Does it interoperate with a current macOS OpenSSH client? — **pending
   hardware measurement**, see [§8](#8-measured-results).
5. Can unsupported SSH functionality (shell, PTY, subsystems, forwarding,
   password auth, unknown users/keys/commands) be made to fail closed? — yes,
   by architecture; see [§6](#6-prototype-architecture) and [§7](#7-threat-and-safety-boundaries).
   Behavioral confirmation against a real client is pending hardware.
6. Can repeated connections terminate without leaks, fragmentation, crashes,
   or degradation over many cycles? — **pending hardware measurement**
   (100-cycle soak test), see [§8](#8-measured-results).

## 3. Repository constraints

- **ESP-IDF v4.4.8, EOL.** The ESP-IDF v4.4 release branch reached end-of-life
  in July 2024 ([Espressif EOL advisory, AR2024-008](https://documentation.espressif.com/AR2024-008%20End-of-Life%20Advisory%20for%20ESP-IDF%20v4.4%20Release%20Branch%20EN.html)).
  This repository still pins v4.4.8 in CI (`.github/workflows/build.yml`).
  Upgrading ESP-IDF is explicitly out of scope for this spike (see
  [§11](#11-scope-exclusions)) and is Phase 1 work in the roadmap below.
- **Partition layout.** `partitions.csv` gives the `factory` app partition
  2 MiB (2,097,152 bytes) at offset `0x10000`, immediately followed by a
  100 KiB `nvs_storage` partition with no gap. The current default firmware
  image (`build/blackmagic.bin`) is 965,008 bytes, leaving roughly 1.08 MiB
  (about 54%) of headroom inside the factory slot. Growing the factory
  partition itself (not needed by this spike) would require moving
  `nvs_storage`, since there is no gap to grow into.
- **Existing networking/HTTP/GDB/UART/USB CLI/NVS architecture.** This spike
  reuses established patterns rather than inventing new ones — see
  [§6](#6-prototype-architecture) for exactly which files and idioms it
  follows and which it deliberately does not touch.
- **Canonical tracked `sdkconfig` and CI drift protection.** CI runs
  `git diff --exit-code -- sdkconfig` (`.github/workflows/build.yml:88-89`).
  This spike adds the first project-authored Kconfig option
  (`CONFIG_EXPERIMENTAL_WOLFSSH_SERVER`, default `n`) to the tracked
  `sdkconfig`; the *experimental* CI build uses a separate build directory and
  sdkconfig overlay so it never touches the canonical file.
- **GPL-3.0 repository licensing.** See [§5](#5-dependency-decision).

## 4. Candidate comparison

| Library | License | Server support | Evidence of ESP32-S2/FreeRTOS fit | Verdict |
| --- | --- | --- | --- | --- |
| **wolfSSH + wolfSSL** | Dual GPLv3 / commercial | Yes | Vendored `ide/Espressif/ESP-IDF` examples in the wolfSSH source tree itself, and wolfSSL's own `wolfcrypt/port/Espressif/esp32-crypt.h` explicitly branches on `CONFIG_IDF_TARGET_ESP32S2` with chip-specific hardware-crypto notes (e.g. "no AES192 HW on ESP32-S2; falls back to SW") | **Selected** |
| **CycloneSSH** (Oryx Embedded) | GPLv2 / commercial | Yes | Vendor explicitly lists ESP32 among supported targets | **Documented fallback, not attempted here** (see below) |
| **libssh** | LGPL | Yes | Only known ESP32 port (`LibSSH-ESP32`) is an unofficial third-party Arduino-library fork; ESP32-S2 support only added June 2024, provenance and ESP-IDF-native (non-Arduino) fit unconfirmed | Rejected: provenance/maintenance risk |
| **Dropbear** | Permissive (MIT-style) | Yes | Architecturally assumes a POSIX fork/exec process model and Unix multi-user accounts; no evidence of bare-FreeRTOS portability | Rejected: architectural mismatch |
| **TinySSH** | ISC-style | Yes | No evidence of any ESP32/FreeRTOS port; built around Unix primitives (libtomcrypt/nacl file-descriptor model) | Rejected: no portability evidence |
| **libssh2** | BSD | **No** (client only) | N/A | Rejected: no server support at all |

**Why wolfSSH:** it is the only candidate with (a) a GPLv3 track directly
compatible with this repository's license, (b) an actively maintained CVE
disclosure/patch history (see [§5](#5-dependency-decision)), and (c) an
official example — bundled directly in the pinned source tree at
`components/wolfssh_spike/wolfssh/ide/Espressif/ESP-IDF/examples/` — with
explicit ESP32-S2 hardware-crypto handling, not merely "should work on
Xtensa" speculation.

**Why CycloneSSH is the fallback, not part of this spike:** it also
explicitly lists ESP32 support, but its open-source track is GPLv2 (not
"GPLv2-or-later"), and combining GPLv2-only code into this GPLv3 project is a
distinct legal question from the GPLv3-vs-GPLv3 compatibility that applies to
wolfSSH — it needs its own review before any code is written, not a decision
made inside this spike. It is also distributed through a vendor download
portal rather than a plainly pinnable git tag, which weakens the reproducible-
submodule provenance this repository's `.gitmodules` convention depends on.
If wolfSSH had turned out to be a no-go, CycloneSSH would be the next
candidate for a dedicated spike — but that is future work, not this PR.

## 5. Dependency decision

| Component | Repository | Tag | Commit SHA | License |
| --- | --- | --- | --- | --- |
| wolfSSL | `github.com/wolfSSL/wolfssl` | `v5.9.2-stable` | `ac01707f552c611fbd135cc723b2682b3e7f80f2` | GPLv3 (commercial alternative available) |
| wolfSSH | `github.com/wolfSSL/wolfssh` | `v1.5.0-stable` | `8643d7be841184f766374e3b0ed68ced6391543c` | GPLv3 (commercial alternative available) |

Both were the latest stable releases as of 2026-08-12 (verified against each
project's GitHub Releases page). Both submodules' `LICENSING`/`COPYING` files
were read directly after checkout and confirm the GPLv3 track (wolfSSL's
`COPYING` also lists a small set of named third-party projects — MariaDB
Server, MariaDB Client Libraries, OpenVPN-NL, Fetchmail, OpenVPN, SWUpdate,
RPCS3, VDE — that may instead combine it under GPLv2; none of those apply
here, so the GPLv3 track governs). This repository is GPL-3.0
(`LICENSE`), so no license conflict exists.

They are added as git submodules pinned to the exact tag/SHA above
(`components/wolfssh_spike/wolfssl`, `components/wolfssh_spike/wolfssh`),
following this repository's existing submodule convention
(`.gitmodules` already tracks `blackmagic-fw`, `mlib`, `tinyusb`, `free-dap`
the same way). Nothing is vendored from `master` or any unpinned branch.

**Why Espressif Component Registry `wolfssl/wolfssh` 1.4.20 is rejected:**

- wolfSSH v1.4.22 (released 2026-01-05) fixed **CVE-2025-14942** (critical):
  the key-exchange state machine could be manipulated to leak a client's
  password in the clear, trick a client into sending a bogus signature, or
  let a server skip user authentication entirely. It affects "1.4.21 and
  earlier" ([wolfSSH v1.4.22 release notes](https://www.wolfssl.com/wolfssh-v1-4-22-release/)).
- The same release also fixed **CVE-2025-15382** (medium): an SCP
  path-cleaning function could read one byte past the end of a string,
  affecting versions 1.4.12 through 1.4.21 inclusive.
- Registry version 1.4.20 falls inside both vulnerable ranges.
- The registry entry is also not a clean, reproducible tagged release — its
  own readme states it includes "post-release changes in PR #770," i.e. an ad
  hoc snapshot rather than something a git tag+SHA can reproduce.

**Dependency update / CVE monitoring going forward:** track wolfSSL's
[security vulnerabilities page](https://www.wolfssl.com/docs/security-vulnerabilities/)
and the GitHub Releases pages for both repositories. Because both are pinned
submodules (not registry packages), updating means bumping the submodule SHA
to a new tagged release and re-running the build/test verification in
[§9](#9-go-no-go-criteria) — the same discipline already implicit in this
repository's other pinned submodules.

## 6. Prototype architecture

**Component boundary.** All new code lives under
`components/wolfssh_spike/` (submodules, `Kconfig`, `CMakeLists.txt`,
`user_settings.h`, `wolfssh_spike.c`/`.h`, `policy.c`/`.h`). It is built as an
ESP-IDF **configuration-only component**: `CMakeLists.txt` branches on
`CONFIG_EXPERIMENTAL_WOLFSSH_SERVER` and calls `idf_component_register()`
with no sources at all when the option is off, so wolfSSH/wolfSSL are not
compiled or linked into the default build — not merely "unused," but absent
from the object list entirely. `main/main.c` gains one `#if
CONFIG_EXPERIMENTAL_WOLFSSH_SERVER` block calling
`wolfssh_spike_start(void)`; no other existing file changes.

wolfSSL/wolfSSH headers and `user_settings.h` are added via
`PRIV_INCLUDE_DIRS`, never public `INCLUDE_DIRS` — their macros and types do
not leak into `main/` or any other component, satisfying "avoid exposing
wolfSSL/wolfSSH configuration macros globally."

**Listener/task lifecycle.** `wolfssh_spike_start()` creates a FreeRTOS
listener task, mirroring the blocking accept-loop shape of
`main/network-gdb.c` and `main/network-uart.c`, with two deliberate
differences:

1. Before creating any socket, the task polls the existing
   `network_get_ip()` accessor (`main/network.h`, already public, already
   used elsewhere) in a `vTaskDelay` loop until the station interface has a
   non-zero IP. No new event group and no change to `main/network.c` — the
   readiness signal that would otherwise require touching shared networking
   code is entirely avoided.
2. Unlike the GDB/UART listeners, the listener starts one separate session
   task for the active client. It therefore keeps accepting while that
   session blocks in wolfSSH and immediately closes any additional accepted
   socket rather than leaving it queued in the TCP backlog. A bare backlog
   of 1 does not itself refuse a second client at the TCP level — the kernel
   will silently queue it — so "a second simultaneous connection fails
   cleanly" requires this explicit accept-and-reject behavior, not just a
   small backlog number.

**Authentication callback.** `wolfSSH_SetUserAuth(ctx, wolfssh_spike_auth_cb)`
registers a callback that:
- Rejects any `authType` other than `WOLFSSH_USERAUTH_PUBLICKEY` immediately
  (`WOLFSSH_USERAUTH_INVALID_AUTHTYPE`) — no password, no keyboard-
  interactive, no `none`. `wolfSSH_SetUserAuthTypes(ctx, ...)` is also used
  at context-setup time to restrict the advertised/accepted auth type list at
  the protocol level, so unsupported methods are rejected before this
  callback even runs, not merely by callback logic alone.
- Checks the username against the fixed value `flipper` using the pure
  function `policy_username_ok()` (`components/wolfssh_spike/policy.c`).
- Checks the presented public key against the single build-time-embedded
  authorized key using `policy_key_matches()`, a constant-time byte compare.
- Returns `WOLFSSH_USERAUTH_INVALID_USER` / `WOLFSSH_USERAUTH_INVALID_PUBLICKEY`
  for any mismatch — never silently falls through.

**Channel-request policy.** Every channel-request callback type wolfSSH
*exposes a callback for* (`shell`, `exec`, `subsystem`, channel-open) is
explicitly registered, not left unset. wolfSSH's own channel-request
dispatcher (`DoChannelRequest()`, pinned `src/internal.c`) additionally
handles a few request types — `env`, `pty-req`, `window-change`,
`exit-status`, `exit-signal`, agent-forwarding — with no corresponding
application callback at all; see the `env`/unknown-request bullet in
[§7](#7-threat-and-safety-boundaries) for exactly what that means and
does not mean.
- `wolfSSH_CTX_SetChannelOpenCb` — allow only a `session` channel type; a
  `direct-tcpip`/forwarded-channel open request is rejected here before any
  request callback runs (this is also how forwarding is refused even though
  `WOLFSSH_FWD` is compiled out — belt and suspenders). Also refuses a
  second channel on a connection that already opened one.
- `wolfSSH_CTX_SetChannelReqExecCb` — the only interesting callback.
  First claims a per-connection one-shot flag
  (`policy_claim_exec_once()`) before doing anything else; a second exec
  request on the same channel is rejected immediately by that claim,
  regardless of whether the first request succeeded, was rejected, or
  failed to send. Only once the claim succeeds does it compare the
  requested command against the exact string `ping` via
  `policy_command_allowed()`; on match, writes `pong\n` with
  `wolfSSH_ChannelSend()`, sets a success exit status with
  `wolfSSH_SetExitStatus()`, and lets the channel close. Any other command
  string is rejected (nonzero return, no shell fallback, no argument
  parsing/expansion of any kind).
- `wolfSSH_CTX_SetChannelReqShellCb` and `wolfSSH_CTX_SetChannelReqSubsysCb`
  — both registered as unconditional-reject callbacks. Neither a `shell`
  channel request nor any named subsystem (which would include a hypothetical
  `sftp` subsystem) succeeds.
- A `pty-req` is protocol-acknowledged, not rejected: it is one of the
  request types with no application callback described above, so it falls
  through wolfSSH's dispatcher the same way an `env` request does — logged,
  never stored, acknowledged to the client as successful. That
  acknowledgment grants nothing on its own; the actual boundary is one level
  later, at the exec callback: `wolfSSH_ChannelIsPty()` rejects any exec
  request made on a PTY-allocated channel (`channel_req_exec_cb()`,
  `components/wolfssh_spike/wolfssh_spike.c`), so no command — supported or
  not — is ever serviced through an allocated PTY.

**Build-time key injection.** Two external inputs are required when the
feature is enabled, both supplied out-of-tree:
- `WOLFSSH_SPIKE_HOST_KEY_PATH` — an ECDSA P-256 host private key.
- `WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH` — the single ECDSA P-256 authorized
  public key.

`components/wolfssh_spike/CMakeLists.txt` reads these as environment
variables and embeds their contents into the firmware image via
`idf_component_register(... EMBED_FILES ...)` (ESP-IDF's built-in
binary-embedding mechanism — no key material is ever copied into the source
tree). If the feature is enabled and either variable is unset, CMake raises
`message(FATAL_ERROR ...)` and the build stops before compiling anything.
`scripts/gen_ssh_spike_keys.sh` generates disposable developer keys into a
caller-supplied or `mktemp` directory outside the repository.

**Buffer/window limits.** `wolfSSH_CTX_SetWindowPacketSize(ctx, windowSz,
packetSz)` is set to a small, explicit value derived from the wolfSSH
Espressif example's own guidance (`DEFAULT_WINDOW_SZ 2000` in the bundled
`ide/Espressif/ESP-IDF/examples/wolfssh_echoserver` `user_settings.h`), then
measured against actual handshake/throughput behavior once hardware is
available (see [§8](#8-measured-results)).

**Connection and timeout limits.** One session/channel at a time (see
listener lifecycle above). `SO_RCVTIMEO`/`SO_SNDTIMEO` are set on the
accepted socket, and `wolfSSH_accept()` is driven in a bounded retry loop
with a wall-clock deadline (it can legitimately return "want read" mid-
handshake and must be called again) so a stalled handshake cannot hang the
task forever. A separate idle deadline applies after authentication succeeds
if no data is exchanged.

**ESP-IDF v4.4.8 compatibility shim.** wolfSSL's `WOLFSSL_ESPIDF` default
block (`wolfcrypt/settings.h`) unconditionally defines `FREERTOS`, which
later triggers a bare `#include "FreeRTOS.h"` / `#include <task.h>` — the
upstream-FreeRTOS header names, not ESP-IDF v4.4's namespaced
`freertos/FreeRTOS.h` / `freertos/task.h` used everywhere else in this
repository. `components/wolfssh_spike/freertos_shim/{FreeRTOS.h,task.h}`
are two one-line compatibility headers (`#include <freertos/FreeRTOS.h>`
and `#include <freertos/task.h>` respectively) added to this component's
private include path to bridge that naming mismatch, without disabling any
of wolfSSL's other ESP-IDF defaults (timing-resistant math, lwIP
integration, etc.) by defining `NO_ESPIDF_DEFAULT` ourselves. This is
exactly the kind of small, isolated, reviewable compatibility patch the
original task brief anticipated might be necessary for ESP-IDF v4.4.8 —
confirmed necessary and applied during this spike's real Docker build
verification (see section 8).

**Cleanup behavior.** On any exit path (successful `ping`, rejected request,
timeout, or socket error) the task calls `wolfSSH_shutdown()`,
`wolfSSH_free()`, closes the socket, and logs resource checkpoints (see
[§8](#8-measured-results)) before returning to `accept()` for the next
connection. No key material or authentication secrets are ever logged.

**Data flow for the one supported command:**

```
client                          ESP32-S2 (wolfssh_spike task)
  |  TCP connect :2222                |
  |----------------------------------->|  accept() (only if idle; else close)
  |  SSH handshake (ECDH P-256,       |
  |  host key verify)                 |
  |<---------------------------------->|  wolfSSH_accept() loop, bounded deadline
  |  publickey auth (flipper, key)    |
  |----------------------------------->|  auth callback: policy_username_ok() +
  |                                    |    policy_key_matches()
  |  channel open (session)           |
  |----------------------------------->|  channel-open callback: allow "session"
  |  exec "ping"                      |
  |----------------------------------->|  exec callback: policy_command_allowed()
  |                                    |
  |<-----------------------------------|  "pong\n" via wolfSSH_stream_send()
  |<-----------------------------------|  exit-status success
  |  channel/connection close         |
  |<----------------------------------->|  wolfSSH_shutdown/free, socket close
```

## 7. Threat and safety boundaries

- **Public-key authentication only.** No password, keyboard-interactive, or
  `none` authentication path succeeds; `wolfSSH_SetUserAuthTypes` restricts
  the advertised methods and the auth callback independently re-checks
  `authType`.
- **No interactive shell, and nothing runs through a PTY.** The
  shell-request callback always rejects. A `pty-req` itself is
  protocol-acknowledged (the pinned wolfSSH has no pty-req rejection
  callback to hook — see [§6](#6-prototype-architecture)), but that grants
  nothing: the exec callback's `wolfSSH_ChannelIsPty()` check refuses any
  exec request on a PTY-allocated channel, so no interactive session and no
  command of any kind is ever serviced through it.
- **No arbitrary command parser.** The exec callback does an exact string
  comparison against `ping` — no argument parsing, no shell invocation, no
  environment/command substitution of any kind.
- **At most one exec request per connection.** The pinned wolfSSH
  `DoChannelRequest()` (`src/internal.c`) invokes `channelReqExecCb` for
  *every* `"exec"` channel request on an open channel — there is no
  built-in limit, so without additional state a client could send `exec
  ping`, get `pong`, and then send a second `exec ping` (or any other
  command) on the same channel. This spike enforces "exactly one" itself:
  `channel_req_exec_cb()` claims a per-connection one-shot flag
  (`policy_claim_exec_once()`, `components/wolfssh_spike/policy.c`, unit
  tested) *before* any command validation or output, so a second exec
  request fails closed even if the first one was rejected (invalid
  command) or failed partway (send error).
- **No SCP, SFTP, forwarding, X11, agent forwarding, or arbitrary
  subsystems.** SCP/SFTP/agent/forwarding source files (`wolfscp.c`,
  `wolfsftp.c`, `agent.c`) are excluded from the component's source list
  entirely and their enabling macros (`WOLFSSH_SCP`, `WOLFSSH_SFTP`,
  `WOLFSSH_AGENT`, `WOLFSSH_FWD`) are never defined — this is a compile-time
  guarantee, not just a runtime callback decision. The subsystem-request
  callback additionally rejects unconditionally at runtime as defense in
  depth.
- **One connection and one channel at a time.** Enforced by the
  accept-and-reject listener behavior described in
  [§6](#6-prototype-architecture); the channel-open callback additionally
  refuses a second channel on an already-active session.
- **Explicit rejection callbacks for every request type wolfSSH exposes a
  callback for.** `shell`, `exec`, `subsystem`, and channel-open are all
  registered with a real handler; none rely on "no callback set" as an
  implicit rejection.
- **`env` and unknown channel-request types are not application-visible,
  and are not "explicitly rejected."** This is a narrower claim than the
  bullet above on purpose. The pinned wolfSSH `DoChannelRequest()`
  (`src/internal.c`) does not expose a callback for either case: an `env`
  request is parsed, its name/value logged at debug level, and then
  discarded — the value is never stored anywhere this spike's code can
  read, so it cannot influence which command runs or anything else. A
  channel-request type matching none of wolfSSH's known types (not
  `shell`/`exec`/`subsystem`/`pty-req`/`window-change`/`exit-status`/
  `exit-signal`/agent-forwarding) falls through the same dispatcher with
  no effect at all — no state changes, no callback fires. Both cases are
  acknowledged back to the client as if successful (wolfSSH's dispatcher
  sends `SendChannelSuccess` whenever no callback rejected the request),
  which is a wolfSSH library behavior this spike does not alter — patching
  or forking the pinned wolfSSH source to change that reply semantics is
  explicitly out of scope for this feasibility spike. The practical
  consequence is: `env` and unknown requests — and `pty-req`, which the
  dispatcher handles the same way — are harmless no-ops, not
  attacker-controlled behavior, but they are not "rejected" in the same
  sense as `shell`/second-exec/unsupported-command, which this spike's own
  callbacks actively refuse. (A PTY-allocated channel is still denied
  everything that matters: the exec callback refuses to service any command
  on it — see [§6](#6-prototype-architecture).)
- **Station-mode/private-network use only.** The listener binds `INADDR_ANY`
  on the station interface's network the same way the existing GDB/UART
  listeners do; nothing in this spike exposes SSH differently than those
  already-shipped services, and there is no NAT/port-forward guidance
  associated with this feature.
- **Bounded handshake, authentication, idle, and I/O timeouts.** See
  [§6](#6-prototype-architecture) "Connection and timeout limits."
- **No private keys or credentials in Git.** Host and authorized keys are
  supplied via environment-variable paths at build time and embedded
  directly into the firmware binary; `scripts/gen_ssh_spike_keys.sh` writes
  disposable developer keys outside the repository only.
- **No sensitive key material in logs.** Resource-checkpoint logging records
  sizes and counts only (heap bytes, stack watermark, timing), never key
  bytes, fingerprints-as-secrets, or raw authentication data.

## 8. Measured results

| Metric | Value | Source |
| --- | --- | --- |
| Default build size (SSH disabled) | 965,008 bytes (baseline, pre-existing) | `build/blackmagic.bin`, read before this spike's changes |
| Default build size after this spike's changes | 964,432 bytes (54% of factory partition free) | Local `idf.py build` (ESP-IDF v4.4.8 Docker image), unchanged apart from normal version-string/build-date drift; zero wolfSSH/wolfSSL objects in the build tree |
| Experimental build size (SSH enabled) | 1,060,784 bytes / `0x102fb0` (49% of factory partition free, 1,036,368 bytes headroom) | Local `idf.py build` with `CONFIG_EXPERIMENTAL_WOLFSSH_SERVER=y`, separate build dir + sdkconfig overlay, ephemeral developer keys |
| Flash delta (experimental vs. default) | +96,352 bytes (~94 KiB) | Difference between the two rows above |
| `libwolfssh_spike.a` size (wolfCrypt + wolfSSH + this spike's own code + embedded keys) | 94,704 bytes (82,127 text + 12,577 rodata + 25 data) | `idf.py size-components` on the experimental build |
| Internal heap before SSH init | Pending hardware measurement | `esp_get_free_heap_size()` at the `before_ssh_init` checkpoint, which fires before `wolfSSH_Init()` or any wolfSSH allocation |
| Heap after listener initialization | Pending hardware measurement | `esp_get_free_heap_size()` at the `after_listener_init` checkpoint |
| Heap after handshake/authentication (success or failure) | Pending hardware measurement | `esp_get_free_heap_size()` at the `after_auth` / `after_failed_handshake` checkpoints |
| Heap after disconnect | Pending hardware measurement | `esp_get_free_heap_size()` at the `after_disconnect` checkpoint |
| Minimum free heap observed since boot, sampled at each checkpoint above | Pending hardware measurement | `esp_get_minimum_free_heap_size()` — a running low-water-mark over the device's whole uptime, not a delta isolated to the interval since the previous checkpoint; logged as `min_free_heap_since_boot` alongside every checkpoint |
| Largest free internal block, sampled at each checkpoint above | Pending hardware measurement | `heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)` |
| Task stack high-water mark, sampled at each checkpoint above | Pending hardware measurement | `uxTaskGetStackHighWaterMark()` |
| Handshake+authentication duration, logged on both success and failure | Pending hardware measurement | FreeRTOS tick-count delta around the complete `wolfSSH_accept()` retry loop, logged as `handshake_auth_duration_ms` |
| Repeated successful/failed connection behavior (target 100 cycles) | Pending hardware measurement | `scripts/run_ssh_spike_hardware_validation.sh --mode experimental ... --cycles 100`, soak phase |
| macOS OpenSSH interoperability, algorithm negotiation, and every fail-closed rejection case | Pending hardware measurement | same script, non-soak phases (see "Hardware validation procedure" below) |

Checkpoint labels, in the order they can fire, and their exact code
position: `before_ssh_init` (start of `wolfssh_spike_start()`, before
`wolfSSH_Init()`) → `after_listener_init` (after `bind()`/`listen()`
succeed) → `before_handshake` (right after `wolfSSH_set_fd()`, per
connection) → `after_auth` or `after_failed_handshake` (immediately after
the `wolfSSH_accept()` loop exits, whichever outcome) → `after_disconnect`
(after `wolfSSH_shutdown()`/`wolfSSH_free()`/`close()`). All five, plus
`handshake_auth_duration_ms`, are `ESP_LOGI` lines emitted by
`wolfssh_spike.c`; reading them off the device's serial console is exactly
how the pending hardware measurements above get filled in.

No physical Flipper Zero Wi-Fi Board is available in the environment that
produced this spike. Every figure above that requires hardware is marked
`Pending hardware measurement` rather than estimated or fabricated. The PR
associated with this document is out of draft for maintainer review of the
design and implementation, but it is not go for production, and it is not
yet fully "go" for the spike itself, until an operator runs the checklist
in the PR description on real hardware and records the results here in
place of the `Pending hardware measurement` placeholders. Build-size
figures above were measured locally against the pinned
`espressif/idf:v4.4.8` Docker image; ccache state, host OS, and Docker
version can shift object layout by a handful of bytes between runs on
different machines, so treat them as representative rather than bit-for-bit
invariant across every environment.

### Hardware validation procedure

`scripts/run_ssh_spike_hardware_validation.sh` is a host-side, fail-closed
runner that drives a real board with the standard OpenSSH client and common
Unix tools (`ssh`, `ssh-keygen`, `ssh-keyscan`; `nc` and `curl` if present).
It does not flash the board or capture the serial console itself — those
remain separate manual steps below — and it never embeds, copies, or prints
private-key material; the developer identity file is only ever passed by
path to `ssh -i`. Run `--help` for the full flag reference, or `--dry-run`
to see the exact planned phase order and validate arguments with no
network, hardware, or real key files touched at all. The runner's own
classification logic (telling genuine protocol/auth rejection apart from
an unreachable board, a timeout, or a local argument error) is covered by
`scripts/test_ssh_spike_hardware_validation.sh`, a CI-run regression suite
against canned transcripts and PATH-injected fake tools — no real network
or board involved there either.

**Prerequisites** (all manual, not automated by the script):
1. A Flipper Zero Wi-Fi Board reachable over the operator's local network,
   with its IP address or `.local` hostname known.
2. `scripts/gen_ssh_spike_keys.sh` run to produce a host key and an
   authorized developer key pair, and the experimental firmware built and
   flashed with `WOLFSSH_SPIKE_HOST_KEY_PATH`/
   `WOLFSSH_SPIKE_AUTHORIZED_KEY_PATH` pointed at them (see AGENTS.md and
   [§6](#6-prototype-architecture)).
3. The expected host-key fingerprint, computed once locally right after key
   generation: `ssh-keygen -lf <embedded_host_key.pem-derived public key>`
   (or read it back from the device's own serial log at boot, if the
   firmware ever logs it — check before assuming). This value is what
   `--host-key-fingerprint` pins against; the script refuses to proceed at
   all if the board's actual host key doesn't match it, rather than
   trust-on-first-use blindly accepting whatever key the board presents.
4. Optionally, a serial monitor capture (`idf.py monitor` output redirected
   to a file, or any equivalent capture) taken while the script's
   experimental-mode phases run, to pass as `--monitor-log` afterward.

**Invocation order:**
```console
# 1. With the DEFAULT (SSH-disabled) firmware flashed:
scripts/run_ssh_spike_hardware_validation.sh --mode default --host flipper.local

# 2. Flash the EXPERIMENTAL firmware, then:
scripts/run_ssh_spike_hardware_validation.sh --mode experimental \
    --host flipper.local --user flipper \
    --identity <path to the developer private key from gen_ssh_spike_keys.sh> \
    --host-key-fingerprint <fingerprint from prerequisite 3> \
    --cycles 100 \
    --monitor-log <path to a serial capture taken during this run, if available> \
    --evidence-dir <a directory to keep the transcripts/summaries in>
```

**Pass/fail interpretation:** the script prints a `PASS`/`FAIL`/`SKIP` line
per check and a final `SUMMARY: pass=N fail=N skip=N required_skip=N` line.
It exits non-zero if `fail>0`, and also if `required_skip>0` (a
prerequisite tool for a check the script's contract says it performs was
missing) unless `--allow-incomplete-evidence` was explicitly given — a
required check being skipped is incomplete evidence, not a clean pass, and
the script refuses to let that silently satisfy the merge gate. Optional
skips (`--skip-coexistence`, `--cycles 0`, no `--monitor-log`) do not count
as required and never block the exit status. Any `FAIL` is a real go/no-go
blocker for this spike (see [§9](#9-go-no-go-criteria)) and should stop
before promoting past this draft-review state, not just get noted and
ignored.

Every negative check classifies the underlying `ssh -v` transcript rather
than treating "non-zero exit" as proof of rejection — an unreachable board,
a DNS failure, a stale host key, a bad local `ssh` argument, and a timeout
are all non-zero exits that are *not* evidence the board rejected anything,
and the classifier (`classify_ssh_result()`, unit tested in
`scripts/test_ssh_spike_hardware_validation.sh`) distinguishes all of them
from genuine `auth_rejected`/`protocol_rejected` outcomes before a check is
allowed to PASS.

What each mode's phases map back to in this document and in
[§7](#7-threat-and-safety-boundaries):
- `--mode default`: first confirms the board is reachable and identifiable
  at all (via HTTP `/api/v1/system/ping`) — an offline/unreachable board
  must never be reported as "SSH correctly disabled" — then confirms port
  2222 is not exposed.
- `--mode experimental`: host-key fingerprint pinning; `ping` → exact
  `pong` + exit 0; negotiated kex/host-key/cipher algorithms match the
  restricted P-256/AES-256-GCM profile; unrecognized key, unknown username,
  and password/keyboard-interactive auth are all confirmed `auth_rejected`
  with the server's advertised auth-method continuation list independently
  confirmed to exclude password/keyboard-interactive; unsupported exec
  command, shell request, and subsystem request are each confirmed rejected
  by OpenSSH's own request-specific `<type> request failed on channel`
  evidence for a genuine `SSH_MSG_CHANNEL_FAILURE` (not merely
  `protocol_rejected`'s coarser "authenticated, then some non-zero exit"),
  so a request the board actually serviced but which merely exited non-zero
  cannot be mistaken for a refusal; a PTY-requested exec is confirmed the
  same way — the pty-req itself is protocol-acknowledged (see
  [§7](#7-threat-and-safety-boundaries)), so the evidence required is the
  subsequent `exec request failed on channel` line plus the absence of
  `pong`, not a (nonexistent) PTY-allocation refusal; TCP forwarding is
  probed with `ssh -W` (a real direct-tcpip channel-open request the server
  must answer) and requires the corresponding `channel N: open failed`
  `SSH_MSG_CHANNEL_OPEN_FAILURE` evidence, so a forwarding request the board
  accepted but whose destination connection later failed for an unrelated
  reason cannot be mistaken for a rejected request, rather than a
  `-L ...:0...` specification, which OpenSSH rejects locally before ever
  contacting the board and would prove nothing; a second simultaneous
  connection is only attempted after independently confirming (via `nc -v`)
  that the held first connection actually connected, and is then required
  to fail as `transport_failure`/`protocol_rejected`/`auth_rejected` (the
  board's accept-then-immediately-close design looks like an early close,
  not a post-auth refusal, from the client's point of view) before a
  subsequent reconnect is checked to succeed; best-effort HTTP/GDB/UART
  coexistence reachability probes; a configurable soak phase (default 100
  cycles) requiring every successful-ping leg to classify as `success` and
  every wrong-key leg to classify as `auth_rejected`; and, if
  `--monitor-log` was given, an extracted summary of the
  checkpoint/heap/handshake-duration `ESP_LOGI` lines described above.

**Manual-only phases**, not automated by this script, still required before
marking [§9](#9-go-no-go-criteria)'s hardware-dependent items complete:
- Flashing the default and experimental firmware images themselves.
- Capturing the serial console (for `--monitor-log` and for confirming the
  `ESP_LOGI` checkpoint lines actually appear as expected).
- Exercising the HTTP landing page and `/config` Svelte UI interactively in
  a browser, and confirming existing Blackmagic/GDB debugging and USB CLI
  behavior, beyond this script's bare TCP-reachability probes for those
  services.
- Simulating Wi-Fi loss and recovery (e.g. disabling the AP briefly) and
  confirming the SSH task neither wedges nor leaks across the outage.

**Evidence fields maintainers must record** (in this table, replacing the
`Pending hardware measurement` placeholders, and/or by attaching the
script's `--evidence-dir` output to the PR): the script's final
pass/fail/skip summary and exit code; per-check transcripts for any `FAIL`;
the `soak_summary.txt` cycle counts; and, from `--monitor-log`, the actual
numeric heap/largest-free-block/stack-watermark/handshake-duration values
pulled from the device's own `ESP_LOGI` output — the script summarizes and
locates these lines for convenience, but the numbers themselves come from
the board, not from this script's own observation.

## 9. Go/no-go criteria

- [x] Default build and behavior remain unchanged (verified: 964,432-byte
      image, zero wolfSSH/wolfSSL objects anywhere in the default build
      tree; source-level behavior unchanged since main.c's only change is
      inside `#if CONFIG_EXPERIMENTAL_WOLFSSH_SERVER`, default `n`).
- [x] Experimental build fits the application partition with documented
      headroom (verified: 1,060,784 bytes, 49% of the 2 MB factory
      partition free).
- [x] No credentials or private keys are committed anywhere in the PR
      (verified: `scripts/gen_ssh_spike_keys.sh` writes only outside the
      repository; local build verification used keys generated to a
      directory outside the repo, never staged; `git status` confirms no
      key-bearing files are tracked).
- [ ] Current macOS OpenSSH can authenticate and execute the supported
      `ping` command. **Pending hardware measurement** — run
      `scripts/run_ssh_spike_hardware_validation.sh --mode experimental`
      (see "Hardware validation procedure" above) and record its
      `ping_success`/`algorithms` results here.
- [ ] Unsupported functionality (shell, PTY, subsystems, forwarding,
      password auth, unknown user/key/command, second connection) fails
      closed. **Pending hardware measurement for behavioral confirmation**
      via the same script's rejection-case checks; architecturally
      guaranteed per [§7](#7-threat-and-safety-boundaries).
- [ ] Existing HTTP/`/config`/GDB/UART/USB CLI/mDNS services still work
      with the experimental build flashed. **Pending hardware
      measurement** — the script's coexistence probes cover bare
      HTTP/GDB/UART TCP reachability only; the Svelte `/config` UI, USB
      CLI, and Blackmagic debugging still need the manual phases described
      above.
- [ ] No obvious leak or degradation during repeated connection cycles.
      **Pending hardware measurement** — run the same script's soak phase
      (`--cycles 100`) paired with `--monitor-log` from a serial capture
      taken over the same run, and record the resulting heap/stack
      trend here.
- [x] Production remains explicitly no-go until the Phase 1+ items below
      (key lifecycle, enrollment, hardening, ESP-IDF support) are addressed.

This spike's own go/no-go conclusion is recorded in the associated PR once
local (non-hardware) build/test verification completes, and is either
**GO** (proceed to hardware verification, still Phase 0), **CONDITIONAL GO**
(builds and passes local tests, hardware verification outstanding), or
**NO-GO** (a build/security/license blocker was hit; see
[§12](#12-decision-and-failure-handling) for the fallback path if so).

## 10. Phased roadmap

### Phase 0 — Feasibility spike (this PR)

Build, interop, policy, and resource proof for a disabled-by-default,
single-key, single-command SSH prototype. No production deployment.

### Phase 1 — Supported platform and cryptographic foundation

- Upgrade ESP-IDF from EOL v4.4, or document a credible, time-bounded
  security-maintenance/backport policy for staying on it.
- Per-device host-key generation on first boot (ESP-IDF hardware RNG),
  replacing this spike's build-time-injected fixed host key.
- Persistent host key and authorized-key storage in NVS, following the
  existing `main/nvs.c`/`main/nvs-config.c` string-key pattern but with a
  **versioned schema** (this spike introduces no schema — production needs
  one), atomic updates, validation, and recovery on corruption.
- Stable host fingerprint across ordinary reboots.
- Key revocation, replacement, and factory-reset behavior (factory reset
  must rotate the host key and clear authorized keys, per `ssh-access.md`).

### Phase 2 — Trusted provisioning and management CLI

- USB/serial-local authorized-key enrollment (the current unauthenticated
  HTTP `/config` UI must not become the trust root for SSH keys — this is
  also why issue #10's HTTP-hardening work matters independently).
- SSH stays disabled until at least one authorized key exists.
- Refactor the existing UART CLI (`main/cli/cli.c`, `main/cli/cli-commands.c`)
  into transport-independent sessions so SSH and UART share one command
  registry instead of this spike's standalone `ping`-only exec handler.
- Start with an allowlisted, read-only remote command set (see the
  remote-command-authorization table already in `ssh-access.md`).
- Add strict exec behavior (still no shell expansion) before ever
  considering an interactive firmware shell over SSH.
- Output limits, cancellation, CRLF behavior, cleanup, and audit logging.

### Phase 3 — Read-only logging subsystem

- Add a bounded `flipper-log` SSH subsystem around the existing
  Flipper-facing UART receive path (`main/usb-uart.c`).
- Backpressure/drop accounting; read-only by construction.
- Evaluate deprecating the unauthenticated raw UART TCP listener on port
  3456 (`main/network-uart.c`) once this exists.

### Phase 4 — Optional Flipper MCU bridge

- A separate protocol/design for interacting with the Flipper Zero MCU
  itself, requiring Flipper-side application or RPC work this repository
  does not currently have.
- This SSH server does not and will not automatically expose "the Flipper
  OS" — any such bridge is new, separately designed surface area.

### Phase 5 — Management UI and production rollout

- Address issue #10 (unauthenticated HTTP management-plane hardening)
  *before* adding SSH provisioning to `/config`.
- `/config` may later show SSH status, host fingerprint, and public-key
  metadata — never host private-key material.
- Add malformed-client tests, fuzzing, rate limiting, soak testing,
  recovery documentation, release monitoring, and a documented security
  update procedure for the pinned wolfSSL/wolfSSH submodules.

## 11. Scope exclusions

This PR does **not** include: production NVS key storage, on-device key
generation, web-based authorized-key provisioning, any fix for issue #10,
full CLI bridging, interactive shell support, the logging subsystem, Flipper
MCU RPC, SCP/SFTP, port forwarding, any Unix-compatibility layer, or an
ESP-IDF upgrade. All of these are described only as future roadmap phases
above.

## 12. Decision and failure handling

If, during local build verification, current safe wolfSSH/wolfSSL releases
turn out not to build on ESP-IDF v4.4.8 without a large fork; if the
dependency cannot be compiled completely out of the default build; if it
cannot fit the partition; if unsupported requests cannot be made to fail
closed; or if license/provenance cannot be established — this section is
updated with the exact evidence, attempted approaches, and exact errors, and
the PR is converted to documentation-only (no prototype code), per the
original task brief's failure-handling instructions. As of this writing, no
such blocker has been hit; see the PR description for the actual local build
outcome.
