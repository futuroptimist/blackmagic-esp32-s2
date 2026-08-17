# AGENTS.md

Instructions for coding agents working in this repository.

## What this project is

Firmware for the ESP32-S2 Wi-Fi Board that ships with the Flipper Zero
BlackMagic Probe / DapLink debugger. It is an ESP-IDF (FreeRTOS) application,
**not** a Linux/POSIX system: there is no shell, process model, filesystem,
or package manager on the ESP32-S2 target. `docs/design/ssh-access.md` and
`docs/design/ssh-feasibility-spike.md` explain this distinction in detail
before proposing anything that sounds like "SSH shell."

The repository is a fork of `flipperdevices/blackmagic-esp32-s2` (remote
`upstream`); this fork's own work happens on `personal` (remote `origin`),
not `upstream/dev`.

## License

GPL-3.0 (`LICENSE`, full text). Any new dependency must be license-compatible
with GPLv3 — check this explicitly, don't assume from a project's name or
reputation. `docs/design/ssh-feasibility-spike.md` §5 is a worked example of
how that check was done for wolfSSL/wolfSSH.

## Build

Requires ESP-IDF **v4.4.8** specifically (see below on why that exact
version) and `idf.py` on `PATH`.

```shell
git submodule update --init --recursive
idf.py build
```

Do **not** run `idf.py set-target esp32s2` — it overwrites settings in the
committed `sdkconfig`. The target is already configured.

If ESP-IDF is not installed locally, Docker can run the pinned toolchain:

```shell
docker run --rm -v "$PWD:/project" -w /project espressif/idf:v4.4.8 idf.py build
```

The web configuration UI (`components/svelte-portal`, Svelte) is built
separately: `npm install && npm run build` inside that directory, before
`idf.py build` picks up the built assets.

## The canonical `sdkconfig` is a CI gate

`.github/workflows/build.yml` runs `git diff --exit-code -- sdkconfig` after
building. **Any change that adds/changes a Kconfig option and is meant to be
the new default must be built once and the resulting `sdkconfig` committed**,
or CI fails on unrelated PRs. Do not hand-edit `sdkconfig`; let `idf.py`
regenerate it and diff the result.

If you need an experimental build with different options (e.g. the
`CONFIG_EXPERIMENTAL_WOLFSSH_SERVER` spike), use a separate build directory
and an sdkconfig overlay — never let a non-default configuration get written
back to the tracked root `sdkconfig`.

## Native (non-ESP-IDF) tests

Some pure, dependency-free C logic is tested by compiling and running with
the host compiler, no ESP-IDF toolchain required:

- SSH-spike policy functions in `components/wolfssh_spike/policy.c`:
  ```shell
  scripts/run_policy_tests.sh
  ```
- SSH-spike NVS key-storage blob codec in
  `components/wolfssh_spike/ssh_keystore_codec.c`:
  ```shell
  scripts/run_ssh_keystore_codec_tests.sh
  ```

There is no ESP-IDF-hosted unit test framework (no Unity/cmocka) here. If you
add more pure logic worth testing this way, prefer extending this pattern
over pulling in a new framework.

## Component conventions

Third-party code is vendored as **pinned git submodules** under
`components/<name>/`, wrapped by a thin `CMakeLists.txt` — see `.gitmodules`
for the existing set (`blackmagic-fw`, `mlib`, `tinyusb`, `free-dap`, plus
`wolfssl`/`wolfssh` under `components/wolfssh_spike/`). Always pin to an
exact tag and commit SHA; never track `master`/`main`/a branch.

Existing raw TCP services (`main/network-gdb.c`, `main/network-uart.c`) share
one shape: `xTaskCreate` a single task, `socket()`/`bind()`/`listen(backlog
1)`, blocking `accept()` loop, one connection at a time. Follow this shape
for new listener-style services unless you have a specific reason not to.

## Design docs

- `docs/design/ssh-access.md` — target architecture for SSH access (not yet
  implemented in production form).
- `docs/design/ssh-feasibility-spike.md` — the feasibility spike's decision
  record: dependency choice, evidence, measured results, go/no-go.

Read both before touching anything SSH-related; they encode boundaries
(no shell, no arbitrary command execution, public-key-only auth, fail-closed
on anything unsupported) that are easy to accidentally violate otherwise.

## Issue tracking

GitHub issues on `futuroptimist/blackmagic-esp32-s2`. Issue #10 tracks
pre-existing unauthenticated HTTP management-plane exposure inherited from
upstream — it is deliberately **out of scope** for SSH work; don't fold
HTTP-hardening changes into an SSH PR or vice versa unless explicitly asked.
