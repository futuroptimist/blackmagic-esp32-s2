# CLAUDE.md

See [`AGENTS.md`](./AGENTS.md) first for build commands, license constraints,
and pointers to the design docs — this file only adds detail distilled from
prior exploration of this specific codebase that's worth not re-deriving.

## Things that are easy to assume and wrong

- **There is no Kconfig anywhere in this repo** except what
  `components/wolfssh_spike/Kconfig` introduced. Before this, zero project
  code was Kconfig-gated — every `idf_component_register()` call in every
  component was unconditional, and `main/CMakeLists.txt` compiled a flat,
  unconditional source list. If you're adding another optional feature,
  `components/wolfssh_spike/CMakeLists.txt` is the only in-repo example of
  the "configuration-only component" pattern (real sources when the option
  is on, `idf_component_register()` with nothing when it's off).
- **`main/network.c` has no "network ready" signal.** It defines
  `WIFI_CONNECTED_BIT`/`WIFI_FAIL_BIT` but never sets or waits on them — dead
  code. `network_get_ip()` is the only public, safe way to check station-IP
  status, and it's synchronous/pollable, not event-driven. Don't assume an
  event group exists to wait on; poll instead, or add one deliberately (and
  know you'd be the first).
- **`ping` already exists as a UART CLI command** (`cli_ping()` in
  `main/cli/cli-commands.c`, table-driven via `cli_items[]`). It's unrelated
  to (and not reused by) the SSH spike's own `ping` exec command — the two
  are separate dispatchers by design; see
  `docs/design/ssh-feasibility-spike.md` §6 for why.
- **mbedTLS is already compiled into every build** (WiFi supplicant +
  `esp_http_client` HTTPS option), but no application code in `main/` calls
  it directly — only `esp_http_server`/plain HTTP is used. Adding a second
  crypto stack (wolfSSL) is not code sharing with mbedTLS; it's a second,
  independent stack, and its flash/RAM cost should be measured as such.
- **`CONFIG_SPIRAM=y` but `CONFIG_SPIRAM_USE_MALLOC` is not set.** Plain
  `malloc()` stays on internal SRAM, not PSRAM, unless a call explicitly uses
  `heap_caps_malloc(..., MALLOC_CAP_SPIRAM)`. Don't assume PSRAM is "just
  available" to a library's default allocator.
- **The committed root `sdkconfig` is a CI gate**, not just a config file —
  see AGENTS.md. Never hand-edit it; never let an experimental/non-default
  configuration overwrite it.

## Repo-specific conventions worth following

- New raw TCP listener services should mirror `main/network-gdb.c` /
  `main/network-uart.c`: one FreeRTOS task via `xTaskCreate`, `socket()` +
  `SO_REUSEADDR` + `bind(INADDR_ANY, port)` + `listen()`, blocking `accept()`
  loop, `SO_KEEPALIVE`/`TCP_NODELAY`/`TCP_KEEPIDLE`/`TCP_KEEPINTVL`/
  `TCP_KEEPCNT` for liveness. Neither existing listener has a real recv
  timeout, though — don't assume one to copy; add your own if you need it.
- Third-party libraries are pinned git submodules under `components/<name>/`
  with a thin wrapping `CMakeLists.txt`, never vendored-and-modified source
  and never tracking a floating branch. See `.gitmodules`.
- NVS config uses flat string key/value pairs under one namespace
  (`main/nvs-config.c`, namespace `"config"` on the `"nvs_storage"`
  partition) — there's no versioned schema today. If you add persisted state
  that needs one, you're introducing schema versioning for the first time,
  not following precedent.
