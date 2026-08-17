# ESP-IDF security-maintenance policy

## Context

This firmware is pinned to ESP-IDF v4.4.8 (see `AGENTS.md`,
`.github/workflows/build.yml`, and `README.md`). Per Espressif's own advisory
([AR2024-008](https://documentation.espressif.com/AR2024-008%20End-of-Life%20Advisory%20for%20ESP-IDF%20v4.4%20Release%20Branch%20EN.html)),
**the v4.4 release branch reached End-of-Life in July 2024.** Espressif's
published [support policy](https://github.com/espressif/esp-idf/blob/master/SUPPORT_POLICY.md)
states plainly: "It is our policy to not continue fixing bugs in End of Life
releases" — including security fixes. That means this project has been
running on a branch with **no upstream security support at all since
July 2024** — this document was first written in August 2026, over two
years after that date; compute the current gap from those two dates
rather than from this document's own age.

The existing network-facing surface includes the HTTP server, raw GDB and raw
UART TCP servers started by `main/main.c`, plus the discovery services started
by `main/network.c`. Adding SSH (`components/wolfssh_spike/`) is the first new
network-facing surface governed by `docs/design/ssh-feasibility-spike.md`'s
Phase 1 roadmap, which requires either an ESP-IDF upgrade or a documented,
time-bounded maintenance policy before shipping. Given a full v4.4 → v5.x
migration is a large, separate, high-risk undertaking (toolchain changes and
API breakage across every component: `main/network.c`, `main/network-http.c`,
`components/wolfssh_spike/`, USB/UART code, all of it needing full hardware
re-validation), this document is the latter: the concrete policy for
managing security risk on the current pinned version until that migration
happens.

## Scope

Components actually compiled into either the default build or the
experimental SSH-enabled build, and therefore relevant to CVE tracking:

- Wi-Fi stack (`esp_wifi`, `wpa_supplicant`)
- lwIP (TCP/IP stack)
- `esp_http_server` (actively used by `main/network-http.c` for the
  device's web config UI and HTTP APIs)
- `mdns` (actively used by `main/network.c` for hostname advertisement)
- cJSON (HTTP handlers in `main/network-http.c` parse received request bodies
  with `cJSON_Parse()`)
- mbedTLS (used by NVS encryption support and other ESP-IDF internals)
- NVS / `spi_flash` (persistent storage, including the SSH key material
  added in Phase 1)
- Bootloader / `bootloader_support`
- USB stack (`tinyusb`, `usb`) — network-adjacent attack surface via the
  device's exposed USB interfaces

Components not linked into any build target here (e.g. Bluetooth, Ethernet
PHY drivers for hardware this board doesn't have, most of the `bt`/`openthread`
tree) are explicitly out of scope — tracking their CVEs would be noise.

## Detection

- Manually review Espressif's published security advisories
  ([github.com/espressif/esp-idf/security/advisories](https://github.com/espressif/esp-idf/security/advisories))
  for anything touching an in-scope component.
- Cross-check NVD/CVE feeds for the same component list, since Espressif's
  own advisory feed may lag or omit issues found by third parties in
  vendored code (e.g. lwIP or mbedTLS upstream CVEs that predate
  Espressif's own advisory).
- No automated scanning is wired into this repo's CI today. This is a
  manual process; automating it (e.g. a scheduled workflow diffing the
  advisory feed) is future work, not required by this policy.

## Review cadence

- **Quarterly**: a scheduled manual review of the sources above for any new
  advisory touching an in-scope component since the last review.
- **Ad hoc**: immediately on learning of any publicly disclosed
  critical/high-severity CVE affecting an in-scope component, independent
  of the quarterly cadence.

## Backport mechanism

Because the v4.4 branch is fully EOL, **Espressif will not cut further
v4.4.x point releases** — there is no upstream patch to simply pull in.
A fix cannot live only as a hand-edit to a local or CI-container ESP-IDF
checkout (per `AGENTS.md`, this project builds against ESP-IDF either from
a local install at whatever path the developer chose, or from the
`espressif/idf:v4.4.8` Docker image — both are ephemeral/developer-specific
and neither is version-controlled, so an edit made only there disappears
the moment that checkout or container is recreated, and every other build
silently reverts to stock, unpatched v4.4.8). Concretely, "backport" here
means:

1. Locate the fix in a newer ESP-IDF branch (typically v5.x, where
   Espressif does patch actively-supported branches).
2. Save it as a diff under a repository-tracked `patches/esp-idf/`
   directory (does not exist yet — create it when the first backport is
   needed), named after the CVE or advisory ID and the affected file(s).
3. Apply it as an explicit, documented build step run against whichever
   ESP-IDF checkout is in use (local install or the Docker image) *before*
   `idf.py build`, wired into both the local build instructions
   (`AGENTS.md`'s `Build` section) and `.github/workflows/build.yml`'s CI
   jobs, so a patch applies identically and automatically everywhere,
   rather than depending on someone remembering to hand-edit each
   environment.
4. Document provenance explicitly in the patch file's header: the upstream
   commit hash, the ESP-IDF version it landed in, and why it's believed to
   apply cleanly to v4.4.8 — the same discipline already used for the
   pinned `wolfssl`/`wolfssh` submodules in `components/wolfssh_spike/`.

This is inherently a heavier, rarer operation than pulling a point release,
since it requires understanding and validating the patch ourselves without
upstream review or testing on this specific branch.

## Mandatory-upgrade triggers

Any of the following starts a mandatory ESP-IDF upgrade project (not just a
backport):

- **(a) Unpatchable-in-place CVE.** A critical/high-severity CVE in an
  in-scope component that cannot be confidently and quickly hand-patched
  (e.g. a deep fix in the Wi-Fi stack's closed-source binary blobs, which
  cannot be patched at all without an Espressif-provided rebuild).
- **(b) Sustained EOL exposure, on a firm deadline.** Since there is no
  future EOL date to anchor to — that already happened in July 2024 — this
  trigger is itself time-bounded rather than open-ended: a mandatory
  ESP-IDF-upgrade project must be **opened by January 2027** (chosen as a
  concrete, near-term deadline from this policy's original authorship in
  August 2026, not an indefinitely deferrable "eventually"), and, once
  opened under any trigger in this list, must **complete within 6 months**
  of being opened. Independent of that deadline, review upgrade
  feasibility at least every 12 months and escalate visibly the longer the
  project remains on an unsupported branch.
- **(c) New network-facing surface on a known-unpatched component.** Any
  new network-facing feature (SSH is the first; anything after it) landing
  on top of a component with a known, unpatched CVE is an immediate
  blocker on that feature shipping, independent of the review cadence
  above.

## Tracking

Day-to-day status (what's been reviewed, what's outstanding, upgrade
feasibility notes) belongs in a living GitHub issue, not in edits to this
document. This document is the stable policy statement; keep it short and
update it only when the policy itself changes.
