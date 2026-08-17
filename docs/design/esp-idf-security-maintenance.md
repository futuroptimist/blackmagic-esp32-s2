# ESP-IDF security-maintenance policy

## Context

This firmware is pinned to ESP-IDF v4.4.8 (see `sdkconfig`, `.github/workflows/build.yml`,
and `README.md`). Per Espressif's own advisory
([AR2024-008](https://documentation.espressif.com/AR2024-008%20End-of-Life%20Advisory%20for%20ESP-IDF%20v4.4%20Release%20Branch%20EN.html)),
**the v4.4 release branch reached End-of-Life in July 2024.** Espressif's
published [support policy](https://github.com/espressif/esp-idf/blob/master/SUPPORT_POLICY.md)
states plainly: "It is our policy to not continue fixing bugs in End of Life
releases" — including security fixes. That means this project has been
running on a branch with **no upstream security support at all since mid-2024**,
over two years before this document was written.

Adding SSH (`components/wolfssh_spike/`) is the first network-facing feature
built on top of this stack beyond the existing WiFi/HTTP surface, which is
exactly the kind of change `docs/design/ssh-feasibility-spike.md`'s Phase 1
roadmap flags as requiring either an ESP-IDF upgrade or a documented,
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
Concretely, "backport" here means:

1. Locate the fix in a newer ESP-IDF branch (typically v5.x, where
   Espressif does patch actively-supported branches).
2. Hand-port the specific diff into this project's pinned ESP-IDF checkout
   (`~/esp/esp-idf-v4.4.8` locally / `espressif/idf:v4.4.8` in CI) or, if the
   affected code lives in a component this project already vendors as a
   submodule pattern, apply it there.
3. Document provenance explicitly: the upstream commit hash, the ESP-IDF
   version it landed in, and why it's believed to apply cleanly to v4.4.8 —
   the same discipline already used for the pinned `wolfssl`/`wolfssh`
   submodules in `components/wolfssh_spike/`.

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
- **(b) Sustained EOL exposure.** Since there is no future EOL date to
  anchor to — that already happened in July 2024 — treat time itself as a
  signal: review upgrade feasibility at least every 12 months regardless of
  whether a specific CVE has been found, and escalate visibly the longer
  the project remains on an unsupported branch.
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
