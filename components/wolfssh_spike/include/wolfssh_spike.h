/* wolfssh_spike.h -- public API for the wolfSSH feasibility-spike server.
 *
 * Deliberately minimal: no wolfSSL/wolfSSH types or macros appear here, so
 * including this header (e.g. from main/main.c) never leaks the spike's
 * private crypto configuration into the rest of the firmware. See
 * docs/design/ssh-feasibility-spike.md.
 */
#ifndef WOLFSSH_SPIKE_H
#define WOLFSSH_SPIKE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the experimental SSH server task. Safe to call once from
 * app_main() after networking has been initialized (network_init()).
 *
 * `get_station_ip` is injected rather than called directly against
 * main/network.h so this component never depends on the `main` component
 * (main already depends on this component to call this very function --
 * a component dependency cycle is not something ESP-IDF's build supports).
 * Pass network_get_ip. It returns 0 until the station interface has a
 * usable IP; the spike's task polls it before opening its listening
 * socket.
 *
 * No-op build target when CONFIG_EXPERIMENTAL_WOLFSSH_SERVER is disabled
 * -- this component compiles to nothing in that case, so this declaration
 * only needs to be reachable from within a matching
 * #if CONFIG_EXPERIMENTAL_WOLFSSH_SERVER guard at the call site. */
void wolfssh_spike_start(uint32_t (*get_station_ip)(void));

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_SPIKE_H */
