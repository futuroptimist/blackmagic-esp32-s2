/* FreeRTOS.h -- compatibility shim, PRIV_INCLUDE_DIRS-only.
 *
 * wolfSSL's WOLFSSL_ESPIDF default block (wolfssl/wolfcrypt/settings.h,
 * "#ifndef NO_ESPIDF_DEFAULT") unconditionally defines FREERTOS, which
 * later triggers a bare `#include "FreeRTOS.h"` / `#include <task.h>` --
 * the classic upstream FreeRTOS header names. ESP-IDF v4.4 namespaces
 * these under a `freertos/` directory (`#include <freertos/FreeRTOS.h>`,
 * matching every other file in this repository), so the bare names don't
 * resolve on their own.
 *
 * This shim exists purely to bridge that naming mismatch for this one
 * ESP-IDF version/wolfSSL-version combination, without disabling any of
 * wolfSSL's other ESP-IDF defaults (timing-resistant math, lwIP, etc.) by
 * defining NO_ESPIDF_DEFAULT ourselves. See
 * docs/design/ssh-feasibility-spike.md, section 3 and 5, for why this
 * kind of small, isolated compatibility patch is acceptable for this
 * spike.
 */
#include <freertos/FreeRTOS.h>
