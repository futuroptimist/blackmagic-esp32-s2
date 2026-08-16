/* allocator.c -- XMALLOC/XFREE/XREALLOC implementations required by
 * XMALLOC_USER (see user_settings.h). wolfssl/wolfcrypt/types.h declares
 * these as `extern` functions with exactly this signature when
 * XMALLOC_USER is defined; it does not accept macros in that mode. Thin
 * wrappers over plain newlib malloc/free/realloc -- see user_settings.h
 * for why this profile does not use the Espressif-specific allocator
 * wrapper instead.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "allocator.h"

typedef union {
    struct {
        size_t size;
    } metadata;
    long double alignment;
    void* pointer_alignment;
} allocation_header_t;

void* XMALLOC(size_t n, void* heap, int type)
{
    (void)heap;
    (void)type;
    allocation_header_t* allocation;

    if (n > SIZE_MAX - sizeof(*allocation)) {
        return NULL;
    }
    allocation = malloc(sizeof(*allocation) + n);
    if (allocation == NULL) {
        return NULL;
    }
    allocation->metadata.size = n;
    return allocation + 1;
}

void* XREALLOC(void* p, size_t n, void* heap, int type)
{
    (void)heap;
    (void)type;
    allocation_header_t* allocation;

    if (p == NULL) {
        return XMALLOC(n, heap, type);
    }
    if (n > SIZE_MAX - sizeof(*allocation)) {
        return NULL;
    }
    allocation = (allocation_header_t*)p - 1;
    allocation = realloc(allocation, sizeof(*allocation) + n);
    if (allocation == NULL) {
        return NULL;
    }
    allocation->metadata.size = n;
    return allocation + 1;
}

void XFREE(void* p, void* heap, int type)
{
    (void)heap;
    (void)type;
    if (p != NULL) {
        free((allocation_header_t*)p - 1);
    }
}

size_t wolfssh_spike_allocation_size(const void* p)
{
    if (p == NULL) {
        return 0;
    }
    return ((const allocation_header_t*)p - 1)->metadata.size;
}
