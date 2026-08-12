/* allocator.c -- XMALLOC/XFREE/XREALLOC implementations required by
 * XMALLOC_USER (see user_settings.h). wolfssl/wolfcrypt/types.h declares
 * these as `extern` functions with exactly this signature when
 * XMALLOC_USER is defined; it does not accept macros in that mode. Thin
 * wrappers over plain newlib malloc/free/realloc -- see user_settings.h
 * for why this profile does not use the Espressif-specific allocator
 * wrapper instead.
 */
#include <stddef.h>
#include <stdlib.h>

void* XMALLOC(size_t n, void* heap, int type)
{
    (void)heap;
    (void)type;
    return malloc(n);
}

void* XREALLOC(void* p, size_t n, void* heap, int type)
{
    (void)heap;
    (void)type;
    return realloc(p, n);
}

void XFREE(void* p, void* heap, int type)
{
    (void)heap;
    (void)type;
    free(p);
}
