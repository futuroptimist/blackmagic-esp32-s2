#ifndef WOLFSSH_SPIKE_ALLOCATOR_H
#define WOLFSSH_SPIKE_ALLOCATOR_H

#include <stddef.h>

/* Returns the requested size recorded by the XMALLOC_USER wrapper. */
size_t wolfssh_spike_allocation_size(const void* p);

#endif /* WOLFSSH_SPIKE_ALLOCATOR_H */
