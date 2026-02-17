/*
 * Fast TLS access for compatmalloc.
 *
 * Uses __thread with initial-exec TLS model to get direct fs: segment
 * loads (~1-3 cycles) instead of __tls_get_addr PLT calls (~25 cycles)
 * or pthread_getspecific PLT calls (~10-15 cycles).
 *
 * initial-exec is safe for LD_PRELOAD / DT_NEEDED shared libraries
 * (loaded at program start). NOT safe for dlopen'd libraries.
 */

#include <stddef.h>

static __thread void *_tls_state
    __attribute__((tls_model("initial-exec"))) = (void *)0;

__attribute__((visibility("hidden")))
void *compatmalloc_tls_get(void) {
    return _tls_state;
}

__attribute__((visibility("hidden")))
void compatmalloc_tls_set(void *ptr) {
    _tls_state = ptr;
}
