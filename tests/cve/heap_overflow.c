/*
 * Heap Buffer Overflow Proof of Concept
 * Demonstrates the CVE-2023-6246 pattern: heap overflow in syslog().
 *
 * glibc behavior: Silent corruption of adjacent heap metadata.
 * compatmalloc behavior: Canary bytes detect overflow on free().
 *
 * Note: compatmalloc uses deferred batch verification (~every 64 frees).
 * We pre-allocate many same-class blocks, then free them after the
 * corrupted block to force the batch flush, which runs the canary check.
 *
 * Compile: gcc -o heap_overflow tests/cve/heap_overflow.c
 * Run (glibc):          ./heap_overflow
 * Run (compatmalloc):   LD_PRELOAD=./target/release/libcompatmalloc.so ./heap_overflow
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLUSH_COUNT 70

int main(void) {
    setbuf(stdout, NULL);  /* Disable buffering so output is visible before abort */
    printf("=== Heap Buffer Overflow Detection Demo ===\n");
    printf("    (CVE-2023-6246 pattern)\n\n");

    size_t buf_size = 100;

    /* Pre-allocate blocks to use for flushing the free buffer later */
    void *flush_ptrs[FLUSH_COUNT];
    for (int i = 0; i < FLUSH_COUNT; i++) {
        flush_ptrs[i] = malloc(buf_size);
    }

    char *buf = malloc(buf_size);
    if (!buf) { perror("malloc"); return 1; }
    printf("[1] malloc(%zu) => %p\n", buf_size, (void *)buf);

    /* Overflow: write 120 bytes into 100-byte buffer.
     * Under compatmalloc, malloc(100) returns a 112-byte slot
     * with canary bytes in the gap [100..112). Writing 120 bytes
     * destroys the canary.
     */
    size_t overflow_size = 120;
    printf("[2] memset(%p, 'X', %zu) => overflow by %zu bytes!\n",
           (void *)buf, overflow_size, overflow_size - buf_size);
    memset(buf, 'X', overflow_size);

    printf("[3] free(%p)    => queued for deferred canary check\n", (void *)buf);
    free(buf);

    /*
     * Trigger batch flush: free pre-allocated blocks of the same size
     * class to fill the deferred free buffer, forcing a batch verification
     * pass that checks canary bytes.
     */
    printf("[4] Triggering batch flush (%d frees)...\n", FLUSH_COUNT);
    for (int i = 0; i < FLUSH_COUNT; i++) {
        free(flush_ptrs[i]);
    }

    /* If we reach here, the overflow was NOT detected */
    printf("\n[!] Heap overflow was NOT detected on free().\n");
    printf("    Under glibc, the adjacent chunk's metadata may be\n");
    printf("    silently corrupted, enabling exploitation.\n");

    return 0;
}
