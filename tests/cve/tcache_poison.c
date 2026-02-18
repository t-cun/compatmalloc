/*
 * Tcache Poisoning via 1-Byte Overflow Proof of Concept
 * Demonstrates the CVE-2024-2961 exploitation technique.
 *
 * glibc behavior: 1-byte overflow modifies tcache fd pointer.
 * compatmalloc behavior: Canary bytes detect overflow + out-of-band metadata.
 *
 * Note: compatmalloc uses deferred batch verification (~every 64 frees).
 * We pre-allocate many same-class blocks, then free them after the
 * corrupted block to force the batch flush, which runs the canary check.
 *
 * Compile: gcc -o tcache_poison tests/cve/tcache_poison.c
 * Run (glibc):          ./tcache_poison
 * Run (compatmalloc):   LD_PRELOAD=./target/release/libcompatmalloc.so ./tcache_poison
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define FLUSH_COUNT 70

int main(void) {
    setbuf(stdout, NULL);  /* Disable buffering so output is visible before abort */
    printf("=== Tcache Poisoning via 1-Byte Overflow Demo ===\n");
    printf("    (CVE-2024-2961 exploitation technique)\n\n");

    /* Use 50 instead of 64 so compatmalloc places canary bytes in [50..64).
     * A 1-byte overflow at index 50 will land in the canary region. */
    size_t chunk_size = 50;

    /* Pre-allocate blocks to use for flushing the free buffer later */
    void *flush_ptrs[FLUSH_COUNT];
    for (int i = 0; i < FLUSH_COUNT; i++) {
        flush_ptrs[i] = malloc(chunk_size);
    }

    char *chunk_a = malloc(chunk_size);
    char *chunk_b = malloc(chunk_size);
    if (!chunk_a || !chunk_b) { perror("malloc"); return 1; }

    printf("[1] chunk_a = malloc(%zu) => %p\n", chunk_size, (void *)chunk_a);
    printf("[2] chunk_b = malloc(%zu) => %p\n", chunk_size, (void *)chunk_b);
    printf("    distance: %td bytes\n\n", (char *)chunk_b - (char *)chunk_a);

    memset(chunk_a, 'A', chunk_size);
    memset(chunk_b, 'B', chunk_size);

    printf("[3] free(chunk_b) => chunk_b enters tcache\n");
    free(chunk_b);

    uint64_t original_fd;
    memcpy(&original_fd, chunk_b, sizeof(original_fd));
    printf("[4] chunk_b tcache fd = 0x%016lx\n\n", (unsigned long)original_fd);

    /* 1-byte overflow from chunk_a into chunk_b (CVE-2024-2961 pattern).
     * Under glibc, this overwrites the inline tcache next pointer.
     * Under compatmalloc, this lands in canary bytes [50..64). */
    printf("[5] Simulating 1-byte overflow from chunk_a into chunk_b...\n");
    chunk_a[chunk_size] = 0x42;

    printf("[6] free(chunk_a) => queued for deferred canary check\n");
    free(chunk_a);

    /*
     * Trigger batch flush: free pre-allocated blocks of the same size
     * class to fill the deferred free buffer, forcing a batch verification
     * pass that checks canary bytes.
     */
    printf("[7] Triggering batch flush (%d frees)...\n", FLUSH_COUNT);
    for (int i = 0; i < FLUSH_COUNT; i++) {
        free(flush_ptrs[i]);
    }

    /* If we reach here, the overflow was NOT detected */
    printf("\n[!] 1-byte overflow was NOT detected.\n");

    uint64_t corrupted_fd;
    memcpy(&corrupted_fd, chunk_b, sizeof(corrupted_fd));
    printf("[8] chunk_b tcache fd now = 0x%016lx\n", (unsigned long)corrupted_fd);

    if (corrupted_fd != original_fd) {
        printf("    [!!] fd pointer was modified by the overflow!\n");
        printf("    An attacker can now redirect malloc() to return\n");
        printf("    an arbitrary address, enabling arbitrary write.\n");
    }

    return 0;
}
