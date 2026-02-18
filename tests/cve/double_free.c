/*
 * Double-Free Proof of Concept
 * Demonstrates CVE-2025-8058 (glibc regcomp double-free) pattern.
 *
 * glibc behavior: On glibc < 2.29, no detection. On glibc >= 2.29,
 * tcache key check may detect it, but can be bypassed.
 *
 * compatmalloc behavior: Immediate abort with
 * "compatmalloc: double free detected" via out-of-band metadata
 * FLAG_FREED check. Cannot be bypassed by heap corruption.
 *
 * Compile: gcc -o double_free tests/cve/double_free.c
 * Run (glibc):          ./double_free
 * Run (compatmalloc):   LD_PRELOAD=./target/release/libcompatmalloc.so ./double_free
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    setbuf(stdout, NULL);  /* Disable buffering so output is visible before abort */
    printf("=== Double-Free Detection Demo ===\n\n");

    char *ptr = malloc(64);
    if (!ptr) { perror("malloc"); return 1; }
    memset(ptr, 'A', 64);
    printf("[1] malloc(64)  => %p\n", (void *)ptr);

    printf("[2] free(%p)    => OK\n", (void *)ptr);
    free(ptr);

    /*
     * Second free - BUG: double free.
     * Under glibc (older): silently corrupts tcache freelist.
     * Under glibc (>= 2.29): may detect via tcache key, but key is inline.
     * Under compatmalloc: FLAG_FREED in out-of-band metadata => immediate abort.
     */
    printf("[3] free(%p)    => double free! (should be caught)\n", (void *)ptr);
    free(ptr);

    /* If we reach here, the double-free was NOT detected */
    printf("\n[!] Double-free was NOT detected.\n");
    printf("    Under glibc, the tcache freelist is now corrupted.\n");
    printf("    Subsequent malloc() calls may return the same pointer,\n");
    printf("    enabling use-after-free exploitation.\n\n");

    char *a = malloc(64);
    char *b = malloc(64);
    printf("[4] malloc(64)  => %p\n", (void *)a);
    printf("[5] malloc(64)  => %p\n", (void *)b);
    if (a == b) {
        printf("\n[!!] CONFIRMED: both pointers are identical!\n");
        printf("     An attacker can now read/write through both.\n");
    }

    free(a);
    if (a != b) free(b);
    return 0;
}
