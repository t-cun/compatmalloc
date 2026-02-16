# Deviations from glibc

compatmalloc aims for full ABI compatibility with glibc's malloc, but makes deliberate behavioral choices that differ in edge cases. This page documents every known deviation.

## malloc(0)

| Behavior | glibc | compatmalloc |
|----------|-------|--------------|
| `malloc(0)` | Returns a unique non-`NULL` pointer (implementation-defined minimum size) | Returns a unique non-`NULL` pointer (internally allocates 1 byte, rounded up to a 16-byte slot) |

Both return a valid pointer that must be freed. The difference is academic; compatmalloc's behavior is conformant with the C standard, which states that `malloc(0)` may return either `NULL` or a unique pointer.

## Minimum allocation alignment

| Behavior | glibc | compatmalloc |
|----------|-------|--------------|
| Minimum alignment | 16 bytes on 64-bit | 16 bytes (`MIN_ALIGN`) |

No deviation. Both guarantee alignment to `max_align_t`.

## malloc_usable_size

| Behavior | glibc | compatmalloc |
|----------|-------|--------------|
| Usable size | Typically the chunk size minus overhead (often significantly larger than requested) | The slab slot size for the allocation's size class |

glibc often returns usable sizes much larger than requested due to its chunk-based design. compatmalloc returns the size-class slot size, which is typically closer to the requested size. Programs that depend on `malloc_usable_size` returning a value much larger than requested may behave differently.

## realloc(ptr, 0)

| Behavior | glibc | compatmalloc |
|----------|-------|--------------|
| `realloc(ptr, 0)` | Frees `ptr`, returns `NULL` (glibc 2.x behavior; was implementation-defined) | Frees `ptr`, returns `NULL` |

No deviation in practice. Note that the C standard makes `realloc(ptr, 0)` implementation-defined; both implementations choose to free and return `NULL`.

## mallopt / mallinfo / mallinfo2

| Behavior | glibc | compatmalloc |
|----------|-------|--------------|
| `mallopt` | Adjusts internal tuning parameters | Accepts the call, returns success, does nothing |
| `mallinfo` / `mallinfo2` | Returns live statistics | Returns zeroed structs |

These functions are provided only for binary compatibility. Programs that rely on `mallopt` to tune allocator behavior (e.g., `M_MMAP_THRESHOLD`) will find those tunings silently ignored. Programs that display `mallinfo` statistics will see all zeros.

## Freed memory contents

| Behavior | glibc | compatmalloc (default features) |
|----------|-------|-------------------------------|
| After `free(ptr)` | Memory contents undefined; typically contains freelist pointers | Memory is poisoned with `0xFE` bytes |

When the `poison-on-free` feature is enabled (included in the default `hardened` feature set), freed memory is overwritten with a poison byte (`0xFE`). Programs that access freed memory will read predictable but invalid data rather than stale user content or heap metadata.

If the `zero-on-free` feature is also enabled, memory is zeroed after poison checking, ensuring no sensitive data persists.

## Double free

| Behavior | glibc | compatmalloc |
|----------|-------|--------------|
| Double free | May print a diagnostic and abort, or may corrupt the heap silently depending on the tcache state | Detected via metadata flags; aborts with a diagnostic message to stderr |

compatmalloc's out-of-band metadata tracks the freed state of each allocation, providing more reliable double-free detection than glibc's inline freelist checks.

## Thread safety during init

| Behavior | glibc | compatmalloc |
|----------|-------|--------------|
| Early allocations before full init | Uses a brk-based arena | Uses a static 64 KiB bootstrap buffer; allocations from this buffer cannot be freed or reallocated back to the system |

The bootstrap buffer is a fixed-size bump allocator used only during the brief window when `dlsym` itself may call `malloc` before the real libc functions are resolved. Under normal operation, the bootstrap buffer is used for a handful of small allocations during initialization and is never exhausted.

## Aligned allocation internals

| Behavior | glibc | compatmalloc |
|----------|-------|--------------|
| Over-aligned allocations | Uses dedicated aligned chunk logic | Over-allocates by `size + alignment`, then returns an aligned offset within the allocation |

This approach is correct but wastes up to `alignment - 1` bytes per over-aligned allocation. For alignments of 16 bytes or less, no extra allocation is needed because the slab allocator already guarantees 16-byte alignment.
