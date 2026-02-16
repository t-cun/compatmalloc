# ABI Contract

compatmalloc exports every symbol that a glibc-linked program may reference for dynamic memory management. This page documents each exported function, its parameters, return values, and error behavior.

All functions use the C ABI (`extern "C"`).

---

## Standard C allocator

### `malloc`

```c
void *malloc(size_t size);
```

Allocate `size` bytes of uninitialized memory.

- **Parameters:** `size` -- number of bytes to allocate.
- **Returns:** Pointer to the allocated memory, aligned to at least 16 bytes. Returns `NULL` on failure (and `errno` is set to `ENOMEM` by the underlying mapping).
- **Special case:** `malloc(0)` returns a valid, unique, non-`NULL` pointer (to a 1-byte internal allocation). This pointer must be passed to `free()`.

### `free`

```c
void free(void *ptr);
```

Release memory previously returned by `malloc`, `calloc`, `realloc`, or an alignment function.

- **Parameters:** `ptr` -- pointer to free. If `NULL`, the call is a no-op.
- **Behavior on double-free:** If the `write-after-free-check` feature is enabled and the metadata table detects the pointer was already freed, the allocator writes a diagnostic to stderr and calls `abort()`.
- **Behavior on invalid pointer:** Pointers not recognized by any arena or the large allocator are silently ignored for compatibility.

### `realloc`

```c
void *realloc(void *ptr, size_t size);
```

Change the size of a previously allocated block.

- **Parameters:**
  - `ptr` -- pointer to the existing allocation. If `NULL`, behaves like `malloc(size)`.
  - `size` -- new size in bytes. If `0`, behaves like `free(ptr)` and returns `NULL`.
- **Returns:** Pointer to the resized block (may differ from `ptr`). Returns `NULL` on failure; the original block is left unchanged.
- **Copy behavior:** When a new block is allocated, `min(old_size, new_size)` bytes are copied from the old block.

### `calloc`

```c
void *calloc(size_t nmemb, size_t size);
```

Allocate zeroed memory for an array.

- **Parameters:**
  - `nmemb` -- number of elements.
  - `size` -- size of each element.
- **Returns:** Pointer to zero-initialized memory. Returns `NULL` if the multiplication `nmemb * size` overflows or if allocation fails.
- **Overflow protection:** Uses `checked_mul` internally. On overflow, sets `errno` to `ENOMEM` and returns `NULL`.

---

## POSIX alignment APIs

### `posix_memalign`

```c
int posix_memalign(void **memptr, size_t alignment, size_t size);
```

Allocate memory with a specified alignment (POSIX).

- **Parameters:**
  - `memptr` -- output pointer. Must not be `NULL`.
  - `alignment` -- must be a power of two and at least `sizeof(void *)` (8 bytes on 64-bit).
  - `size` -- number of bytes.
- **Returns:** `0` on success (pointer stored in `*memptr`). `EINVAL` if `memptr` is `NULL` or `alignment` is invalid. `ENOMEM` if allocation fails.

### `aligned_alloc`

```c
void *aligned_alloc(size_t alignment, size_t size);
```

Allocate memory with a specified alignment (C11).

- **Parameters:**
  - `alignment` -- must be a power of two.
  - `size` -- must be a multiple of `alignment` (unless `size` is `0`).
- **Returns:** Aligned pointer, or `NULL` on failure (with `errno` set to `EINVAL` or `ENOMEM`).

### `memalign`

```c
void *memalign(size_t alignment, size_t size);
```

Allocate memory with a specified alignment (legacy).

- **Parameters:**
  - `alignment` -- must be a power of two.
  - `size` -- number of bytes.
- **Returns:** Aligned pointer, or `NULL` on failure.

### `valloc`

```c
void *valloc(size_t size);
```

Allocate page-aligned memory.

- **Parameters:** `size` -- number of bytes.
- **Returns:** Pointer aligned to the system page size (4096 bytes), or `NULL` on failure.

### `pvalloc`

```c
void *pvalloc(size_t size);
```

Allocate page-aligned memory, rounding the size up to a page boundary.

- **Parameters:** `size` -- number of bytes (rounded up to the next multiple of the page size).
- **Returns:** Page-aligned pointer, or `NULL` on failure.

---

## GNU extensions

### `malloc_usable_size`

```c
size_t malloc_usable_size(void *ptr);
```

Return the usable size of an allocation.

- **Parameters:** `ptr` -- pointer returned by an allocator function. If `NULL`, returns `0`.
- **Returns:** The number of usable bytes in the allocation. This may be larger than the originally requested size (due to size-class rounding) but programs must not rely on the excess bytes persisting across `realloc`.

### `mallopt`

```c
int mallopt(int param, int value);
```

Set allocator tuning parameters.

- **Behavior:** Accepts all calls and returns `1` (success) but performs no action. Provided solely for binary compatibility with programs that call `mallopt`.

### `mallinfo` / `mallinfo2`

```c
struct mallinfo  mallinfo(void);
struct mallinfo2 mallinfo2(void);  // Linux only
```

Return allocator statistics.

- **Behavior:** Returns a zeroed struct. Provided solely for binary compatibility. `mallinfo2` is only exported on Linux targets.

---

## Minimum alignment

All allocations are aligned to at least **16 bytes** (`MIN_ALIGN`), which matches `max_align_t` on 64-bit Linux. This guarantees correct alignment for any C data type.
