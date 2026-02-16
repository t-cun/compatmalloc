# Failure Modes

This page documents what happens when compatmalloc encounters error conditions at runtime. Understanding these failure modes is important for debugging and for setting expectations about how the allocator behaves under stress or attack.

## Out of memory (OOM)

### Slab allocation failure

When `mmap` fails while allocating a new slab region, the slab allocator returns a null pointer. This propagates up through `malloc`, which returns `NULL` to the caller. The allocator does not abort on OOM; it follows the C standard convention of returning `NULL`.

### Large allocation failure

When `mmap` fails for a large allocation, `LargeAlloc::create` returns `None`, and `malloc` returns `NULL`.

### Metadata table growth failure

When the metadata table exceeds its 75% load factor and `mmap` fails for the new table, the `grow` function returns without growing. Subsequent insertions may degrade to long probe chains but will still function as long as there is at least one empty slot. The allocator does not abort.

### Calloc overflow

If `nmemb * size` overflows `usize`, `calloc` sets `errno` to `ENOMEM` and returns `NULL`. No allocation is attempted.

## Heap corruption detected

### Canary violation

**Trigger:** `free` or `realloc` of a pointer whose canary bytes have been modified (buffer overflow detected).

**Behavior:** When the canary check fails, the allocator writes a diagnostic message to stderr and calls `abort()`:

```
compatmalloc: canary check failed -- heap buffer overflow detected
```

The process is terminated immediately. This is intentional: a corrupted canary means the heap is in an unknown state, and continuing execution could allow exploitation.

### Write-after-free detected

**Trigger:** A quarantine entry's poison bytes have been modified when the entry is evicted (write-after-free detected).

**Behavior:** The allocator writes a diagnostic to stderr and calls `abort()`:

```
compatmalloc: write-after-free detected during quarantine eviction
```

### Double free

**Trigger:** `free` is called on a pointer whose metadata `FLAG_FREED` bit is already set.

**Behavior:** For large allocations, the allocator writes a diagnostic to stderr and calls `abort()`:

```
compatmalloc: double free detected (large)
```

For slab allocations, double-free detection relies on the metadata table's freed flag.

### Guard page violation

**Trigger:** A read or write to a guard page (buffer overflow/underflow past the allocation region boundary).

**Behavior:** The kernel delivers `SIGSEGV` to the process. The allocator does not handle this signal; it results in the default behavior (core dump and termination). The faulting address will be within a guard page region, which can be identified in the core dump.

## Diagnostic output

All diagnostic messages are written directly to file descriptor 2 (stderr) using `libc::write`, with no heap allocation. This ensures that diagnostics work even when the heap is corrupted. After writing the message, the allocator calls `libc::abort()`, which generates a `SIGABRT` and (on most configurations) a core dump.

The diagnostic path is implemented in `hardening::abort_with_message`:

```rust
pub fn abort_with_message(msg: &str) -> ! {
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::abort();
    }
}
```

## Kill-switch behavior

When `COMPATMALLOC_DISABLE=1` is set, the allocator enters disabled mode during initialization. All allocation calls pass through to glibc via `dlsym(RTLD_NEXT)`. No hardening features are active, and no hardening-related failures can occur.

## Summary table

| Condition | Behavior | Exit? |
|-----------|----------|-------|
| `mmap` fails (OOM) | Returns `NULL` | No |
| `calloc` size overflow | Returns `NULL`, sets `errno = ENOMEM` | No |
| Metadata table growth fails | Continues with existing table | No |
| Canary violation | Diagnostic to stderr, `abort()` | Yes |
| Write-after-free | Diagnostic to stderr, `abort()` | Yes |
| Double free (large) | Diagnostic to stderr, `abort()` | Yes |
| Guard page violation | `SIGSEGV` (kernel-delivered) | Yes |
| Unknown pointer to `free` | Silently ignored | No |
