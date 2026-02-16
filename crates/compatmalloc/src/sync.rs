use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, Ordering};

/// A simple mutex built on futex (Linux) or pthread_mutex.
/// We cannot use std::sync::Mutex because it may allocate.
pub struct RawMutex {
    /// 0 = unlocked, 1 = locked no waiters, 2 = locked with waiters
    state: AtomicI32,
}

unsafe impl Send for RawMutex {}
unsafe impl Sync for RawMutex {}

impl RawMutex {
    pub const fn new() -> Self {
        Self {
            state: AtomicI32::new(0),
        }
    }

    #[inline]
    pub fn lock(&self) {
        // Fast path: uncontended
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        self.lock_slow();
    }

    #[cold]
    fn lock_slow(&self) {
        loop {
            // Try to acquire
            let old = self.state.swap(2, Ordering::Acquire);
            if old == 0 {
                return;
            }
            // Wait on futex
            #[cfg(target_os = "linux")]
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    &self.state as *const AtomicI32,
                    libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                    2i32,
                    core::ptr::null::<libc::timespec>(),
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                core::hint::spin_loop();
            }
        }
    }

    #[inline]
    pub fn unlock(&self) {
        let old = self.state.fetch_sub(1, Ordering::Release);
        if old != 1 {
            // There were waiters
            self.state.store(0, Ordering::Release);
            self.wake_one();
        }
    }

    #[cold]
    fn wake_one(&self) {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.state as *const AtomicI32,
                libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                1i32,
            );
        }
    }

    /// Try to lock without blocking. Returns true if lock was acquired.
    #[inline]
    pub fn try_lock(&self) -> bool {
        self.state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }
}

/// A mutex that wraps data, similar to std::sync::Mutex but allocation-free.
pub struct Mutex<T> {
    raw: RawMutex,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            raw: RawMutex::new(),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.raw.lock();
        MutexGuard { mutex: self }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self.raw.try_lock() {
            Some(MutexGuard { mutex: self })
        } else {
            None
        }
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.raw.unlock();
    }
}
