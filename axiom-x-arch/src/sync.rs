//! Locking primitives for a kernel whose threads can be preempted.
//!
//! A plain spin lock is unsafe to share between preemptible code and code
//! that runs with interrupts off (interrupt handlers, and every system call
//! today, since `int 0x80` is an interrupt gate). On one CPU: if a thread is
//! preempted while holding the lock and the code that runs next spins on it
//! with interrupts off, nothing can ever release it, and the kernel hangs.
//!
//! [`IrqMutex`] closes that hole: interrupts are off for as long as the lock
//! is held, so its holder cannot be preempted. Keep its critical sections
//! short; their length is time the timer cannot interrupt (see `latency`).
//!
//! Status: `partial` — single CPU. On SMP this is still the right lock for
//! state shared with interrupt handlers, but it does not by itself bound
//! another CPU's waiting time.

use core::ops::{Deref, DerefMut};

pub struct IrqMutex<T> {
    inner: spin::Mutex<T>,
}

impl<T> IrqMutex<T> {
    pub const fn new(value: T) -> Self {
        Self { inner: spin::Mutex::new(value) }
    }

    /// Disable interrupts, then take the lock. Interrupts are restored to
    /// their previous state when the guard is dropped (after unlocking).
    pub fn lock(&self) -> IrqMutexGuard<'_, T> {
        let was_enabled = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();
        IrqMutexGuard { guard: Some(self.inner.lock()), was_enabled }
    }
}

pub struct IrqMutexGuard<'a, T> {
    guard: Option<spin::MutexGuard<'a, T>>,
    was_enabled: bool,
}

impl<T> Deref for IrqMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().unwrap()
    }
}

impl<T> DerefMut for IrqMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().unwrap()
    }
}

impl<T> Drop for IrqMutexGuard<'_, T> {
    fn drop(&mut self) {
        drop(self.guard.take()); // unlock first
        if self.was_enabled {
            x86_64::instructions::interrupts::enable();
        }
    }
}
