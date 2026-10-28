//! Axiom-X agent runtime.
//!
//! One job: give ring-3 programs a real heap. `AgentAlloc` is a
//! `GlobalAlloc` implementation over `AX_MMAP` — arenas grow in chunks
//! under the governed `Rights::ALLOC` right, so every page a process
//! allocates is a ledgered action. Processes are single-threaded, so the
//! free list needs no locking.
//!
//! With `#[global_allocator]` set, `alloc` collections (`Vec`, `String`,
//! `format!`) work in user programs.

#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

/// Required by `alloc` in a no_std binary: called when an allocation
/// fails. Without it the `__rust_alloc_error_handler` extern resolves to
/// a weak null and an OOM is an immediate call-to-0.
#[alloc_error_handler]
fn oom(_layout: core::alloc::Layout) -> ! {
    axiom_x_user::println!("[agent] out of memory");
    axiom_x_user::exit(134)
}

pub mod heap;

pub use heap::AgentAlloc;

// The syscall surface agents program against: console, spawn, files,
// evidence, mmap. Re-exported so agent code imports one crate.
pub use axiom_x_user::*;
