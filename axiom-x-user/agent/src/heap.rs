//! User-space heap over `AX_MMAP`.
//!
//! Layout: `[u64 size-and-flag | payload ...]` blocks. Low bit of the
//! header word is the free flag. Arenas grow by `AX_MMAP` in `CHUNK`
//! pages; allocation is first-fit over a singly-linked free list, then a
//! bump into the current arena tail. `free` pushes the block back on the
//! list — no coalescing (v1). Single-threaded: every process owns its own
//! arena, so plain statics are safe.

use core::alloc::{GlobalAlloc, Layout};

/// `AX_MMAP` growth granularity: 16 pages per arena extension.
const CHUNK: usize = 64 * 1024;
/// Header + payload alignment; covers every Rust type through u128.
const ALIGN: usize = 16;
const HEADER: usize = ALIGN;

struct Free {
    size: usize,
    next: *mut Free,
}

static mut ARENA_END: usize = 0;
static mut BUMP: usize = 0;
static mut FREE: *mut Free = core::ptr::null_mut();

/// `GlobalAlloc` backend for `alloc` collections in Axiom-X user programs.
pub struct AgentAlloc;

/// Raw block total including its header, `ALIGN`-rounded.
fn block_total(layout: Layout) -> usize {
    (layout.size().max(1) + HEADER + (ALIGN - 1)) & !(ALIGN - 1)
}

/// Extend the arena by at least `need` bytes via `AX_MMAP`.
unsafe fn grow(need: usize) -> bool {
    let chunk = need.max(CHUNK);
    let base = axiom_x_user::mmap(chunk);
    if base < 0 {
        return false;
    }
    // Kernel heap growth is contiguous per process: normally this extends
    // the tail. A gap just orphans the old remainder (waste, v1).
    if base as usize == ARENA_END {
        ARENA_END += chunk;
    } else {
        BUMP = base as usize;
        ARENA_END = BUMP + chunk;
    }
    true
}

unsafe impl GlobalAlloc for AgentAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > ALIGN {
            return core::ptr::null_mut();
        }
        let need = block_total(layout);

        // First-fit over the free list; split oversized blocks.
        let mut link = &mut FREE as *mut *mut Free;
        unsafe {
            while !(*link).is_null() {
                let block = *link;
                let total = (*block).size;
                if total >= need {
                    if total >= need + HEADER + ALIGN {
                        (*block).size = total - need;
                        let taken = (block as usize + total - need) as *mut Free;
                        (*taken).size = need | 1;
                        return (taken as usize + HEADER) as *mut u8;
                    }
                    *link = (*block).next;
                    (*block).size = total | 1;
                    return (block as usize + HEADER) as *mut u8;
                }
                link = &mut (*block).next;
            }

            // Bump into the arena tail, growing via AX_MMAP as needed.
            if BUMP + need > ARENA_END && !grow(need) {
                return core::ptr::null_mut();
            }
            let block = BUMP as *mut Free;
            (*block).size = need | 1;
            BUMP += need;
            (block as usize + HEADER) as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let block = unsafe { &mut *((ptr as usize - HEADER) as *mut Free) };
        block.size = block.size & !1;
        block.next = unsafe { FREE };
        unsafe { FREE = block };
    }
}
