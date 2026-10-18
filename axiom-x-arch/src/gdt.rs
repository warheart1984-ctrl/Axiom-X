//! Kernel GDT and TSS for x86_64.
//!
//! Replaces the trampoline's boot GDT (null / kernel code / kernel data) with
//! one that also has ring-3 segments and a TSS, which ring 3 needs: the TSS
//! supplies RSP0 (the kernel stack used when an interrupt or `int 0x80`
//! arrives from user mode) and the IST stack for double faults.
//!
//! Selector layout (fixed; `sysret` requires user data at STAR base + 8 and
//! user code at STAR base + 16):
//!
//! ```text
//! 0x08 kernel code   0x10 kernel data
//! 0x1B user data     0x23 user code     (RPL 3)
//! 0x28 TSS (16-byte system descriptor)
//! ```
//!
//! Status: `partial` — loaded at boot and exercised by ring-3 entry/exit in
//! QEMU; single CPU only (one TSS, one RSP0 stack).

use core::ptr::{addr_of, addr_of_mut};
use spin::Once;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x18 | 3;
pub const USER_CS: u16 = 0x20 | 3;
pub const TSS_SEL: u16 = 0x28;

/// IST slot (0-based, as the `x86_64` crate counts) for the double-fault handler.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Kernel stack for entries from ring 3 (TSS.RSP0). IRQs taken in user mode
/// run the unoptimized scheduler tick on it, so it is sized like the boot
/// kernel stacks.
const RING0_STACK_SIZE: usize = 256 * 1024;
/// Dedicated stack so a double fault caused by a kernel stack overflow can
/// still be reported.
const DOUBLE_FAULT_STACK_SIZE: usize = 32 * 1024;

#[repr(C, align(16))]
struct Stack<const N: usize>([u8; N]);

static mut RING0_STACK: Stack<RING0_STACK_SIZE> = Stack([0; RING0_STACK_SIZE]);
static mut DOUBLE_FAULT_STACK: Stack<DOUBLE_FAULT_STACK_SIZE> = Stack([0; DOUBLE_FAULT_STACK_SIZE]);

/// Mutable because RSP0 changes on every switch to a thread with its own
/// kernel stack; the CPU reads it from memory on each ring 3 -> 0 entry.
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static GDT: Once<GlobalDescriptorTable> = Once::new();

fn stack_top<const N: usize>(stack: *const Stack<N>) -> VirtAddr {
    VirtAddr::from_ptr(stack) + N as u64
}

/// Top of the RSP0 stack that entries from ring 3 land on.
pub fn ring0_stack_top() -> VirtAddr {
    stack_top(addr_of!(RING0_STACK))
}

/// Build and load the kernel GDT, reload the segment registers, load the TSS.
///
/// Must run before the IDT is used from ring 3 and before `init_syscall`.
pub fn init_gdt() {
    unsafe {
        let tss = addr_of_mut!(TSS);
        (*tss).privilege_stack_table[0] = ring0_stack_top();
        (*tss).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            stack_top(addr_of!(DOUBLE_FAULT_STACK));
    }

    let gdt = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let selectors = [
            gdt.append(Descriptor::kernel_code_segment()),
            gdt.append(Descriptor::kernel_data_segment()),
            gdt.append(Descriptor::user_data_segment()),
            gdt.append(Descriptor::user_code_segment()),
            // SAFETY: TSS is a static that lives for the whole kernel run.
            gdt.append(unsafe { Descriptor::tss_segment_unchecked(addr_of!(TSS)) }),
        ];
        let expected = [KERNEL_CS, KERNEL_DS, USER_DS, USER_CS, TSS_SEL];
        for (sel, want) in selectors.iter().zip(expected) {
            assert_eq!(sel.0, want, "GDT selector layout changed");
        }
        gdt
    });

    gdt.load();
    unsafe {
        CS::set_reg(SegmentSelector(KERNEL_CS));
        SS::set_reg(SegmentSelector(KERNEL_DS));
        DS::set_reg(SegmentSelector(KERNEL_DS));
        ES::set_reg(SegmentSelector(KERNEL_DS));
        load_tss(SegmentSelector(TSS_SEL));
    }
}

/// Point TSS.RSP0 at `top`: the kernel stack the CPU switches to when the
/// next interrupt or syscall arrives from ring 3. Call with interrupts off.
pub fn set_kernel_stack(top: VirtAddr) {
    unsafe { (*addr_of_mut!(TSS)).privilege_stack_table[0] = top };
}
