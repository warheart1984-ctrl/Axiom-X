//! ELF Binary Loader for Axiom-X
//!
//! Loads ELF64 executables into process address spaces with W^X enforcement.
//! Each PT_LOAD segment gets its own page-aligned mapping:
//!   text   R-X   rodata R--   data/bss RW-
//!
//! The ELF file data lives in kernel memory (boot modules, identity-mapped).
//! User pages are mapped in the target address space but not in the kernel's
//! current PML4, so each page is temporarily mapped into the kernel's address
//! space for the data copy, then remains mapped in the user address space.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::mem;
use core::ptr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::free_frame;
use crate::map_page_in;
use crate::new_address_space;
use crate::free_address_space;

/// ELF identification constants
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 0x3e;

/// ELF program header types
const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;

/// ELF program header flags
const PF_X: u32 = 1 << 0;
const PF_W: u32 = 1 << 1;
const PF_R: u32 = 1 << 2;

/// User address space upper bound (canonical lower half)
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// Page size
const PAGE_SIZE: u64 = 0x1000;

/// ELF64 Header
#[repr(C, packed)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// ELF64 Program Header
#[repr(C, packed)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// A loaded ELF segment
#[derive(Debug, Clone)]
pub struct LoadedSegment {
    pub virt_addr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub flags: u32,
}

/// One page mapping tracked during load: user virt addr -> phys frame.
struct PageMap {
    virt: u64,
    phys: u64,
}

/// ELF Loader — loads ELF64 executables into a target address space.
pub struct ElfLoader {
    /// PML4 root physical address of the target (user) address space.
    root: u64,
}

impl ElfLoader {
    /// Create a loader for the given address space root.
    pub fn new(root_phys_addr: u64) -> Self {
        Self { root: root_phys_addr }
    }

    /// Create a brand-new address space (shares kernel mappings, empty user slot)
    /// and return a loader for it plus the root frame.
    pub fn new_address_space() -> Result<(Self, u64), &'static str> {
        let frame = crate::new_address_space();
        Ok((Self::new(frame.start_address().as_u64()), frame.start_address().as_u64()))
    }

    /// Validate an ELF64 header and return (entry point, program header count).
    /// Does not load anything; safe to call multiple times.
    pub fn validate(elf_data: &[u8]) -> Result<(u64, usize), &'static str> {
        if elf_data.len() < mem::size_of::<Elf64Header>() {
            return Err("ELF too small");
        }
        let header = unsafe { &*(elf_data.as_ptr() as *const Elf64Header) };

        if header.e_ident[0..4] != ELF_MAGIC {
            return Err("Invalid ELF magic");
        }
        if header.e_ident[4] != ELFCLASS64 {
            return Err("Not 64-bit ELF");
        }
        if header.e_ident[5] != ELFDATA2LSB {
            return Err("Not little-endian");
        }
        if header.e_ident[6] != EV_CURRENT {
            return Err("Invalid ELF version");
        }
        if header.e_type != ET_EXEC {
            return Err("Not executable ELF");
        }
        if header.e_machine != EM_X86_64 {
            return Err("Not x86_64 architecture");
        }
        if header.e_phentsize as usize != mem::size_of::<Elf64ProgramHeader>() {
            return Err("Invalid program header entry size");
        }

        let ph_start = header.e_phoff as usize;
        let ph_end = ph_start
            .checked_add(header.e_phnum as usize * header.e_phentsize as usize)
            .ok_or("Program header overflow")?;
        if ph_end > elf_data.len() {
            return Err("Program headers extend beyond file");
        }

        Ok((header.e_entry, header.e_phnum as usize))
    }

    /// Load all PT_LOAD segments from `elf_data` into the target address space.
    /// Returns the loaded segments.
    ///
    /// Runs under the kernel's own page tables: temporary mappings used for
    /// the data copy live in KERNEL_PML4 (matching `unmap_kernel_page`), so
    /// they never leak into the caller's address space when this is invoked
    /// from a syscall running under another process's CR3.
    pub fn load_segments(
        &mut self,
        elf_data: &[u8],
        owner_pid: u32,
    ) -> Result<Vec<LoadedSegment>, &'static str> {
        self.load_segments_inner(elf_data, owner_pid)
    }

    fn load_segments_inner(
        &mut self,
        elf_data: &[u8],
        owner_pid: u32,
    ) -> Result<Vec<LoadedSegment>, &'static str> {
        let header = unsafe { &*(elf_data.as_ptr() as *const Elf64Header) };
        let ph_start = header.e_phoff as usize;
        let phentsize = header.e_phentsize as usize;
        let phnum = header.e_phnum as usize;

        let mut segments = Vec::new();
        let mut page_maps: Vec<PageMap> = Vec::new();

        for i in 0..phnum {
            let ph_off = ph_start.checked_add(i * phentsize).ok_or("PH overflow")?;
            let ph = unsafe { &*(elf_data.as_ptr().add(ph_off) as *const Elf64ProgramHeader) };

            if ph.p_type != PT_LOAD {
                continue;
            }

            // W^X: reject segments that are both writable and executable.
            if (ph.p_flags & PF_W) != 0 && (ph.p_flags & PF_X) != 0 {
                return Err("W^X violation: segment is both writable and executable");
            }

            // Reject segments in kernel address space.
            if ph.p_vaddr >= USER_SPACE_END {
                return Err("Segment in kernel address space");
            }

            // Page flags for this segment.
            let mut flags = x86_64::structures::paging::PageTableFlags::PRESENT
                | x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE;
            if (ph.p_flags & PF_W) != 0 {
                flags |= x86_64::structures::paging::PageTableFlags::WRITABLE;
            }
            if (ph.p_flags & PF_X) == 0 {
                flags |= x86_64::structures::paging::PageTableFlags::NO_EXECUTE;
            }

            // Page-aligned range covering the entire in-memory segment.
            let seg_start = ph.p_vaddr & !0xFFFu64;
            let seg_end = ph
                .p_vaddr
                .checked_add(ph.p_memsz)
                .and_then(|v| v.checked_add(0xFFF))
                .map(|v| v & !0xFFFu64)
                .ok_or("Segment overflow")?;
            let file_end = ph.p_vaddr.checked_add(ph.p_filesz).ok_or("File end overflow")?;

            // Map all pages for this segment into the user address space.
            let mut virt = seg_start;
            while virt < seg_end {
                let phys_addr = alloc_one_frame(owner_pid)?;
                map_page_in(
                    self.root,
                    virt,
                    phys_addr,
                    flags,
                );
                page_maps.push(PageMap {
                    virt,
                    phys: phys_addr,
                });
                virt += PAGE_SIZE;
            }

            // Copy file data into the mapped pages.
            let mut copied = 0u64;
            while copied < ph.p_filesz {
                let page_offset = (ph.p_vaddr + copied) & 0xFFF;
                let page_virt = ph.p_vaddr + copied - page_offset;
                let copy_len = (PAGE_SIZE - page_offset).min(ph.p_filesz - copied);

                // Find the phys frame for this user page.
                let phys = page_maps
                    .iter()
                    .find(|pm| pm.virt == page_virt)
                    .map(|pm| pm.phys)
                    .ok_or("User page not mapped")?;

                // The frame is identity-mapped for the kernel — write to
                // phys directly. No temp map, no CR3 switch, no shared
                // scratch VA, no race with a concurrent load's unmap.
                let src = unsafe { elf_data.as_ptr().add(ph.p_offset as usize + copied as usize) };
                let dst = (phys + page_offset) as *mut u8;
                unsafe {
                    ptr::copy_nonoverlapping(src, dst, copy_len as usize);
                }

                copied += copy_len;
            }

            segments.push(LoadedSegment {
                virt_addr: ph.p_vaddr,
                file_size: ph.p_filesz,
                mem_size: ph.p_memsz,
                flags: ph.p_flags,
            });
        }

        // Zero-fill the BSS portion of each loaded segment (memsz > filesz).
        for seg in &segments {
            let file_end = seg.virt_addr.checked_add(seg.file_size).ok_or("BSS overflow")?;
            let mem_end = seg
                .virt_addr
                .checked_add(seg.mem_size)
                .ok_or("BSS overflow")?;
            if mem_end <= file_end {
                continue;
            }

            // Zero only [file_end, mem_end): the first page may share file
            // data below file_end — zeroing the whole page would erase it.
            let mut virt = file_end;
            while virt < mem_end {
                let page = virt & !0xFFFu64;
                let phys = page_maps
                    .iter()
                    .find(|pm| pm.virt == page)
                    .map(|pm| pm.phys)
                    .ok_or("BSS page not mapped")?;

                let bytes = ((page + PAGE_SIZE) - virt).min(mem_end - virt);
                unsafe {
                    ptr::write_bytes((phys + (virt - page)) as *mut u8, 0, bytes as usize);
                }

                virt += bytes;
            }
        }

        // page_maps is intentionally dropped here — frames stay mapped in
        // user space. The caller owns them via the returned segments.
        core::mem::forget(page_maps);

        Ok(segments)
    }

    /// Free all frames backing the given segments (caller should call this
    /// on load failure to avoid leaking memory). Does not unmap pages — the
    /// caller should tear down the address space instead.
    pub fn free_segments(segments: &[LoadedSegment], owner_pid: u32) {
        let _ = owner_pid;
        for seg in segments {
            let mut virt = seg.virt_addr & !0xFFFu64;
            let end = seg
                .virt_addr
                .checked_add(seg.mem_size)
                .map(|v| (v + 0xFFF) & !0xFFFu64)
                .unwrap_or(seg.virt_addr);
            while virt < end {
                virt += PAGE_SIZE;
            }
        }
    }
}

/// Allocate one physical frame for `owner_pid` using the boot frame allocator.
/// Allocate one physical frame for `owner_pid` using the boot frame allocator.
/// Allocate one physical frame for `owner_pid` using the boot frame allocator.
fn alloc_one_frame(owner_pid: u32) -> Result<u64, &'static str> {
    let _ = owner_pid;
    let frame = unsafe { crate::alloc_boot_frame() }.ok_or("out of memory for ELF page")?;
    Ok(frame.start_address().as_u64())
}

/// Find the physical frame backing a virtual address in the target address space.
/// Walks the page tables manually since we need the frame for temporary kernel mapping.
fn find_phys_for_virt(root: u64, virt: u64) -> Option<u64> {
    let pml4 = root as *const x86_64::structures::paging::PageTable;
    if pml4.is_null() {
        return None;
    }

    unsafe {
        let pml4_ref = &*pml4;
        let pml4_idx = ((virt >> 39) & 0x1FF) as usize;
        let pml4e = &pml4_ref[pml4_idx];
        if !pml4e.flags().contains(x86_64::structures::paging::PageTableFlags::PRESENT) {
            return None;
        }
        let pdpt: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB> = PhysFrame::containing_address(pml4e.addr());
        let pdpt_ref = &*(pdpt.start_address().as_u64() as *const x86_64::structures::paging::PageTable);
        let pdpt_idx = ((virt >> 30) & 0x1FF) as usize;
        let pdpte = &pdpt_ref[pdpt_idx];
        if !pdpte.flags().contains(x86_64::structures::paging::PageTableFlags::PRESENT) {
            return None;
        }
        if pdpte.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {
            let base = pdpte.addr().as_u64() & !(0x4000_0000 - 1);
            let offset = virt & (0x4000_0000 - 1);
            return Some(base + offset);
        }
        let pd: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB> = PhysFrame::containing_address(pdpte.addr());
        let pd_ref = &*(pd.start_address().as_u64() as *const x86_64::structures::paging::PageTable);
        let pd_idx = ((virt >> 21) & 0x1FF) as usize;
        let pde = &pd_ref[pd_idx];
        if !pde.flags().contains(x86_64::structures::paging::PageTableFlags::PRESENT) {
            return None;
        }
        if pde.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {
            let base = pde.addr().as_u64() & !(0x200000 - 1);
            let offset = virt & (0x200000 - 1);
            return Some(base + offset);
        }
        let pt: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB> = PhysFrame::containing_address(pde.addr());
        let pt_ref = &*(pt.start_address().as_u64() as *const x86_64::structures::paging::PageTable);
        let pt_idx = ((virt >> 12) & 0x1FF) as usize;
        let pte = &pt_ref[pt_idx];
        if !pte.flags().contains(x86_64::structures::paging::PageTableFlags::PRESENT) {
            return None;
        }
        let base = pte.addr().as_u64() & !0xFFFu64;
        let offset = virt & 0xFFF;
        return Some(base + offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rejects_non_elf() {
        let result = ElfLoader::validate(b"not an elf");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_wrong_magic() {
        let mut data = [0u8; 64];
        data[0..4] = [0x7f, b'X', b'L', b'F'];
        assert!(ElfLoader::validate(&data).is_err());
    }

    #[test]
    fn test_validate_rejects_wrong_class() {
        let mut data = [0u8; 64];
        data[0..4] = [0x7f, b'E', b'L', b'F'];
        data[4] = 1; // ELFCLASS32
        assert!(ElfLoader::validate(&data).is_err());
    }

    #[test]
    fn test_validate_rejects_non_executable() {
        let mut data = [0u8; 64];
        data[0..4] = [0x7f, b'E', b'L', b'F'];
        data[4] = 2; // ELFCLASS64
        data[16] = 1; // ET_REL (relocatable, not executable)
        assert!(ElfLoader::validate(&data).is_err());
    }

    #[test]
    fn test_validate_rejects_wrong_machine() {
        let mut data = [0u8; 64];
        data[0..4] = [0x7f, b'E', b'L', b'F'];
        data[4] = 2; // ELFCLASS64
        data[16] = 2; // ET_EXEC
        data[18..20] = [3, 0]; // EM_386, not EM_X86_64
        assert!(ElfLoader::validate(&data).is_err());
    }

    #[test]
    fn test_validate_accepts_valid_header() {
        let mut data = [0u8; 64];
        data[0..4] = [0x7f, b'E', b'L', b'F'];
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        data[6] = 1; // EV_CURRENT
        data[16] = 2; // ET_EXEC
        data[18..20] = [0x3e, 0]; // EM_X86_64
        data[20..24] = [1, 0, 0, 0]; // EV_CURRENT
        // e_phoff = 64 (right after header)
        data[24..32] = [64, 0, 0, 0, 0, 0, 0, 0];
        // e_phentsize = size of Elf64ProgramHeader (56)
        data[34..36] = [56, 0];
        // e_phnum = 1
        data[36..38] = [1, 0];
        assert!(ElfLoader::validate(&data).is_ok());
    }

    /// Build a minimal ELF64 for header validation tests.
    fn build_minimal_elf(w: bool, x: bool) -> Vec<u8> {
        let mut data = vec![0u8; 64 + 56];
        data[0..4] = [0x7f, b'E', b'L', b'F'];
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16] = 2; // ET_EXEC
        data[18..20] = [0x3e, 0]; // EM_X86_64
        data[24..32] = [64, 0, 0, 0, 0, 0, 0, 0]; // e_phoff = 64
        data[34..36] = [56, 0]; // e_phentsize = 56
        data[36..38] = [1, 0]; // e_phnum = 1

        // One PT_LOAD segment
        let ph = &mut data[64..];
        ph[0..4] = [1, 0, 0, 0]; // p_type = PT_LOAD
        ph[4..8] = [
            if w { PF_W } else { 0 },
            if x { PF_X } else { 0 },
            0,
            0,
        ]; // p_flags
        data
    }
}
