//! ELF64 loader for user programs (static `ET_EXEC`, x86-64).
//!
//! `parse` validates an image and lists its `PT_LOAD` segments without
//! touching memory; `load` maps them into an address space. Policy enforced
//! here, not trusted from the file:
//!
//! - every loadable segment is page-aligned, inside the user image window,
//!   and not both writable and executable (W^X);
//! - file ranges lie inside the image, `filesz <= memsz`, segments don't overlap;
//! - the entry point is inside an executable segment;
//! - pages get exactly the segment's permissions (no X -> `NO_EXECUTE`),
//!   bytes past `filesz` are zero (bss).
//!
//! Status: `partial` — loads the GRUB-module test programs in QEMU.

use heapless::Vec;
use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};

use crate::{alloc_boot_frame, map_page_in};

/// User image window inside the per-process slot (PML4 index 1).
pub const USER_IMAGE_BASE: u64 = 0x0000_0080_0000_0000;
pub const USER_IMAGE_END: u64 = 0x0000_0080_3F00_0000;

const PAGE: u64 = 4096;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

#[derive(Clone, Copy, Debug)]
pub struct Segment {
    pub vaddr: u64,
    pub memsz: u64,
    pub offset: u64,
    pub filesz: u64,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug)]
pub struct ElfImage {
    pub entry: u64,
    pub segments: Vec<Segment, 8>,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Validate `bytes` as a loadable user program.
pub fn parse(bytes: &[u8]) -> Result<ElfImage, &'static str> {
    const TRUNC: &str = "truncated ELF";
    if bytes.get(0..4) != Some(b"\x7fELF".as_slice()) {
        return Err("not an ELF file");
    }
    if bytes.get(4) != Some(&2) || bytes.get(5) != Some(&1) || bytes.get(6) != Some(&1) {
        return Err("not ELF64 little-endian v1");
    }
    if u16_at(bytes, 16).ok_or(TRUNC)? != 2 {
        return Err("not ET_EXEC (static executable)");
    }
    if u16_at(bytes, 18).ok_or(TRUNC)? != 0x3E {
        return Err("not x86-64");
    }
    let entry = u64_at(bytes, 24).ok_or(TRUNC)?;
    let phoff = u64_at(bytes, 32).ok_or(TRUNC)? as usize;
    let phentsize = u16_at(bytes, 54).ok_or(TRUNC)? as usize;
    let phnum = u16_at(bytes, 56).ok_or(TRUNC)? as usize;
    if phentsize != 56 {
        return Err("unexpected program header size");
    }

    let mut segments: Vec<Segment, 8> = Vec::new();
    for i in 0..phnum {
        let ph = phoff.checked_add(i * phentsize).ok_or(TRUNC)?;
        if u32_at(bytes, ph).ok_or(TRUNC)? != PT_LOAD {
            continue;
        }
        let flags = u32_at(bytes, ph + 4).ok_or(TRUNC)?;
        let seg = Segment {
            offset: u64_at(bytes, ph + 8).ok_or(TRUNC)?,
            vaddr: u64_at(bytes, ph + 16).ok_or(TRUNC)?,
            filesz: u64_at(bytes, ph + 32).ok_or(TRUNC)?,
            memsz: u64_at(bytes, ph + 40).ok_or(TRUNC)?,
            writable: flags & PF_W != 0,
            executable: flags & PF_X != 0,
        };
        if seg.writable && seg.executable {
            return Err("segment is both writable and executable (W^X)");
        }
        if seg.vaddr % PAGE != 0 {
            return Err("segment not page-aligned");
        }
        if seg.filesz > seg.memsz {
            return Err("segment filesz > memsz");
        }
        let end = seg.vaddr.checked_add(seg.memsz).ok_or("segment overflows")?;
        if seg.vaddr < USER_IMAGE_BASE || end > USER_IMAGE_END {
            return Err("segment outside the user image window");
        }
        let file_end = seg.offset.checked_add(seg.filesz).ok_or(TRUNC)?;
        if file_end > bytes.len() as u64 {
            return Err("segment file range past end of image");
        }
        let page_end = (end + PAGE - 1) & !(PAGE - 1);
        if segments
            .iter()
            .any(|s| seg.vaddr < ((s.vaddr + s.memsz + PAGE - 1) & !(PAGE - 1)) && s.vaddr < page_end)
        {
            return Err("overlapping segments");
        }
        segments.push(seg).map_err(|_| "too many segments")?;
    }
    if segments.is_empty() {
        return Err("no loadable segments");
    }
    if !segments
        .iter()
        .any(|s| s.executable && entry >= s.vaddr && entry < s.vaddr + s.memsz)
    {
        return Err("entry point not in an executable segment");
    }
    Ok(ElfImage { entry, segments })
}

/// Map every segment of a parsed image into `root`. Returns pages mapped.
pub fn load(root: PhysFrame<Size4KiB>, bytes: &[u8], image: &ElfImage) -> Result<u64, &'static str> {
    let mut pages = 0;
    for seg in &image.segments {
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if seg.writable {
            flags |= PageTableFlags::WRITABLE;
        }
        if !seg.executable {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        let mut va = seg.vaddr;
        while va < seg.vaddr + seg.memsz {
            let frame = unsafe { alloc_boot_frame() }.ok_or("out of memory loading ELF")?;
            let dst = frame.start_address().as_u64() as *mut u8;
            unsafe { core::ptr::write_bytes(dst, 0, PAGE as usize) };
            // Copy the part of [offset, offset + filesz) that lands on this page.
            let page_off = va - seg.vaddr;
            if page_off < seg.filesz {
                let n = (seg.filesz - page_off).min(PAGE) as usize;
                let src = &bytes[(seg.offset + page_off) as usize..][..n];
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, n) };
            }
            map_page_in(root.start_address().as_u64(), va, frame.start_address().as_u64(), flags);
            pages += 1;
            va += PAGE;
        }
    }
    Ok(pages)
}
