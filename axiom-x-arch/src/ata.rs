//! ATA PIO block driver: primary bus, master drive, LBA28, polled.
//!
//! Interrupts from the drive are disabled (nIEN) and IRQ14 stays masked at
//! the PIC; every command polls the status register with a bounded loop, so
//! a missing or wedged drive returns an error instead of hanging the kernel.
//! Each command runs under one lock with interrupts off, so the kernel init
//! thread (flushing) and a syscall (reading evidence) never interleave on
//! the ports.
//!
//! Status: `partial` — used for the persistent ledger on QEMU's IDE disk;
//! no DMA, no secondary bus, no LBA48.

use spin::Mutex;

use crate::{inb, inw, outb, outw};

const DATA: u16 = 0x1F0;
const SECTOR_COUNT: u16 = 0x1F2;
const LBA_LO: u16 = 0x1F3;
const LBA_MID: u16 = 0x1F4;
const LBA_HI: u16 = 0x1F5;
const DRIVE: u16 = 0x1F6;
const STATUS_CMD: u16 = 0x1F7;
const CONTROL: u16 = 0x3F6;

const BSY: u8 = 0x80;
const DF: u8 = 0x20;
const DRQ: u8 = 0x08;
const ERR: u8 = 0x01;

const CMD_READ: u8 = 0x20;
const CMD_WRITE: u8 = 0x30;
const CMD_FLUSH: u8 = 0xE7;
const CMD_IDENTIFY: u8 = 0xEC;

/// Bound on status polls before a command is declared failed.
const POLL_LIMIT: u32 = 2_000_000;

pub const SECTOR_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtaError {
    NoDrive,
    NotAta,
    Timeout,
    DeviceFault,
    OutOfRange,
}

/// The identified drive (LBA28 sector count), once `identify` succeeds.
static DRIVE_SECTORS: Mutex<Option<u64>> = Mutex::new(None);
/// Serializes port access across threads and syscalls.
static PORT_LOCK: Mutex<()> = Mutex::new(());

fn with_ports<R>(f: impl FnOnce() -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let _g = PORT_LOCK.lock();
        f()
    })
}

/// ~400 ns settle time: four reads of the alternate status register.
fn settle() {
    for _ in 0..4 {
        inb(CONTROL);
    }
}

fn wait_not_busy() -> Result<u8, AtaError> {
    for _ in 0..POLL_LIMIT {
        let s = inb(STATUS_CMD);
        if s & BSY == 0 {
            return Ok(s);
        }
    }
    Err(AtaError::Timeout)
}

fn wait_drq() -> Result<(), AtaError> {
    for _ in 0..POLL_LIMIT {
        let s = inb(STATUS_CMD);
        if s & BSY != 0 {
            continue;
        }
        if s & (ERR | DF) != 0 {
            return Err(AtaError::DeviceFault);
        }
        if s & DRQ != 0 {
            return Ok(());
        }
    }
    Err(AtaError::Timeout)
}

/// Detect the primary master. Returns its size in sectors.
pub fn identify() -> Result<u64, AtaError> {
    let sectors = with_ports(|| {
        outb(CONTROL, 0x02); // nIEN: no interrupts from the drive
        outb(DRIVE, 0xA0);
        settle();
        outb(SECTOR_COUNT, 0);
        outb(LBA_LO, 0);
        outb(LBA_MID, 0);
        outb(LBA_HI, 0);
        outb(STATUS_CMD, CMD_IDENTIFY);
        settle();
        if inb(STATUS_CMD) == 0 {
            return Err(AtaError::NoDrive);
        }
        wait_not_busy()?;
        if inb(LBA_MID) != 0 || inb(LBA_HI) != 0 {
            return Err(AtaError::NotAta); // ATAPI / SATA signature
        }
        wait_drq()?;
        let mut id = [0u16; 256];
        for w in id.iter_mut() {
            *w = inw(DATA);
        }
        Ok(id[60] as u64 | ((id[61] as u64) << 16))
    })?;
    *DRIVE_SECTORS.lock() = Some(sectors);
    Ok(sectors)
}

/// Sectors on the identified drive (None before `identify` succeeded).
pub fn sectors() -> Option<u64> {
    *DRIVE_SECTORS.lock()
}

fn select(lba: u64, cmd: u8) -> Result<(), AtaError> {
    match sectors() {
        Some(n) if lba < n && lba < (1 << 28) => {}
        Some(_) => return Err(AtaError::OutOfRange),
        None => return Err(AtaError::NoDrive),
    }
    wait_not_busy()?;
    outb(DRIVE, 0xE0 | ((lba >> 24) & 0x0F) as u8);
    settle();
    outb(SECTOR_COUNT, 1);
    outb(LBA_LO, lba as u8);
    outb(LBA_MID, (lba >> 8) as u8);
    outb(LBA_HI, (lba >> 16) as u8);
    outb(STATUS_CMD, cmd);
    settle();
    Ok(())
}

pub fn read_sector(lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), AtaError> {
    with_ports(|| {
        select(lba, CMD_READ)?;
        wait_drq()?;
        for chunk in buf.chunks_exact_mut(2) {
            chunk.copy_from_slice(&inw(DATA).to_le_bytes());
        }
        Ok(())
    })
}

pub fn write_sector(lba: u64, buf: &[u8; SECTOR_SIZE]) -> Result<(), AtaError> {
    with_ports(|| {
        select(lba, CMD_WRITE)?;
        wait_drq()?;
        for chunk in buf.chunks_exact(2) {
            outw(DATA, u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        settle();
        let s = wait_not_busy()?;
        if s & (ERR | DF) != 0 {
            return Err(AtaError::DeviceFault);
        }
        Ok(())
    })
}

/// Ask the drive to commit its write cache (QEMU: flush to the image).
pub fn flush() -> Result<(), AtaError> {
    with_ports(|| {
        if sectors().is_none() {
            return Err(AtaError::NoDrive);
        }
        outb(DRIVE, 0xE0);
        settle();
        outb(STATUS_CMD, CMD_FLUSH);
        settle();
        let s = wait_not_busy()?;
        if s & (ERR | DF) != 0 {
            return Err(AtaError::DeviceFault);
        }
        Ok(())
    })
}
