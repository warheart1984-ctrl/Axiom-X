//! ATA PIO block driver: primary bus, master and slave drives, LBA28, polled.
//!
//! The evidence ledger lives on the master, the file system on the slave.
//! Interrupts from the drives are disabled (nIEN) and IRQ14 stays masked at
//! the PIC; every command polls the status register with a bounded loop, so
//! a missing or wedged drive returns an error instead of hanging the kernel.
//! Each command runs under one lock with interrupts off, so the kernel init
//! thread (flushing) and syscalls (reading evidence, file I/O) never
//! interleave on the shared bus.
//!
//! Status: `partial` — used for the persistent ledger and the file system
//! on QEMU / Hyper-V IDE disks; no DMA, no secondary bus, no LBA48.

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

/// A drive on the primary bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drive {
    Master = 0,
    Slave = 1,
}

impl Drive {
    /// Drive/head register value selecting this drive (CHS form, IDENTIFY).
    fn select_chs(self) -> u8 {
        0xA0 | ((self as u8) << 4)
    }
    /// Drive/head register base with LBA mode set.
    fn select_lba(self) -> u8 {
        0xE0 | ((self as u8) << 4)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtaError {
    NoDrive,
    NotAta,
    Timeout,
    DeviceFault,
    OutOfRange,
}

/// Identified size of each drive (LBA28 sector count).
static DRIVE_SECTORS: Mutex<[Option<u64>; 2]> = Mutex::new([None, None]);
/// Serializes port access across threads and syscalls.
static PORT_LOCK: Mutex<()> = Mutex::new(());

fn with_ports<R>(f: impl FnOnce() -> R) -> R {
    crate::latency::irq_off(crate::latency::Site::AtaCommand, || {
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

/// Detect `drive`. Returns its size in sectors.
pub fn identify_on(drive: Drive) -> Result<u64, AtaError> {
    let sectors = with_ports(|| {
        outb(CONTROL, 0x02); // nIEN: no interrupts from the drives
        outb(DRIVE, drive.select_chs());
        settle();
        outb(SECTOR_COUNT, 0);
        outb(LBA_LO, 0);
        outb(LBA_MID, 0);
        outb(LBA_HI, 0);
        outb(STATUS_CMD, CMD_IDENTIFY);
        settle();
        let s = inb(STATUS_CMD);
        if s == 0 || s == 0xFF {
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
    DRIVE_SECTORS.lock()[drive as usize] = Some(sectors);
    Ok(sectors)
}

/// Sectors on `drive` (None before `identify_on` succeeded).
pub fn sectors_on(drive: Drive) -> Option<u64> {
    DRIVE_SECTORS.lock()[drive as usize]
}

fn select(drive: Drive, lba: u64, cmd: u8) -> Result<(), AtaError> {
    match sectors_on(drive) {
        Some(n) if lba < n && lba < (1 << 28) => {}
        Some(_) => return Err(AtaError::OutOfRange),
        None => return Err(AtaError::NoDrive),
    }
    wait_not_busy()?;
    outb(DRIVE, drive.select_lba() | ((lba >> 24) & 0x0F) as u8);
    settle();
    outb(SECTOR_COUNT, 1);
    outb(LBA_LO, lba as u8);
    outb(LBA_MID, (lba >> 8) as u8);
    outb(LBA_HI, (lba >> 16) as u8);
    outb(STATUS_CMD, cmd);
    settle();
    Ok(())
}

pub fn read_sector_on(drive: Drive, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), AtaError> {
    with_ports(|| {
        select(drive, lba, CMD_READ)?;
        wait_drq()?;
        for chunk in buf.chunks_exact_mut(2) {
            chunk.copy_from_slice(&inw(DATA).to_le_bytes());
        }
        Ok(())
    })
}

pub fn write_sector_on(drive: Drive, lba: u64, buf: &[u8; SECTOR_SIZE]) -> Result<(), AtaError> {
    with_ports(|| {
        select(drive, lba, CMD_WRITE)?;
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

/// Ask `drive` to commit its write cache (QEMU: flush to the image).
pub fn flush_on(drive: Drive) -> Result<(), AtaError> {
    with_ports(|| {
        if sectors_on(drive).is_none() {
            return Err(AtaError::NoDrive);
        }
        outb(DRIVE, drive.select_lba());
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

// The evidence ledger's disk: the primary master.

pub fn identify() -> Result<u64, AtaError> {
    identify_on(Drive::Master)
}

pub fn sectors() -> Option<u64> {
    sectors_on(Drive::Master)
}

pub fn read_sector(lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), AtaError> {
    read_sector_on(Drive::Master, lba, buf)
}

pub fn write_sector(lba: u64, buf: &[u8; SECTOR_SIZE]) -> Result<(), AtaError> {
    write_sector_on(Drive::Master, lba, buf)
}

pub fn flush() -> Result<(), AtaError> {
    flush_on(Drive::Master)
}
