//! Console: one input queue fed by the PS/2 keyboard (IRQ1) and the COM1
//! receiver (IRQ4), and a VGA text-mode screen that mirrors everything
//! written to serial, so the system is usable both from a terminal (serial)
//! and from a VM window (keyboard + screen).
//!
//! Interrupt handlers only push bytes into the queue; they never touch the
//! process table. Readers blocked in `read(0)` are woken by the scheduler
//! on its next tick when input is pending (`has_input`).
//!
//! Status: `partial` — US keyboard layout (scancode set 1: letters, digits,
//! punctuation, Shift, Caps Lock, Enter, Backspace, Tab); no line
//! discipline in the kernel (the shell edits lines); 80x25 text mode only.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::{inb, outb};

// ----------------------------------------------------------------------------
// Input queue (single CPU: written from IRQ handlers, read from syscalls,
// both with interrupts off)
// ----------------------------------------------------------------------------

const INPUT_CAP: usize = 4096;
static mut INPUT: [u8; INPUT_CAP] = [0; INPUT_CAP];
static HEAD: AtomicUsize = AtomicUsize::new(0); // next byte to read
static TAIL: AtomicUsize = AtomicUsize::new(0); // next free slot
/// Bytes dropped because the queue was full.
pub static DROPPED: AtomicU32 = AtomicU32::new(0);

/// Queue a byte from outside an interrupt handler (e.g. one that arrived
/// before the UART was configured).
pub fn push_input(b: u8) {
    push(if b == b'\r' { b'\n' } else { b });
}

fn push(b: u8) {
    let tail = TAIL.load(Ordering::Relaxed);
    let next = (tail + 1) % INPUT_CAP;
    if next == HEAD.load(Ordering::Acquire) {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    unsafe { (*core::ptr::addr_of_mut!(INPUT))[tail] = b };
    TAIL.store(next, Ordering::Release);
}

/// True when at least one input byte is waiting.
pub fn has_input() -> bool {
    HEAD.load(Ordering::Acquire) != TAIL.load(Ordering::Acquire)
}

/// Move up to `out.len()` queued bytes into `out`; returns how many.
pub fn read_into(out: &mut [u8]) -> usize {
    let mut n = 0;
    while n < out.len() && has_input() {
        let head = HEAD.load(Ordering::Relaxed);
        out[n] = unsafe { (*core::ptr::addr_of!(INPUT))[head] };
        HEAD.store((head + 1) % INPUT_CAP, Ordering::Release);
        n += 1;
    }
    n
}

// ----------------------------------------------------------------------------
// Serial receive (COM1, IRQ4)
// ----------------------------------------------------------------------------

const COM1: u16 = 0x3F8;

/// Enable the COM1 "data available" interrupt (the boot path already set
/// OUT2 in the modem control register, which gates the UART's IRQ line).
pub fn enable_serial_rx() {
    outb(COM1 + 1, 0x01);
}

/// IRQ4 body: drain the UART receive FIFO into the queue.
pub fn on_serial_irq() {
    while inb(COM1 + 5) & 0x01 != 0 {
        let b = inb(COM1);
        // Terminals send CR for Enter; the shell expects LF.
        push(if b == b'\r' { b'\n' } else { b });
    }
}

// ----------------------------------------------------------------------------
// PS/2 keyboard (IRQ1), scancode set 1, US layout
// ----------------------------------------------------------------------------

static mut SHIFT: bool = false;
static mut CAPS: bool = false;

const NORMAL: &[u8; 58] = b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
const SHIFTED: &[u8; 58] = b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

/// Decode one scancode; returns the ASCII byte it produces, if any.
pub fn decode_scancode(sc: u8) -> Option<u8> {
    unsafe {
        match sc {
            0x2A | 0x36 => SHIFT = true,           // shift press
            0xAA | 0xB6 => SHIFT = false,          // shift release
            0x3A => CAPS = !CAPS,                  // caps lock press
            s if s & 0x80 != 0 => {}               // other releases
            s if (s as usize) < NORMAL.len() => {
                let c = if SHIFT { SHIFTED[s as usize] } else { NORMAL[s as usize] };
                if c == 0 {
                    return None;
                }
                let c = if CAPS && c.is_ascii_alphabetic() {
                    if SHIFT { c.to_ascii_lowercase() } else { c.to_ascii_uppercase() }
                } else {
                    c
                };
                return Some(c);
            }
            _ => {}
        }
    }
    None
}

/// IRQ1 body: read the scancode and queue the character it produces.
pub fn on_keyboard_irq() {
    let sc = inb(0x60);
    if let Some(c) = decode_scancode(sc) {
        push(c);
    }
}

// ----------------------------------------------------------------------------
// VGA text mode (80x25 at physical 0xB8000, reached via the identity map)
// ----------------------------------------------------------------------------

const VGA: usize = 0xB8000;
const COLS: usize = 80;
const ROWS: usize = 25;
/// Light grey on black.
const ATTR: u16 = 0x07 << 8;

static mut ROW: usize = 0;
static mut COL: usize = 0;
static mut CLEARED: bool = false;

fn cell(row: usize, col: usize) -> *mut u16 {
    (VGA as *mut u16).wrapping_add(row * COLS + col)
}

fn scroll() {
    unsafe {
        for r in 1..ROWS {
            for c in 0..COLS {
                cell(r - 1, c).write_volatile(cell(r, c).read_volatile());
            }
        }
        for c in 0..COLS {
            cell(ROWS - 1, c).write_volatile(ATTR | b' ' as u16);
        }
    }
}

fn update_cursor(row: usize, col: usize) {
    let pos = (row * COLS + col) as u16;
    outb(0x3D4, 0x0F);
    outb(0x3D5, (pos & 0xFF) as u8);
    outb(0x3D4, 0x0E);
    outb(0x3D5, (pos >> 8) as u8);
}

/// Write one byte to the VGA screen (newline, carriage return, backspace
/// and tab handled; other control bytes ignored). Callers hold interrupts
/// off, as every console write path does.
pub fn vga_putc(b: u8) {
    unsafe {
        if !CLEARED {
            // GRUB leaves its menu on screen; start from a clean page.
            for i in 0..ROWS * COLS {
                (VGA as *mut u16).wrapping_add(i).write_volatile(ATTR | b' ' as u16);
            }
            CLEARED = true;
        }
        match b {
            b'\n' => {
                COL = 0;
                ROW += 1;
            }
            b'\r' => COL = 0,
            0x08 => {
                if COL > 0 {
                    COL -= 1;
                    cell(ROW, COL).write_volatile(ATTR | b' ' as u16);
                }
            }
            b'\t' => COL = (COL + 8) & !7,
            0x20..=0x7E => {
                cell(ROW, COL).write_volatile(ATTR | b as u16);
                COL += 1;
            }
            _ => {}
        }
        if COL >= COLS {
            COL = 0;
            ROW += 1;
        }
        if ROW >= ROWS {
            scroll();
            ROW = ROWS - 1;
        }
        update_cursor(ROW, COL);
    }
}
