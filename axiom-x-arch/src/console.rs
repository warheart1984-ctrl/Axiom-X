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

fn rx_drain() {
    while inb(COM1 + 5) & LSR_DATA_READY != 0 {
        let b = inb(COM1);
        // Terminals send CR for Enter; the shell expects LF.
        push(if b == b'\r' { b'\n' } else { b });
    }
}

/// IRQ4 body. IRQ4 is edge-triggered at the 8259, so the handler must leave
/// the UART with nothing pending: otherwise its interrupt line stays high,
/// no new edge ever arrives and serial input stalls. So it loops on the
/// interrupt-identification register until it reports "none pending",
/// serving receive (drain into the input queue) and transmit-empty (next
/// byte from the output ring, or switch that interrupt off when the ring
/// is empty). Bounded: if it is still busy after that many rounds (an
/// emulated UART can report transmit-empty again at once), it stops the
/// transmit interrupt and leaves the rest to the tick fallback.
pub fn on_serial_irq() {
    for _ in 0..256 {
        let iir = inb(COM1 + 2);
        if iir & 0x01 != 0 {
            return; // nothing pending: the line is low
        }
        match iir & 0x0E {
            0x04 | 0x0C => rx_drain(),  // data available / character timeout
            0x02 => tx_send_next(),     // transmit holding register empty
            0x06 => {
                inb(COM1 + 5);          // line status
            }
            _ => {
                inb(COM1 + 6);          // modem status
            }
        }
    }
    TX_IRQ_ON.store(false, Ordering::Relaxed);
    outb(COM1 + 1, IER_RX);
    rx_drain();
}

// ----------------------------------------------------------------------------
// Serial transmit (COM1): ring buffer drained by the THR-empty interrupt
// ----------------------------------------------------------------------------
//
// Writing a byte used to mean waiting for the UART, with interrupts off: at
// 115200 baud about 87 us per byte (far more on an emulated port), so one
// console `write` could hold off the timer for hundreds of milliseconds.
// Now output goes into a ring and returns; IRQ4 ("transmit holding register
// empty") sends the next byte, and the timer tick sends one too in case an
// interrupt was missed. Before `enable_async_tx` (early boot, interrupts
// still off) and after `serial_sync` (panic) every byte is written directly.
// Callers run with interrupts off (single CPU), so the ring needs no lock.

const LSR_DATA_READY: u8 = 0x01;
const LSR_THR_EMPTY: u8 = 0x20;
const IER_RX: u8 = 0x01;
const IER_THRE: u8 = 0x02;
const TX_CAP: usize = 16 * 1024;

static mut TX: [u8; TX_CAP] = [0; TX_CAP];
static TX_HEAD: AtomicUsize = AtomicUsize::new(0);
static TX_TAIL: AtomicUsize = AtomicUsize::new(0);
static TX_ASYNC: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Bytes written synchronously because the ring was full.
pub static TX_OVERFLOW_SYNC: AtomicU32 = AtomicU32::new(0);
/// THR-empty interrupt enabled (the drain is running). Tracked here so the
/// write path touches the UART once per burst, not once per byte: every
/// UART access is a host exit on an emulated port (~40 us on Hyper-V).
static TX_IRQ_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn tx_put_sync(b: u8) {
    while inb(COM1 + 5) & LSR_THR_EMPTY == 0 {}
    outb(COM1, b);
}

/// The transmitter is empty: send the next ring byte, or switch the THRE
/// interrupt off when there is nothing left.
fn tx_send_next() {
    let head = TX_HEAD.load(Ordering::Relaxed);
    if head == TX_TAIL.load(Ordering::Acquire) {
        if TX_IRQ_ON.swap(false, Ordering::Relaxed) {
            outb(COM1 + 1, IER_RX);
        }
        return;
    }
    outb(COM1, unsafe { (*core::ptr::addr_of!(TX))[head] });
    TX_HEAD.store((head + 1) % TX_CAP, Ordering::Release);
}

/// Tick fallback for the transmitter: restart the THRE interrupt if output
/// is waiting and it is off, else send a byte if the UART is free.
fn tx_kick() {
    if tx_pending() == 0 {
        return;
    }
    if !TX_IRQ_ON.swap(true, Ordering::Relaxed) {
        outb(COM1 + 1, IER_RX | IER_THRE);
    } else if inb(COM1 + 5) & LSR_THR_EMPTY != 0 {
        tx_send_next();
    }
}

/// Output one byte on COM1 (and the VGA mirror). Call with interrupts off.
pub fn serial_out(b: u8) {
    vga_putc(b);
    if !TX_ASYNC.load(Ordering::Relaxed) {
        tx_put_sync(b);
        return;
    }
    let tail = TX_TAIL.load(Ordering::Relaxed);
    let next = (tail + 1) % TX_CAP;
    if next == TX_HEAD.load(Ordering::Acquire) {
        // Ring full: send the oldest byte now (wait for the UART) to make room.
        let head = TX_HEAD.load(Ordering::Relaxed);
        tx_put_sync(unsafe { (*core::ptr::addr_of!(TX))[head] });
        TX_HEAD.store((head + 1) % TX_CAP, Ordering::Release);
        TX_OVERFLOW_SYNC.fetch_add(1, Ordering::Relaxed);
    }
    unsafe { (*core::ptr::addr_of_mut!(TX))[tail] = b };
    TX_TAIL.store(next, Ordering::Release);
    // Start the interrupt-driven drain if it is not running: enabling the
    // THR-empty interrupt while the register is empty raises IRQ4 at once
    // (delivered when the caller turns interrupts back on).
    if !TX_IRQ_ON.swap(true, Ordering::Relaxed) {
        outb(COM1 + 1, IER_RX | IER_THRE);
    }
}

/// Switch to buffered output (once interrupts will be on to drain it).
pub fn enable_async_tx() {
    TX_ASYNC.store(true, Ordering::SeqCst);
}

/// Back to direct output, flushing what is buffered first (panic path).
pub fn serial_sync() {
    TX_ASYNC.store(false, Ordering::SeqCst);
    loop {
        let head = TX_HEAD.load(Ordering::Relaxed);
        if head == TX_TAIL.load(Ordering::Acquire) {
            break;
        }
        tx_put_sync(unsafe { (*core::ptr::addr_of!(TX))[head] });
        TX_HEAD.store((head + 1) % TX_CAP, Ordering::Release);
    }
    TX_IRQ_ON.store(false, Ordering::Relaxed);
    outb(COM1 + 1, IER_RX);
}

/// Bytes waiting in the transmit ring.
pub fn tx_pending() -> usize {
    (TX_TAIL.load(Ordering::Acquire) + TX_CAP - TX_HEAD.load(Ordering::Acquire)) % TX_CAP
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

const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
/// Status: output buffer full (a byte waits in 0x60).
const PS2_OBF: u8 = 0x01;
/// Status: input buffer full (controller still busy with our last write).
const PS2_IBF: u8 = 0x02;
/// Status: the waiting byte is from the mouse port, not the keyboard.
const PS2_AUX: u8 = 0x20;

/// What `init_ps2` found and set (for the boot log).
#[derive(Clone, Copy, Debug)]
pub struct Ps2Report {
    pub present: bool,
    pub config_before: u8,
    pub config_after: u8,
    /// Keyboard's reply to "enable scanning" (0xFA = ACK), if any.
    pub enable_reply: Option<u8>,
    pub flushed: u32,
}

fn ps2_wait_write() -> bool {
    (0..100_000).any(|_| inb(PS2_STATUS) & PS2_IBF == 0)
}

fn ps2_wait_read() -> Option<u8> {
    (0..100_000).find(|_| inb(PS2_STATUS) & PS2_OBF != 0).map(|_| inb(PS2_DATA))
}

fn ps2_command(cmd: u8) {
    if ps2_wait_write() {
        outb(PS2_STATUS, cmd);
    }
}

fn ps2_flush() -> u32 {
    let mut n = 0;
    while n < 64 && inb(PS2_STATUS) & PS2_OBF != 0 {
        inb(PS2_DATA);
        n += 1;
    }
    n
}

/// Put the 8042 controller in a known state instead of trusting the BIOS:
/// keyboard port on with its interrupt (IRQ1), scancode translation to set
/// 1, mouse port off, scanning enabled, and the output buffer empty, since
/// a byte left waiting there blocks every later IRQ1 (it is edge-triggered).
/// Call with interrupts off, before IRQ1 is unmasked.
pub fn init_ps2() -> Ps2Report {
    let mut r = Ps2Report { present: false, config_before: 0, config_after: 0, enable_reply: None, flushed: 0 };
    if inb(PS2_STATUS) == 0xFF {
        return r; // no controller
    }
    r.present = true;
    ps2_command(0xAD); // disable keyboard port
    ps2_command(0xA7); // disable mouse port
    r.flushed = ps2_flush();
    ps2_command(0x20); // read configuration byte
    let cfg = ps2_wait_read().unwrap_or(0);
    r.config_before = cfg;
    let cfg = (cfg | 0x01 | 0x40) & !0x02 & !0x10; // IRQ1 on, translate, no IRQ12, clock on
    ps2_command(0x60); // write configuration byte
    if ps2_wait_write() {
        outb(PS2_DATA, cfg);
    }
    ps2_command(0x20);
    r.config_after = ps2_wait_read().unwrap_or(0);
    ps2_command(0xAE); // enable keyboard port
    if ps2_wait_write() {
        outb(PS2_DATA, 0xF4); // keyboard: enable scanning
        r.enable_reply = ps2_wait_read();
    }
    r.flushed += ps2_flush();
    r
}

/// Take one keyboard byte if the controller holds one.
fn take_keyboard_byte() {
    let s = inb(PS2_STATUS);
    if s & PS2_OBF == 0 || s & PS2_AUX != 0 {
        return;
    }
    if let Some(c) = decode_scancode(inb(PS2_DATA)) {
        push(c);
    }
}

/// IRQ1 body: queue the character the waiting scancode produces. Checks the
/// status first: the timer may already have taken the byte (`poll_keyboard`).
pub fn on_keyboard_irq() {
    take_keyboard_byte();
}

/// Called on every timer tick (interrupts off). Fallbacks only, so they run
/// every 10th tick (100 ms): pick up a keyboard byte whose IRQ1 was lost,
/// and nudge the serial transmitter the same way. The cursor follows the
/// text at the full tick rate, only when it moved.
pub fn poll_keyboard() {
    static N: AtomicU32 = AtomicU32::new(0);
    if N.fetch_add(1, Ordering::Relaxed) % 10 == 0 {
        take_keyboard_byte();
        rx_drain();
        tx_kick();
    }
    vga_sync_cursor();
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
/// First cell of the visible screen inside VGA text memory. Scrolling moves
/// this window (CRTC start address) instead of copying the screen: one
/// line of writes per newline, and a full copy only when the window reaches
/// the end of the 32 KiB text memory (every few screens).
static mut BASE: usize = 0;
/// Cells of text memory at 0xB8000 (32 KiB of 16-bit cells).
const TEXT_CELLS: usize = 16 * 1024;
/// Cursor moved since the hardware cursor was last set (`vga_sync_cursor`).
static CURSOR_DIRTY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn cell(row: usize, col: usize) -> *mut u16 {
    (VGA as *mut u16).wrapping_add(unsafe { BASE } + row * COLS + col)
}

fn crtc(index: u8, value: u8) {
    outb(0x3D4, index);
    outb(0x3D5, value);
}

fn set_start(base: usize) {
    crtc(0x0C, (base >> 8) as u8);
    crtc(0x0D, (base & 0xFF) as u8);
}

fn scroll() {
    unsafe {
        if BASE + (ROWS + 1) * COLS > TEXT_CELLS {
            // Out of text memory: move the screen (minus its top line) back
            // to the start.
            let vga = VGA as *mut u16;
            for i in 0..(ROWS - 1) * COLS {
                vga.add(i).write_volatile(vga.add(BASE + COLS + i).read_volatile());
            }
            BASE = 0;
        } else {
            BASE += COLS;
        }
        for c in 0..COLS {
            cell(ROWS - 1, c).write_volatile(ATTR | b' ' as u16);
        }
        set_start(BASE);
    }
}

/// Move the hardware cursor to where text is being written, if it moved.
/// Called from the timer tick: the cursor is cosmetic, and setting it for
/// every byte cost four port writes each (a host exit apiece in a VM).
pub fn vga_sync_cursor() {
    if !CURSOR_DIRTY.swap(false, Ordering::Relaxed) {
        return;
    }
    let pos = unsafe { BASE + ROW * COLS + COL } as u16;
    crtc(0x0F, (pos & 0xFF) as u8);
    crtc(0x0E, (pos >> 8) as u8);
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
            BASE = 0;
            set_start(0);
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
        CURSOR_DIRTY.store(true, Ordering::Relaxed);
    }
}
