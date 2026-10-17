#![no_std]
#![no_main]
#![feature(naked_functions, asm_const, asm)]

extern crate alloc;

use core::arch::asm;

use axiom_x_sys::{syscall, SyscallNumber};
use heapless::Vec;

// Console output via serial port
const COM1: u16 = 0x3F8;

fn serial_putc(c: u8) {
    unsafe {
        while inb(COM1 + 5) & 0x20 == 0 {}
        outb(COM1, c);
    }
}

fn serial_puts(s: &str) {
    for c in s.bytes() {
        serial_putc(c);
    }
}

#[inline]
fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe { asm!("in al, dx", in("dx") port, out("al") value) };
    value
}

#[inline]
fn outb(port: u16, value: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") value) };
}

fn print_banner() {
    serial_puts("\r\n========================================\r\n");
    serial_puts("    Axiom-X Microkernel - Init Process  \r\n");
    serial_puts("========================================\r\n\r\n");
    serial_puts("Initializing userspace...\r\n");
}

fn print_prompt() {
    serial_puts("axiom> ");
}

fn read_line(buf: &mut [u8]) -> usize {
    let mut len = 0;
    loop {
        let c = read_char();
        match c {
            b'\n' | b'\r' => {
                serial_putc(b'\r');
                serial_putc(b'\n');
                break;
            }
            b'\x08' | 0x7F => { // Backspace
                if len > 0 {
                    len -= 1;
                    serial_putc(b'\x08');
                    serial_putc(b' ');
                    serial_putc(b'\x08');
                }
            }
            c if c.is_ascii_graphic() || c == b' ' => {
                if len < 255 {
                    buf[len] = c;
                    len += 1;
                    serial_putc(c);
                }
            }
            _ => {}
        }
    }
    buf[len] = 0;
    len
}

fn read_char() -> u8 {
    unsafe {
        while inb(COM1 + 5) & 0x01 == 0 {}
        inb(COM1)
    }
}

fn execute_command(cmd: &str) {
    let parts: Vec<&str, 8> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }
    
    match parts[0] {
        "help" => {
            serial_puts("Available commands:\r\n");
            serial_puts("  help    - Show this help\r\n");
            serial_puts("  echo    - Echo arguments\r\n");
            serial_puts("  clear   - Clear screen (ANSI)\r\n");
            serial_puts("  exit    - Exit init (halts)\r\n");
            serial_puts("  mem     - Show memory info\r\n");
        }
        "echo" => {
            for arg in &parts[1..] {
                serial_puts(arg);
                serial_puts(" ");
            }
            serial_puts("\r\n");
        }
        "clear" => {
            serial_puts("\x1B[2J\x1B[H"); // ANSI clear
        }
        "exit" => {
            serial_puts("Halting...\r\n");
            loop {
                unsafe { asm!("cli; hlt") };
            }
        }
        "mem" => {
            serial_puts("Memory info: not implemented yet\r\n");
        }
        _ => {
            serial_puts("Unknown command: ");
            serial_puts(parts[0]);
            serial_puts("\r\n");
        }
    }
}

fn sys_write(buf: &[u8]) -> i64 {
    unsafe {
        syscall(1, &[1, buf.as_ptr() as u64, buf.len() as u64, 0, 0, 0])
    }
}

fn sys_exit(code: i32) -> ! {
    unsafe { syscall(60, &[code as u64, 0, 0, 0, 0, 0]) };
    loop { unsafe { asm!("hlt") }; }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    print_banner();
    
    let mut buf = [0u8; 256];
    
    loop {
        print_prompt();
        let len = read_line(&mut buf);
        if len > 0 {
            let cmd = core::str::from_utf8(&buf[..len]).unwrap_or("");
            execute_command(cmd);
        }
    }
}