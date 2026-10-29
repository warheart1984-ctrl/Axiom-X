//! Ring-3 programs: embedded user binaries started as concurrent processes.
//!
//! Each program gets its own address space (private PML4 user slot, shared
//! kernel half), its own guarded kernel stack, and is mapped at the *same*
//! user virtual address, so they can only coexist if address spaces really
//! are per-process. They all run at once under the preemptive scheduler:
//!
//! 1. `hello`: `write(1, "hello from ring 3\n")`, then `write(1, <kernel
//!    pointer>, 8)`, which must return `-EFAULT`; reports it and `exit(0)`.
//! 2. `probe`: loads from a kernel address directly; the supervisor-only
//!    mapping must page-fault in ring 3 and the kernel kills it (code 139).
//! 3. `spin-A`, 4. `spin-B`: busy loops that never yield; each prints a tick
//!    5 times then exits. Interleaved A/B ticks can only come from timer
//!    preemption, since neither ever blocks or yields.
//!
//! Status: `partial` — exercised in QEMU; programs are embedded blobs, not ELF.

use core::arch::global_asm;
use core::ptr::addr_of;
use core::sync::atomic::Ordering;

use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use axiom_x_arch::process::{Process, ProcessState};

use crate::{alloc_boot_frame, alloc_kernel_stack, frames_in_use, map_page_in, new_address_space, serial_puts};
use crate::elf_loader::ElfLoader;

/// User code page (PML4 slot 1), identical in every process.
const USER_CODE_VA: u64 = 0x0000_0080_0000_0000;
/// User stack page, 1 MiB above the code; stack grows down from page end.
const USER_STACK_VA: u64 = 0x0000_0080_0010_0000;

/// Busy-loop iterations between spinner ticks (several 10 ms slices in QEMU).
macro_rules! spin_program {
    ($tag:literal) => {
        concat!(
            ".global user_spin_", $tag, "_start\n",
            ".global user_spin_", $tag, "_end\n",
            "user_spin_", $tag, "_start:\n",
            "    mov r12d, 5\n",
            "spin_", $tag, "_loop:\n",
            "    mov ecx, 4000000\n",
            "spin_", $tag, "_busy:\n",
            "    dec ecx\n",
            "    jnz spin_", $tag, "_busy\n",
            "    mov eax, 1\n",
            "    mov edi, 1\n",
            "    lea rsi, [rip + spin_", $tag, "_msg]\n",
            "    lea rdx, [rip + spin_", $tag, "_msg_end]\n",
            "    sub rdx, rsi\n",
            "    int 0x80\n",
            "    dec r12d\n",
            "    jnz spin_", $tag, "_loop\n",
            "    mov eax, 60\n",
            "    xor edi, edi\n",
            "    int 0x80\n",
            "spin_", $tag, "_hang:\n",
            "    jmp spin_", $tag, "_hang\n",
            "spin_", $tag, "_msg: .ascii \"[user ", $tag, "] tick\\n\"\n",
            "spin_", $tag, "_msg_end:\n",
            "user_spin_", $tag, "_end:\n",
        )
    };
}

// Position-independent programs: data is addressed RIP-relatively, so the
// bytes can be copied to any page.
global_asm!(
    ".section .rodata.user_programs, \"a\"",
    ".global user_hello_start",
    ".global user_hello_end",
    ".global user_probe_start",
    ".global user_probe_end",
    "user_hello_start:",
    // write(1, msg, len)
    "    mov eax, 1",
    "    mov edi, 1",
    "    lea rsi, [rip + uh_msg]",
    "    lea rdx, [rip + uh_msg_end]",
    "    sub rdx, rsi",
    "    int 0x80",
    // write(1, kernel image, 8) must be refused with -EFAULT (-14)
    "    mov eax, 1",
    "    mov edi, 1",
    "    movabs rsi, 0xFFFF800000100000",
    "    mov edx, 8",
    "    int 0x80",
    "    cmp rax, -14",
    "    jne uh_fail",
    "    mov eax, 1",
    "    mov edi, 1",
    "    lea rsi, [rip + uh_ok]",
    "    lea rdx, [rip + uh_ok_end]",
    "    sub rdx, rsi",
    "    int 0x80",
    "    xor edi, edi",
    "    jmp uh_exit",
    "uh_fail:",
    "    mov edi, 1",
    "uh_exit:",
    "    mov eax, 60",
    "    int 0x80",
    "uh_hang:",
    "    jmp uh_hang",
    "uh_msg: .ascii \"hello from ring 3\\n\"",
    "uh_msg_end:",
    "uh_ok: .ascii \"ring 3: kernel pointer refused with -EFAULT\\n\"",
    "uh_ok_end:",
    "user_hello_end:",
    "user_probe_start:",
    // Direct load from a supervisor-only kernel page: must #PF from ring 3.
    "    movabs rax, 0xFFFF800000100000",
    "    mov rax, [rax]",
    // Only reached if isolation is broken.
    "    mov eax, 60",
    "    mov edi, 2",
    "    int 0x80",
    "up_hang:",
    "    jmp up_hang",
    "user_probe_end:",
    spin_program!("A"),
    spin_program!("B"),
);

extern "C" {
    static user_hello_start: u8;
    static user_hello_end: u8;
    static user_probe_start: u8;
    static user_probe_end: u8;
    static user_spin_A_start: u8;
    static user_spin_A_end: u8;
    static user_spin_B_start: u8;
    static user_spin_B_end: u8;
}

struct UserProgram {
    name: &'static str,
    start: *const u8,
    end: *const u8,
}

fn programs() -> [UserProgram; 4] {
    unsafe {
        [
            UserProgram { name: "hello", start: addr_of!(user_hello_start), end: addr_of!(user_hello_end) },
            UserProgram { name: "probe", start: addr_of!(user_probe_start), end: addr_of!(user_probe_end) },
            UserProgram { name: "spin-A", start: addr_of!(user_spin_A_start), end: addr_of!(user_spin_A_end) },
            UserProgram { name: "spin-B", start: addr_of!(user_spin_B_start), end: addr_of!(user_spin_B_end) },
        ]
    }
}

/// Top of every ELF program's user stack (stack grows down; the page below
/// the lowest mapped stack page is left unmapped).
const ELF_STACK_TOP: u64 = 0x0000_0080_4000_0000;
const ELF_STACK_PAGES: u64 = 4;

/// The user-space init program the kernel starts each round; it spawns the
/// other boot modules itself through `AX_SPAWN_MODULE` and reaps them with
/// `wait4`.
const USER_INIT_MODULE: &str = "elf-init";

use axiom_x_arch::governance::{self, Rights};

/// Rights the kernel grants the embedded regression programs: console only.
const EMBEDDED_RIGHTS: Rights = Rights::SEND;

/// Private heap region: slot 1, well above ELF segments (~0x8000_0000_0000)
/// and the 4-page stack under 0x8040_0000_0000. `AX_MMAP` grows upward.
const USER_HEAP_BASE: u64 = 0x0000_0081_0000_0000;
/// Per-process heap cap: bounds a governed ALLOC right, not a hard limit.
const USER_HEAP_MAX: u64 = 32 * 1024 * 1024;

/// Per-pid heap cursor; 128 live processes max, entries are per-boot
/// (freed address spaces are not recycled by pid).
static mut HEAP_CURSORS: heapless::Vec<(u32, u64), 128> = heapless::Vec::new();

/// Per-process frame quota: total frames a process may own (page tables,
/// segment pages, kernel stack, heap). A bounded right, not just binary.
const FRAME_QUOTA: u64 = 16384; // 64 MiB
static mut OWNED_FRAMES: heapless::Vec<(u32, u64), 128> = heapless::Vec::new();

fn owned(pid: u32) -> Option<u64> {
    unsafe { &*core::ptr::addr_of!(OWNED_FRAMES) }
        .iter()
        .find(|(p, _)| *p == pid)
        .map(|(_, n)| *n)
}

fn owned_add(pid: u32, n: i64) {
    let v = unsafe { &mut *core::ptr::addr_of_mut!(OWNED_FRAMES) };
    match v.iter_mut().find(|(p, _)| *p == pid) {
        Some(e) => e.1 = (e.1 as i64 + n).max(0) as u64,
        None => {
            if n > 0 {
                let _ = v.push((pid, n as u64));
            }
        }
    }
}

/// `AX_MMAP` backend: map `len` bytes of zeroed RW/NX user memory into the
/// caller's slot-1 heap region. Runs under the caller's page tables but
/// writes PTEs by physical address, so no CR3 dance is needed.
fn mmap_hook(pid: u32, len: u64) -> i64 {
    use axiom_x_arch::syscall::{EINVAL, ENOMEM, ENOSYS};
    if len == 0 || len > USER_HEAP_MAX {
        return -EINVAL;
    }
    let bytes = (len + 4095) & !4095u64;
    let cursors = unsafe { &mut *core::ptr::addr_of_mut!(HEAP_CURSORS) };
    let idx = match cursors.iter().position(|(p, _)| *p == pid) {
        Some(i) => i,
        None => {
            if cursors.push((pid, USER_HEAP_BASE)).is_err() {
                return -ENOMEM;
            }
            cursors.len() - 1
        }
    };
    let base = cursors[idx].1;
    let pages = bytes / 4096;
    if base - USER_HEAP_BASE + bytes > USER_HEAP_MAX
        || owned(pid).unwrap_or(0) + pages > FRAME_QUOTA
    {
        return -ENOMEM;
    }
    let Some(root) = axiom_x_arch::interrupts::process_table()
        .with_locked(|ps| ps.iter().find(|p| p.pid == pid).map(|p| p.page_table_root.start_address().as_u64()))
    else {
        return -ENOSYS;
    };
    for i in 0..(bytes / 4096) {
        let Some(frame) = (unsafe { crate::alloc_boot_frame() }) else {
            return -ENOMEM;
        };
        let phys = frame.start_address().as_u64();
        unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096) };
        map_page_in(root, base + i * 4096, phys, user_rw());
    }
    cursors[idx].1 = base + bytes;
    owned_add(pid, pages as i64);
    base as i64
}

/// COM2: the governed egress channel. Requests go out framed as
/// "AXEG" + len64 + payload; the host proxy replies "RESP" + len64 +
/// payload. Every call is a ledgered governed action (Rights::NET).
const COM2: u16 = 0x2f8;
const EGRESS_REQ_MAX: usize = 4096;
const EGRESS_RESP_MAX: usize = 8192;
const EGRESS_TIMEOUT_NS: u64 = 30_000_000_000;

fn com2_write(bytes: &[u8]) {
    for &b in bytes {
        while unsafe { axiom_x_arch::inb(COM2 + 5) } & 0x20 == 0 {}
        unsafe { axiom_x_arch::outb(COM2, b) };
    }
}

fn com2_read_exact(buf: &mut [u8], deadline: u64) -> bool {
    for slot in buf.iter_mut() {
        loop {
            if unsafe { axiom_x_arch::inb(COM2 + 5) } & 0x01 != 0 {
                *slot = unsafe { axiom_x_arch::inb(COM2) };
                break;
            }
            if axiom_x_arch::clock::monotonic_ns() > deadline {
                return false;
            }
        }
    }
    true
}

/// Per-pid egress token bucket: the NET right grants the ability to
/// petition; the rate limit bounds it. `BURST` petitions may go
/// back-to-back; thereafter `RATE` per second.
const EGRESS_RATE_PER_SEC: u32 = 2;
const EGRESS_BURST: u32 = 4;
static mut EGRESS_BUCKETS: heapless::Vec<(u32, u64, u32), 128> = heapless::Vec::new();

fn egress_allow(pid: u32, now: u64) -> bool {
    let v = unsafe { &mut *core::ptr::addr_of_mut!(EGRESS_BUCKETS) };
    let idx = match v.iter().position(|(p, _, _)| *p == pid) {
        Some(i) => i,
        None => {
            if v.push((pid, now, EGRESS_BURST)).is_err() {
                return false;
            }
            v.len() - 1
        }
    };
    let (_, last, tokens) = &mut v[idx];
    // Advance `last` only by the whole seconds actually spent — a caller
    // retrying below the 1 s quantum must still accumulate them.
    let secs = (now - *last) / 1_000_000_000;
    if secs > 0 {
        *tokens = (*tokens + secs as u32 * EGRESS_RATE_PER_SEC).min(EGRESS_BURST);
        *last += secs * 1_000_000_000;
    }
    if *tokens == 0 {
        return false;
    }
    *tokens -= 1;
    true
}

/// `AX_EGRESS` backend: frame the request to COM2, wait for the framed
/// response, copy it into the caller's buffer. Runs under the caller's
/// page tables, so user VAs copy directly.
/// One petition at a time: concurrent callers' COM2 writes would
/// interleave mid-frame and corrupt the channel protocol.
static EGRESS_LOCK: spin::Mutex<()> = spin::Mutex::new(());

fn egress_hook(pid: u32, req_ptr: u64, req_len: u64, resp_ptr: u64, resp_max: u64) -> i64 {
    use axiom_x_arch::syscall::{EAGAIN, EFAULT, EINVAL, EIO, user_range_accessible};
    if req_len == 0 || req_len > EGRESS_REQ_MAX as u64 || resp_max == 0 || resp_max > EGRESS_RESP_MAX as u64 {
        return -EINVAL;
    }
    if !egress_allow(pid, axiom_x_arch::clock::monotonic_ns()) {
        return -EAGAIN;
    }
    let _channel = EGRESS_LOCK.lock();
    if !user_range_accessible(req_ptr, req_len, false) || !user_range_accessible(resp_ptr, resp_max, true) {
        return -EFAULT;
    }
    static mut REQ: [u8; EGRESS_REQ_MAX] = [0; EGRESS_REQ_MAX];
    static mut RESP_BUF: [u8; 16384] = [0; 16384];
    unsafe {
        core::ptr::copy_nonoverlapping(req_ptr as *const u8, core::ptr::addr_of_mut!(REQ) as *mut u8, req_len as usize);
    }
    // Both sides of the petition carry the same content hash — the kernel
    // ledger and the gateway ledger can attest the same request bytes.
    let req_hash = axiom_x_ledger::sha256::sha256(unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(REQ) as *const u8, req_len as usize)
    });
    serial_print!(
        "[egress] pid {} petition sha256 {:016x}..\n",
        pid,
        u64::from_be_bytes(req_hash[..8].try_into().unwrap())
    );
    com2_write(b"AXE2");
    com2_write(&req_len.to_le_bytes());
    com2_write(unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(REQ) as *const u8, req_len as usize)
    });
    com2_write(&req_hash);

    let deadline = axiom_x_arch::clock::monotonic_ns() + EGRESS_TIMEOUT_NS;
    let mut magic = [0u8; 4];
    let mut status = [0u8; 1];
    let mut lenb = [0u8; 8];
    if !com2_read_exact(&mut magic, deadline)
        || !com2_read_exact(&mut status, deadline)
        || !com2_read_exact(&mut lenb, deadline)
        || &magic != b"RSP2"
    {
        return -EIO;
    }
    if status[0] != 0 {
        serial_print!("[egress] pid {} petition status {}\n", pid, status[0]);
    }
    let resp_len = u64::from_le_bytes(lenb) as usize;
    let attestable = resp_len <= 16384;
    // Read the WHOLE frame, not just what fits the caller's buffer: the
    // proxy signed all resp_len bytes, and the signature trailer follows
    // them — reading only the caller's share desyncs the stream and the
    // attestation.
    let frame = if attestable { resp_len } else { resp_len.min(resp_max as usize).min(16384) };
    if !com2_read_exact(unsafe { &mut RESP_BUF[..frame] }, deadline) {
        return -EIO;
    }
    // Oversized frame: drain the rest so the trailer/next frame stays aligned.
    let mut left = resp_len.saturating_sub(frame);
    while left > 0 {
        let chunk = left.min(16384);
        if !com2_read_exact(unsafe { &mut RESP_BUF[..chunk] }, deadline) {
            return -EIO;
        }
        left -= chunk;
    }
    let n = resp_len.min(resp_max as usize).min(frame);
    unsafe {
        core::ptr::copy_nonoverlapping(RESP_BUF.as_ptr(), resp_ptr as *mut u8, n);
    }
    // Wire digest: sha256 over the whole response payload — the kernel
    // verifies it before trusting the signature. A corrupted frame is -EIO,
    // not silent bad data.
    let mut wire_digest = [0u8; 32];
    if !com2_read_exact(&mut wire_digest, deadline) {
        return -EIO;
    }
    if attestable {
        let mine = axiom_x_ledger::sha256::sha256(unsafe { &RESP_BUF[..resp_len] });
        if mine != wire_digest {
            serial_print!("[egress] pid {} frame digest mismatch — wire corruption\n", pid);
            return -EIO;
        }
    }
    // Attestation trailer: 64-byte Ed25519 signature over
    // sha256(request) || sha256(response), when the proxy is keyed.
    let mut sig = [0u8; 64];
    if attestable && com2_read_exact(&mut sig, deadline) {
        // The syscall record is appended right after this hook returns, so
        // it takes the ledger's next seq.
        let egress_seq = governance::ledger_summary().0;
        governance::record_egress_attest(pid, egress_seq, &req_hash, &wire_digest, &sig);
        serial_print!("[egress] pid {} attestation: proxy sig recorded (seq {})\n", pid, egress_seq);
    }
    n as i64
}

/// Rights the kernel grants user-space init. Everything any process can
/// ever hold descends from this set: init can only pass on subsets.
const INIT_RIGHTS: Rights = Rights::new(
    Rights::SEND.bits() | Rights::SPAWN.bits() | Rights::DELEGATE.bits() | Rights::EVIDENCE.bits() | Rights::ALLOC.bits() | Rights::NET.bits() | Rights::READ.bits() | Rights::WRITE.bits(),
);

/// Ledger the grant for a process the kernel itself created (the rights
/// were set at creation, before it could run).
fn kernel_grant(pid: u32, rights: Rights) {
    governance::record_create(0, pid, rights, true, pid as i64);
}

/// Lowercase hex of the first 8 bytes of a digest (for logs).
fn short_hex(d: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in d[..8].iter().enumerate() {
        out[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
        out[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
    }
    out
}

/// Map an embedded blob (one code page + one stack page) into a new
/// address space and start it.
fn spawn_embedded(prog: &UserProgram) {
    let len = prog.end as usize - prog.start as usize;
    assert!(len <= 4096, "user program larger than one page");

    let root = new_address_space();
    let code = unsafe { alloc_boot_frame() }.expect("frame for user code").start_address().as_u64();
    let stack = unsafe { alloc_boot_frame() }.expect("frame for user stack").start_address().as_u64();
    unsafe {
        // Frames are written through the identity map: the code page is
        // not user-writable, so the kernel fills it before mapping.
        core::ptr::write_bytes(code as *mut u8, 0xCC, 4096); // int3 filler
        core::ptr::copy_nonoverlapping(prog.start, code as *mut u8, len);
        core::ptr::write_bytes(stack as *mut u8, 0, 4096);
    }
    // Code: user, read + execute (not writable). Stack: user, RW, no-exec.
    map_page_in(root.start_address().as_u64(), USER_CODE_VA, code, PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE);
    map_page_in(root.start_address().as_u64(), USER_STACK_VA, stack, user_rw());

    let kstack = alloc_kernel_stack();
    let pid = axiom_x_arch::sched::spawn_user_process(
        USER_CODE_VA, USER_STACK_VA + 4096, kstack, root, None, EMBEDDED_RIGHTS, prog.name,
    )
    .expect("create user process");
    // Leak-hunt (a): the process must run on the same PML4 we mapped into.
    let stored = axiom_x_arch::interrupts::process_table()
        .with_locked(|ps| ps.iter().find(|p| p.pid == pid).map(|p| p.page_table_root));
    if stored != Some(root) {
        serial_print!(
            "[kernel] ROOT MISMATCH pid {}: mapped {:#x} stored {:?}\n",
            pid,
            root.start_address().as_u64(),
            stored.map(|f| f.start_address().as_u64())
        );
    }
    kernel_grant(pid, EMBEDDED_RIGHTS);
    serial_print!(
        "[kernel] spawned '{}' as pid {}: {} bytes embedded, PML4 {:#x}\n",
        prog.name, pid, len, root.start_address().as_u64()
    );
}

fn user_rw() -> PageTableFlags {
    PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE
}

/// Validate, load and start an ELF image as a child of `parent` (`None` =
/// the kernel). Returns the PID or a negative errno; a rejected image never
/// becomes a process and leaves nothing allocated.
fn spawn_elf_loader(name: &str, bytes: &[u8], parent: Option<u32>, rights: Rights) -> Result<u32, i64> {
    use axiom_x_arch::syscall::ENOEXEC;
    const ENOMEM: i64 = 12;
    let frames_before = crate::frames_in_use();

    // Validate ELF header
    let (_entry, _phnum) = ElfLoader::validate(bytes).map_err(|why| {
        serial_print!("[kernel] ELF '{}' rejected: {}\n", name, why);
        -ENOEXEC
    })?;

    // Create address space and load segments
    let (mut loader, root) = ElfLoader::new_address_space()
        .map_err(|_| -ENOMEM)?;
    loader.load_segments(bytes, parent.unwrap_or(0))
        .map_err(|why| {
            serial_print!("[kernel] ELF '{}' failed to load: {}\n", name, why);
            crate::free_address_space(PhysFrame::containing_address(PhysAddr::new(root)));
            // ELF-format/permission problems are -ENOEXEC; only genuine
            // frame exhaustion is -ENOMEM.
            if why.contains("frames") { -ENOMEM } else { -ENOEXEC }
        })?;

    // Map stack pages
    for i in 1..=ELF_STACK_PAGES {
        let f = unsafe { alloc_boot_frame() }.ok_or(-ENOMEM)?.start_address().as_u64();
        unsafe { core::ptr::write_bytes(f as *mut u8, 0, 4096) };
        map_page_in(root, ELF_STACK_TOP - i * 4096, f, user_rw());
    }

    let kstack = alloc_kernel_stack();
    let root_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(root));
    let pid = axiom_x_arch::sched::spawn_user_process(
        _entry, ELF_STACK_TOP, kstack, root_frame, parent, rights, name,
    ).map_err(|_| -ENOMEM)?;
    // Leak-hunt (a): same PML4 that the loader mapped into.
    let stored = axiom_x_arch::interrupts::process_table()
        .with_locked(|ps| ps.iter().find(|p| p.pid == pid).map(|p| p.page_table_root));
    if stored != Some(root_frame) {
        serial_print!(
            "[kernel] ROOT MISMATCH pid {}: mapped {:#x} stored {:?}\n",
            pid, root, stored.map(|f| f.start_address().as_u64())
        );
    }
    owned_add(pid, (crate::frames_in_use() - frames_before) as i64);
    serial_print!(
        "[kernel] loaded ELF '{}' as pid {} (parent {}): {} bytes, PML4 {:#x}\n",
        name,
        pid,
        parent.map_or(0, |p| p),
        bytes.len(),
        root
    );
    Ok(pid)
}

/// `AX_SPAWN_MODULE` hook: start the boot module called `name`, or, for a
/// name starting with '/', the program stored in that file (hash-verified
/// on read; the syscall layer has already required READ).
fn spawn_module_hook(name: &str, parent: u32, rights: Rights) -> i64 {
    if name.starts_with('/') {
        return match axiom_x_arch::fsys::with_program(name, |bytes| spawn_elf_loader(name, bytes, Some(parent), rights)) {
            Ok(Ok(pid)) => pid as i64,
            Ok(Err(e)) | Err(e) => e,
        };
    }
    if name == LEDGER_KEY_MODULE {
        // Kernel-only module: not a program, and not even acknowledged.
        return -axiom_x_arch::syscall::ENOENT;
    }
    match crate::boot_modules().iter().find(|m| m.name() == name) {
        None => -axiom_x_arch::syscall::ENOENT,
        Some(m) => match spawn_elf_loader(name, m.bytes(), Some(parent), rights) {
            Ok(pid) => pid as i64,
            Err(e) => e,
        },
    }
}

/// `AX_FS_INSTALL` source: any boot module except the signing key.
fn module_bytes_hook(name: &str) -> Option<&'static [u8]> {
    if name == LEDGER_KEY_MODULE {
        return None;
    }
    crate::boot_modules().iter().find(|m| m.name() == name).map(|m| m.bytes())
}

/// Mount the file system disk (primary slave) and report it. Runs after
/// the ledger is attached, since the mount is checked against its anchors.
pub fn mount_fs() {
    use axiom_x_arch::fsys::{Anchor, MountReport};
    fn hex8(d: &[u8; 32]) -> u64 {
        u64::from_be_bytes(d[..8].try_into().unwrap())
    }
    match axiom_x_arch::fsys::mount() {
        MountReport::NoDisk => serial_puts("[fs] no file-system disk (primary slave): no files
"),
        MountReport::Formatted { sectors, root } => serial_print!(
            "[fs] blank disk ({} sectors) formatted as AXFS; root {:016x}.. anchored in ledger
",
            sectors,
            hex8(&root)
        ),
        MountReport::Mounted { files, root, anchor, writable } => {
            serial_print!("[fs] mounted AXFS: {} files, root {:016x}.., ", files, hex8(&root));
            match anchor {
                Anchor::FirstUse => serial_puts("no ledger anchor yet (first use)"),
                Anchor::Matches(seq) => serial_print!("matches ledger anchor #{}", seq),
                Anchor::Mismatch(seq) => serial_print!(
                    "DOES NOT MATCH ledger anchor #{} (changed outside the kernel)", seq
                ),
            }
            serial_puts(if writable { "; read-write
" } else { "; READ-ONLY
" });
        }
        MountReport::Refused(e) => serial_print!("[fs] disk not mounted: {:?} (left untouched)
", e),
        MountReport::CorruptFile { name, root } => {
            let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            serial_print!(
                "[fs] file '{}' fails its hash check: mounted READ-ONLY; root {:016x}..
",
                core::str::from_utf8(&name[..n]).unwrap_or("?"),
                hex8(&root)
            );
        }
    }
}

/// Release hook: free a reaped process's address space and kernel stack.
/// Called from `wait4` (parent's context) or the kernel reaper, never on
/// the dying thread itself, which is standing on both.
fn release_process(p: &Process) -> u64 {
    let aspace = crate::free_address_space(p.page_table_root);
    let kstack = crate::free_kernel_stack(p.kernel_stack_top);
    let freed = aspace + kstack;
    owned_add(p.pid, -(freed as i64));
    serial_print!(
        "[kernel] release pid {}: aspace {} + kstack {} frames (owned {} / {})\n",
        p.pid, aspace, kstack, owned(p.pid).unwrap_or(0), FRAME_QUOTA
    );
    freed
}

/// Attach the persistent ledger (before this boot appends anything) and
/// report what was found on disk.
pub fn attach_ledger_disk() {
    use axiom_x_arch::governance::{CrashPoint, PersistReport};
    // Fault injection for crash-consistency tests: axiom.crash=<point>.
    for arg in crate::boot_cmdline().split_whitespace() {
        if let Some(name) = arg.strip_prefix("axiom.crash=") {
            match CrashPoint::parse(name) {
                Some(p) => {
                    serial_print!("[ledger] TEST: crash injection armed at '{}'\n", name);
                    governance::set_crash_point(p);
                }
                None => serial_print!("[ledger] unknown axiom.crash point '{}' ignored\n", name),
            }
        }
    }
    // Signing seed resolution: boot module (override). When unset, the
    // disk's own identity sector supplies the seed inside attach_disk.
    let key = take_ledger_key();
    let report = governance::persist_init(key);
    // Report the signer actually in effect — module key, disk identity,
    // or a seed minted for a fresh disk.
    match governance::signer_public() {
        Some(pk) => {
            let mut hex = [0u8; 64];
            for (i, b) in pk.iter().enumerate() {
                hex[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
                hex[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
            }
            serial_print!(
                "[ledger] signing key active; public key {}\n",
                core::str::from_utf8(&hex).unwrap_or("?")
            );
        }
        None => serial_puts("[ledger] no signing key provisioned: checkpoints are unsigned\n"),
    }
    let recovery = match report {
        PersistReport::Resumed { recovery, .. } | PersistReport::Refused { recovery, .. } => Some(recovery),
        _ => None,
    };
    if let Some(r) = recovery {
        if let Some(sector) = r.journal_replayed {
            serial_print!("[ledger] recovery: replayed complete journal into sector {}\n", sector);
        }
        if r.torn_journal_discarded {
            serial_puts("[ledger] recovery: discarded an incomplete journal (target untouched)\n");
        }
        if r.superblock_fallback {
            serial_puts("[ledger] recovery: newer superblock copy damaged; using the older one\n");
        }
    }
    match report {
        PersistReport::NoDisk(e) => {
            serial_print!("[ledger] no disk ({:?}): evidence is memory-only this boot\n", e)
        }
        PersistReport::Formatted { sectors, signed } => serial_print!(
            "[ledger] blank disk ({} sectors) formatted: new chain from genesis (boot 1, {})\n",
            sectors,
            if signed { "signed checkpoint" } else { "unsigned" }
        ),
        PersistReport::Resumed { records, boots, head, was_signed, signed, archived, .. } => {
            let hex = short_hex(&head);
            serial_print!(
                "[ledger] boot {}: verified {} persisted records from genesis{}; resuming chain at seq {} (head {}...){}; {} checkpoints archived\n",
                boots,
                records,
                if was_signed { " and the checkpoint signature" } else { " (checkpoint was unsigned)" },
                records,
                core::str::from_utf8(&hex).unwrap_or("?"),
                if signed { "; signing new checkpoints" } else { "" },
                archived
            )
        }
        PersistReport::Refused { reason, broken_at, .. } => match broken_at {
            Some(seq) => serial_print!(
                "[ledger] REFUSED disk ledger: {} at record {}; disk left untouched, evidence is memory-only\n",
                reason, seq
            ),
            None => serial_print!(
                "[ledger] REFUSED disk ledger: {}; disk left untouched, evidence is memory-only\n",
                reason
            ),
        },
    }
    // Persist the signing identity on the disk itself after a healthy
    // mount — never on a refused disk (it stays untouched).
    if let Some(k) = &governance::signer_seed().or(key) {
        let mounted = matches!(report, PersistReport::Formatted { .. } | PersistReport::Resumed { .. });
        if mounted && governance::read_disk_identity().is_none() {
            if governance::provision_disk_identity(k) {
                serial_puts("[ledger] signing identity written to disk identity sector\n");
            }
        }
    }
}

/// Name of the boot module carrying the 32-byte ledger signing seed.
pub const LEDGER_KEY_MODULE: &str = "ledger.key";

/// Copy the signing seed out of its boot module and wipe the module's
/// memory, so the secret exists only inside the kernel's key object.
fn take_ledger_key() -> Option<[u8; 32]> {
    let m = crate::boot_modules().iter().find(|m| m.name() == LEDGER_KEY_MODULE)?;
    let bytes = m.bytes();
    if bytes.len() != 32 {
        serial_print!("[ledger] '{}' is {} bytes, expected 32: ignored\n", LEDGER_KEY_MODULE, bytes.len());
        return None;
    }
    let seed: [u8; 32] = bytes.try_into().ok()?;
    unsafe {
        let p = m.start as *mut u8;
        for i in 0..32 {
            core::ptr::write_volatile(p.add(i), 0);
        }
    }
    Some(seed)
}

/// Persist the ledger and report it.
fn flush_ledger() {
    match governance::persist_flush() {
        Ok(0) => {}
        Ok(n) => serial_print!("[ledger] persisted {} new records to disk\n", n),
        Err(why) => serial_print!("[ledger] persistence error: {}\n", why),
    }
}

/// Install the hooks the syscall layer needs from the boot crate.
pub fn install_hooks() {
    axiom_x_arch::syscall::set_process_end_hook(on_process_end);
    axiom_x_arch::syscall::set_spawn_hook(spawn_module_hook);
    axiom_x_arch::syscall::set_module_bytes_hook(module_bytes_hook);
    axiom_x_arch::syscall::set_release_hook(release_process);
    axiom_x_arch::syscall::set_mmap_hook(mmap_hook);
    axiom_x_arch::syscall::set_egress_hook(egress_hook);
}

/// Start one round: every embedded program plus the user-space init.
fn spawn_round() -> usize {
    let mut started = 0;
    for prog in &programs() {
        spawn_embedded(prog);
        started += 1;
    }
    match crate::boot_modules().iter().find(|m| m.name() == USER_INIT_MODULE) {
        Some(m) => {
            if let Ok(pid) = spawn_elf_loader(USER_INIT_MODULE, m.bytes(), None, INIT_RIGHTS) {
                kernel_grant(pid, INIT_RIGHTS);
                started += 1;
            }
        }
        None => serial_print!("[kernel] no '{}' boot module\n", USER_INIT_MODULE),
    }
    started
}

/// True once every process except the caller (kernel init) has ended.
fn all_user_processes_ended() -> bool {
    let me = axiom_x_arch::process::current_pid();
    axiom_x_arch::interrupts::process_table()
        .with_locked(|ps| ps.iter().all(|p| p.pid == me || p.state == ProcessState::Terminated))
}

/// Reap zombies that no user process will `wait4` for: children of the
/// kernel, including orphans re-parented to it when their parent ended.
fn reap() -> (u32, u64) {
    let table = axiom_x_arch::interrupts::process_table();
    let dead: heapless::Vec<u32, 64> = table.with_locked(|ps| {
        ps.iter()
            .filter(|p| {
                p.state == ProcessState::Terminated
                    && match p.parent_pid {
                        None => true,
                        // Orphan: the parent is gone or Terminated, so no one
                        // will ever wait4 this record — the kernel reaps it.
                        Some(par) => ps
                            .iter()
                            .find(|parent| parent.pid == par)
                            .map(|parent| parent.state == ProcessState::Terminated)
                            .unwrap_or(true),
                    }
            })
            .map(|p| p.pid)
            .collect()
    });
    let (mut n, mut frames) = (0, 0);
    for pid in dead {
        if let Some(p) = table.remove(pid) {
            let f = release_process(&p);
            governance::record_reap(0, pid, f);
            frames += f;
            n += 1;
        }
    }
    (n, frames)
}

/// Run the whole program set twice, reaping after each round. Equal
/// "frames in use" after both rounds means process teardown, by `wait4`
/// in user space or by the kernel reaper, returns everything allocated.
pub fn run_rounds() {
    let mut after = [0u64; 3];
    for round in 0..3 {
        let before = frames_in_use();
        serial_print!("[kernel] === round {}: frames in use {} ===\n", round + 1, before);
        let started = spawn_round();
        while !all_user_processes_ended() {
            unsafe { core::arch::asm!("hlt") };
            if governance::unflushed() >= FLUSH_BACKLOG {
                flush_ledger_quietly();
            }
        }
        let (n, freed) = reap();
        // Leak-hunt (b): free-list duplicates would let two processes
        // share a frame — scan after every reap.
        let (nodes, ok) = crate::free_list_scan();
        if !ok {
            serial_print!("[kernel] FREE-LIST ANOMALY: {} nodes walked\n", nodes);
        }
        let left = axiom_x_arch::interrupts::process_table().count();
        after[round] = frames_in_use();
        flush_ledger();
        let (records, head) = governance::ledger_summary();
        let hex = short_hex(&head);
        serial_print!(
            "[kernel] ledger: {} records, head {}...\n",
            records,
            core::str::from_utf8(&hex).unwrap_or("?")
        );
        serial_print!(
            "[kernel] round {}: kernel started {}, kernel reaped {} ({} frames); {} process records left; frames in use {} -> {}\n",
            round + 1, started, n, freed, left, before, after[round]
        );
    }
    if after[0] == after[1] && after[1] == after[2] {
        serial_print!("[kernel] reclamation check: PASS (frames in use after each round: {})\n", after[1]);
    } else {
        serial_print!(
            "[kernel] reclamation check: FAIL ({} vs {} vs {} frames)\n",
            after[0], after[1], after[2]
        );
    }
}

/// The interactive shell module and what it may do: talk on the console
/// (SEND + RECV), start programs and pass rights on (SPAWN + DELEGATE),
/// observe processes and the ledger (EVIDENCE), and read and change files
/// (READ + WRITE).
const SHELL_MODULE: &str = "elf-shell";
const SHELL_RIGHTS: Rights = Rights::new(
    Rights::SEND.bits()
        | Rights::RECV.bits()
        | Rights::SPAWN.bits()
        | Rights::DELEGATE.bits()
        | Rights::EVIDENCE.bits()
        | Rights::READ.bits()
        | Rights::WRITE.bits()
        | Rights::ALLOC.bits()
        | Rights::NET.bits(),
);

/// Run the shell on the console forever, restarting it when it exits (like
/// getty), persisting the ledger every few seconds. Returns only if there
/// is no shell module.
pub fn run_shell() {
    let Some(m) = crate::boot_modules().iter().find(|m| m.name() == SHELL_MODULE) else {
        serial_print!("[kernel] no '{}' module: no interactive shell\n", SHELL_MODULE);
        return;
    };
    // The ledger records every syscall regardless; stop echoing each one
    // so the console stays readable (axiom.trace=on keeps the echo).
    if !crate::boot_cmdline().split_whitespace().any(|w| w == "axiom.trace=on") {
        axiom_x_arch::syscall::TRACE.store(false, Ordering::SeqCst);
    }
    loop {
        let Ok(pid) = spawn_elf_loader(SHELL_MODULE, m.bytes(), None, SHELL_RIGHTS) else {
            serial_puts("[kernel] cannot start the shell\n");
            return;
        };
        kernel_grant(pid, SHELL_RIGHTS);
        // Timed by the TSC, not by counting ticks: a host that drops timer
        // interrupts must not stretch the persistence interval.
        let mut last_flush = axiom_x_arch::clock::monotonic_ns();
        while !all_user_processes_ended() {
            unsafe { core::arch::asm!("hlt") };
            let now = axiom_x_arch::clock::monotonic_ns();
            if now - last_flush >= 5_000_000_000 || governance::unflushed() >= FLUSH_BACKLOG {
                flush_ledger_quietly();
                last_flush = now;
            }
        }
        reap();
        flush_ledger_quietly();
        serial_puts("[kernel] shell exited; starting a new one\n");
    }
}

/// Save as soon as this many records are waiting (far below the 4096-record
/// in-memory ring), not only on a timer: a burst such as an audit can
/// append hundreds of records per second.
const FLUSH_BACKLOG: u64 = 256;

/// Persist the ledger without a console line per save (errors still shown).
fn flush_ledger_quietly() {
    if let Err(why) = governance::persist_flush() {
        serial_print!("[ledger] persistence error: {}\n", why);
    }
}

/// Process-end hook (runs with interrupts off, in the ending process's
/// syscall or fault context); the scheduler picks what runs next.
pub fn on_process_end(pid: u32, parent: Option<u32>, code: i32) {
    if !axiom_x_arch::syscall::TRACE.load(Ordering::Relaxed) {
        return; // the shell reports its children itself
    }
    let who = parent.map_or(0, |p| p);
    if code >= 0 {
        serial_print!("[kernel] pid {} (parent {}) exited with code {}\n", pid, who, code);
    } else {
        serial_print!("[kernel] pid {} (parent {}) killed by signal {}\n", pid, who, -code);
    }
}
