# Locking and interrupt-assumption audit (2026-10-18)

This audit prepares fix 2 (run long system calls with interrupts on) and, after it, SMP. It lists every piece of shared kernel state, what protects it today, and what breaks once system calls can be preempted.

**Status: `partial`.** The audit was done by reading the code. Three hazards found here were fixed in the same change (below). The plan for fix 2 is not implemented.

## How the kernel is synchronized today

1. **Single CPU.** Nothing else runs at the same time unless an interrupt arrives.
2. **System calls run with interrupts off for their whole duration.** `int 0x80` enters through an interrupt gate, so no timer, keyboard or serial interrupt can arrive mid-call. That makes every call atomic with respect to every other process.
3. **Kernel threads (init) run with interrupts on and can be preempted in ring 0.** The trap-frame scheduler already saves and resumes ring-0 frames: `schedule` stores `frame_rsp` whatever the ring. So "preemptible kernel code" already exists: it is init (ledger persistence, the shell supervisor and reaping).
4. **Interrupt handlers never spin on a lock that preemptible code can hold.** The scheduler uses `try_lock_processes` and backs off.

The danger pattern is a plain spin lock taken **both** by preemptible code (init, interrupts on) and by code with interrupts off (system calls or handlers). If init is preempted while holding it, the next taker spins forever with interrupts off, and the kernel hangs.

## Inventory

| State | Where | Protection today | Taken with IF on? | Taken with IF off? | Verdict |
|---|---|---|---|---|---|
| Process table | `process.rs` `ProcessTable` | spin lock **plus interrupts off** (`locked`, `ProcessGuard`); scheduler uses `try_lock` | yes (init) | yes | safe |
| Ledger ring | `governance::LEDGER` | spin lock; every user wraps it in `without_interrupts` / `irq_off` | yes | yes | safe |
| Ledger persistence state | `governance::PERSIST` | ~~plain spin lock~~ → **`IrqMutex`** | yes (`persist_flush`, init) | yes (`ledger_get_any` from `AX_GET_EVIDENCE`, `unflushed`) | **was a hazard, fixed** |
| Signing key | `governance::SIGNER` | plain spin lock | yes (signing in `persist_flush`) | no (boot and persistence only) | safe today; needs `IrqMutex` or a sleeping lock if a syscall ever signs |
| Crash-injection point | `governance::CRASH` | plain spin lock | yes | no | safe (test only) |
| ATA bus | `ata::PORT_LOCK` | spin lock plus interrupts off, per command | yes | yes | safe |
| Drive sizes | `ata::DRIVE_SECTORS` | ~~plain spin lock~~ → **atomics** | yes (identify at boot) | yes (`select`, `flush_on`, FS `sectors()`) | **latent hazard, fixed** |
| File system | `fsys::STATE` | spin lock plus interrupts off (`with_fs`); `mount` takes it with IF on at boot, before any user process | boot only | yes | safe today. Fix 2 needs a sleeping lock. |
| Program load buffer | `fsys::LOAD_BUF` (256 KiB `static mut`) | none; relies on the spawn syscall being atomic | no | yes | safe today. **Breaks under fix 2:** two spawns from files would share it. |
| Console input ring | `console::INPUT/HEAD/TAIL` | single producer (IRQ1/IRQ4/tick) and single consumer (`sys_read`), all IF off, atomics | no | yes | safe |
| Console output ring | `console::TX*` | producers `serial_out` and consumer IRQ4/tick, all expected IF off; atomics | **one caller**: `crash_if` (now disables interrupts first) | yes | safe after this change |
| VGA mirror | `console::ROW/COL/BASE` (`static mut`) | same callers as `serial_out` (IF off) | no | yes | safe |
| Keyboard modifiers | `console::SHIFT/CAPS` | IRQ1 and tick only | no | yes | safe |
| Frame allocator | `BOOT_FRAME_ALLOCATOR` | `irq_off` around every call | yes | yes | safe |
| Kernel stacks | `NEXT_KERNEL_STACK`, `FREE_KERNEL_STACK_SLOTS` | `without_interrupts` / `irq_off` | yes | yes | safe |
| Kernel heap | `EARLY_HEAP` (bump, no free) | **none** | boot only | no | latent: safe only while nothing allocates after boot. It must be locked before any runtime use. |
| Shared kernel page tables | `KERNEL_PML4`, `map_4kib_page` | callers run with IF off (stack allocation) or at boot | boot | yes | safe today; review for fix 2 |
| TSS RSP0, current PID | `gdt::TSS`, `CURRENT_PID` | written only in the scheduler (IF off) | no | yes | safe |
| Tick and latency counters | `TICKS`, `latency::*` | atomics, IF off | no | yes | safe. Under fix 2, syscall timing must count only interrupts-off time. |
| Hooks, boot info, APIC base | `Once`, write-once statics | written before user code runs | boot | read | safe |

## Hazards found and fixed in this change

1. **`PERSIST` could hang the kernel.**
   - The init thread takes the lock with interrupts on while saving the ledger.
   - `AX_GET_EVIDENCE` takes the same lock from inside a system call, for records older than the in-memory ring.
   - If init was preempted inside one of its short critical sections and a program then asked for an old record, that call would spin forever with interrupts off. The window is a few instructions per save, but it is real.
   - It is now an `IrqMutex` (new `sync.rs`): a spin lock that keeps interrupts off while held, so its holder cannot be preempted.
2. **`DRIVE_SECTORS` had the same shape** (a lock written with IF on at identify, read inside system calls). It is now two atomics.
3. **Buffered serial output lost the last words before a halt.**
   - The crash-injection message, and anything printed just before "no runnable process", stayed in the transmit ring when the CPU halted.
   - A crash-injection run showed it: no `CRASH INJECTION` line, although recovery proved the crash happened.
   - Every final halt now calls `console::serial_sync()`: the panic handler, `crash_if`, `exit_current` with nothing runnable, and `idle_forever`.

Verified in QEMU:
- the self-tests pass;
- `axiom.crash=torn-target` now prints `[ledger] CRASH INJECTION (TornTarget) …`;
- the next boot reports `recovery: replayed complete journal`;
- `ledger-tool fs-verify` gives PASS.

## What fix 2 must change

Fix 2 runs `ax_fs_*` and spawn system calls with interrupts on. The order matters.

1. **System-call entry.** Enable interrupts inside the selected long calls only, after argument copying and the rights check, and disable them again before returning.
   - Everything else stays atomic.
   - The trap frame and the scheduler already support preemption in ring 0, as init shows.
2. **File-system lock: a sleeping lock, not `irq_off`.**
   - A caller that finds the FS busy blocks: a new wait reason, woken when the lock is released.
   - The holder can be preempted.
   - ATA commands keep their own short interrupts-off section (`PORT_LOCK`).
3. **`LOAD_BUF`.** Hold the FS lock for the whole load-and-spawn, or give each spawn its own buffer (frames). The second is preferable.
4. **Ledger appends from preemptible syscalls.** These already use `irq_off`; they stay correct and short.
5. **Rights checks and process lookups.** These already use the interrupt-safe process-table lock. Note that a process's rights can change between the check at entry and the work, if another process delegates or revokes rights. Today rights only change at spawn, so this is not a problem yet. It becomes one when revocation exists.
6. **Latency accounting.** Time only the interrupts-off part of each syscall. Otherwise preempted time is reported as interrupts-off time.
7. **Tests.**
   - Two processes writing files at the same time, and one spawning from `/path` while another installs.
   - Then `fs-verify` and the ledger audit.
   - `lat` should show `ax_fs_*` and spawn no longer holding interrupts off for their whole run.

## For SMP later

Every "safe because single CPU and IF off" verdict above becomes "unsafe" on SMP. That covers the console rings, the VGA mirror, `LOAD_BUF`, the bump heap, the `static mut` scheduler state and the TSS, which must become one per CPU.

The `IrqMutex` locks stay correct on SMP for state shared with interrupt handlers. Per-CPU data (current PID, TSS, scheduler queue) and a real heap are prerequisites for SMP.
