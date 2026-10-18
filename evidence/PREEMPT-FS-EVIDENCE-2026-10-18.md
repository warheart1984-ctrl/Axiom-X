# Fix 2: preemptible file-system and spawn system calls — evidence (2026-10-18)

**Status: `partial`.** Verified in QEMU (TCG) with a concurrent stress test. **Not yet verified on Hyper-V.** Single CPU.

This follows the plan in `LOCKING-AUDIT-2026-10-18.md`.

## Change

- **Preemptible long system calls.** `ax_fs_list/info/read/write/delete/install` and `ax_spawn_module` now run their bodies with interrupts on (`syscall::preemptible`).
  - Entry (rights check, argument fetch) and exit (result, trace, evidence) stay interrupts-off.
  - The thread can be preempted inside the call like a kernel thread: the trap-frame scheduler already saves and resumes ring-0 frames.
- **Kernel yield.** A ring-0 software interrupt, vector 0x81 (`sched::yield_entry`), lets kernel code give up the CPU in the middle of a call.
  - `block_current_on(reason)` marks the thread Blocked and yields.
  - `wake_all(reason)` makes the waiters runnable again.
- **Sleeping FS lock.** `fsys::FsGuard` records the owner PID.
  - A process that finds the lock taken blocks (`WAIT_FS`) and is woken on release; it re-checks in a loop.
  - The check and the block happen with interrupts off, so a wake-up cannot be lost.
  - All file-system access after boot goes through it.
- **Load and spawn from a file.** `fsys::with_program` holds the FS lock across the read into the shared load buffer and the spawn. So two spawns from files cannot overwrite each other's image.
- **Ordering fix found in review.** The `FS_COMMIT` ledger record was appended *after* the FS lock was released.
  - With preemption, two writers could commit in the order A then B but record them as B then A.
  - That would leave an older root as the ledger's newest anchor, and the next mount would refuse the disk (read-only).
  - The anchor is now recorded while the lock is held.
- **`serial_out`** disables interrupts itself, so output is safe from any context.
- **Latency accounting.** A preemptible call is recorded as its interrupts-off segments: the prefix and suffix, which are two rows of count. The report adds the FS lock's acquisitions and how many had to wait.
- **Test programs.**
  - `elf-fswriter`: in 3 rounds, writes 8 files of 3000 bytes with content unique to its PID, round and file, reads them back and compares, then deletes them.
  - `elf-fsstress`: starts two `elf-fswriter` workers at once, plus `/bin/h` from the file system when present, and waits for all of them.
  - The shell's `run` gains `+write` and `+spawn`.

## QEMU results (`fs-stress-qemu-2026-10-18.log`)

The boot ran the full self-tests, then:
- `install elf-hello /bin/h`;
- `lat reset`;
- `run elf-fsstress +read +write +spawn` three times;
- `ls`, `lat`, `df` and `ledger`.

| Check | Result |
|---|---|
| Self-tests | lifecycle, audit and reclamation PASS (both rounds) |
| Stress, 3 runs | each run had 2 writers × 24 writes and read-backs plus 8 deletes, and `/bin/h` spawned from the file system. **0 problems, PASS** every time |
| FS lock contention (first run) | 115 acquisitions, **110 had to wait** (blocked behind a preempted holder, then woken) |
| `sys ax_fs_write` interrupts-off max | **0.13 ms** (was 78 ms in QEMU, 45 ms on Hyper-V) |
| `sys ax_fs_read` / `ax_fs_delete` max | 0.24 ms / 0.10 ms |
| `sys ax_spawn_module` max (including from `/path`) | **0.06 ms** (was 57 ms) |
| `ledger-tool fs-verify` | **PASS**: 2062 records from genesis, signed; 193 FS_COMMIT anchors; the root `d5347833…` is the newest anchor |
| Reboot on the same disks | `mounted AXFS: 1 files, root d5347833…, matches ledger anchor #1800; read-write` |
| Scripted FS harness (`fs-input-1.txt`) | all 16 commands behave as before; `fs-verify` PASS |
| Host tests | 66 pass |

### Remaining interrupts-off region

**A single ATA command.**
- In this QEMU run, one command (a cache flush, which QEMU in writethrough mode turns into a host sync on the Windows drive holding the image) took up to **107 ms**, and the tick gaps followed: max 109 ms, about 32 ticks lost during the stress runs.
- On Hyper-V, ATA commands peaked at about 34 ms.

**Why the fix is not just "interrupts on during disk waits".** Running ATA waits with interrupts on would need the ATA bus lock to tolerate a preempted holder. That in turn needs every disk user to be preemptible: `AX_GET_EVIDENCE` reads old ledger records from disk inside a non-preemptible call, and so does the persistence path. That is the next step.

## Known gap (not new)

A power loss between the disk commit and the `FS_COMMIT` record leaves the disk one version ahead of the ledger. The next mount then refuses it (read-only, anchor mismatch) instead of accepting it. This is the safe direction, and the data is intact, but recovery needs a manual step. Making the anchor durable together with the commit is future work.

## Hyper-V

ISO rebuilt: `evidence/axiom-x-hyperv.iso`, sha256 `bd7f37336fe77eb91e054bf695d2daeee5c2a0861c2b45e3264785a2960c0345`; kernel sha256 `399f271ce69a80eda7dfed06c791418af3efa72103ffe3dacaee3a7465b415cb`.

Suggested run:

```
install elf-hello /bin/h
lat reset
run elf-fsstress +read +write +spawn
lat
```
