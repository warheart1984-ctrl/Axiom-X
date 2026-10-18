# Axiom-X on Hyper-V (hardware virtualization) — 2026-10-18

**Claim:** the same kernel and ISO tested under QEMU boot unchanged in a
Microsoft Hyper-V Generation 1 VM (hardware-assisted virtualization, real
CPU execution, a different BIOS and different device emulation). The VM
passes every self-check. It also verified and continued the signed evidence
ledger that the QEMU boots wrote: the resulting disk verifies off-machine
as one signed chain across both hypervisors.

**Status:** `partial`. Demonstrated: boot, ring 3, preemption, ELF loading,
process lifecycle, governance and audit, crash-safe signed persistence, all
on Hyper-V. Not demonstrated: bare-metal hardware; SMP; accurate timekeeping
(see the timer note below).

## Environment

| Item | Value |
|------|-------|
| Host | Windows 10 Pro for Workstations 10.0.19045, AMD FX-8350 |
| Hypervisor | Hyper-V, Generation 1 VM: BIOS, 1 vCPU, 256 MB static RAM, no network |
| Devices | DVD = ISO (IDE 1:0); ledger disk = fixed VHD (IDE 0:0, primary master); COM1 = `\\.\pipe\axiomx-com1` |
| ISO | sha256 `fa6502d0164eff799d2a2a221e72de8a9655c865fef208d2e0db1c1e583e3b4f` |
| kernel.elf | sha256 `f3026bbdd0720dd2f01faa4f223444594e1a98db5c7c015b2a9c82fc9262a40e` (the crash-safety build) |
| Signing key (public) | `5b82c607bffbf55da01a58b242584edb208cb412e030244ddfc7b7c579705f8a` |

KVM was not an option: `/dev/kvm` exists in WSL2, but this host passes no
nested virtualization through ("No such device").

## Reproduce

```bash
# once (no admin): fixed-VHD copy of the ledger disk
wsl -d Ubuntu-24.04 qemu-img convert -f raw -O vpc -o subformat=fixed,force_size=on evidence/ledger.img evidence/hyperv/ledger-hyperv.vhd
# elevated PowerShell (Run as administrator):
powershell -ExecutionPolicy Bypass -File .\hyperv-run.ps1 -Cleanup
# verify off-machine (no admin):
target\release\ledger-tool.exe verify evidence\hyperv\ledger-hyperv.vhd <public-key>
```

## Observed (`hyperv-serial-2026-10-18.log`, captured from the first byte)

```text
YAXIOM-X BOOT                         <- 'Y' from the 32-bit trampoline, then Rust
  Memory regions: 6                   <- Hyper-V BIOS map (QEMU's has 7)
  Boot modules: 9
[ledger] signing key provisioned; public key 5b82c607...5f8a
[ledger] boot 4: verified 3797 persisted records from genesis and the checkpoint signature; resuming chain at seq 3797 (head df22ba5045d43056...); ...; 10 checkpoints archived
hello from ring 3 ... ring 3: kernel pointer refused with -EFAULT
[kernel] pid=3 killed: page fault in ring 3 ...  (and elf-crash: killed by signal 11)
[audit] chain intact: 400 records ... ledger audit: PASS          (both rounds)
[init] process-lifecycle check: PASS                              (both rounds)
[ledger] persisted 718 new records to disk / persisted 717 new records to disk
[kernel] reclamation check: PASS (frames in use after each round: 281)
```

No kernel panic or double fault. The only faults are the two intended
ring-3 ones per round.

Off-machine, on the Windows host, with only the public key:
```text
superblock: copy A (generation 12), 5232 records, 4 boots, 12 checkpoints archived
hash chain: internally consistent from genesis, matches superblock head
checkpoint signature: Valid
checkpoint archive: 12 signed checkpoints verified; each is a prefix of the current chain
PASS: 5232 records verified from genesis (4 BOOT records, 40 denies) ...
```

Boots 1–3 ran under QEMU (TCG); boot 4 ran under Hyper-V. They form one
chain.

## Differences from QEMU (TCG)

- Sleep wake order followed the deadlines exactly in both rounds (fast @400
  ms before slow @500 ms). Under TCG, woken sleepers lagged behind the
  CPU-bound spinners for a few slices.
- More context switches during the run (504 vs 324): the CPU runs at real
  speed, so more work fits in each slice.
- **Timer note (unconfirmed):** by the end of the ~90 s capture the kernel had
  counted ~3,175 PIT ticks, about 32 s at 100 Hz. The capture window also
  covers the VM's BIOS boot and GRUB, and the kernel has no wall-clock
  reference, so tick loss is not established. Checking it needs a time base
  (CMOS RTC or TSC) to compare against.

## Setup issues found (fixed in `hyperv-run.ps1`)

- `qemu-img` output on this tree is NTFS-*compressed*, because
  `G:\Project Finish` has compression enabled and files inherit it. Hyper-V
  refuses compressed disks ("must be uncompressed and unencrypted and must
  not be sparse", 0xC03A001A).
- The script now:
  - turns compression off for `evidence\hyperv\` only;
  - stages a fresh ISO copy there;
  - refuses to start if either file is compressed, encrypted or sparse.
