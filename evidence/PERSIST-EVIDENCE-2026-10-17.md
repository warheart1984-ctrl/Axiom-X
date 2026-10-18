# Axiom-X persistent evidence ledger — 2026-10-17

**Claim:** under QEMU (TCG), the kernel writes its SHA-256 evidence chain to
an IDE disk through its own ATA driver. At the next boot it re-verifies the
entire persisted chain from genesis and continues the same chain: the
sequence carries on and the first new record links to the previous boot's
head. A one-byte modification of the disk is detected at the exact record,
and the kernel then refuses to continue or overwrite the disk (fail closed).

**Status:** `partial`. Demonstrated:
- an ATA PIO driver (identify, read, write, cache flush; polled, bounded);
- a checksummed superblock and record-slot layout;
- boot-time verification from genesis, chain resumption across boots, and
  tamper detection with fail-closed handling;
- user-space audits that read records written by a previous boot from disk.

Not demonstrated:
- signatures: anyone with write access to the disk could rebuild a consistent
  chain from scratch, and nothing outside the machine anchors the head;
- crash consistency: a power cut mid-flush can leave a torn sector, and there
  is no journal yet;
- DMA, LBA48, other buses, real hardware.

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, `-m 256M` |
| Disk | 4 MiB raw image on the primary IDE master (`cache=writethrough`); 8192 sectors |
| Boot | GRUB 2 ISO from CD (`-boot d`), kernel + user-program modules |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16), `x86_64-unknown-none` |
| kernel.elf | sha256 `71d07072906edc028cb6b222bfb523e97808863f0ff9665802dc247650a1d940` |

## Reproduce

```bash
cargo test                       # 45 host tests, incl. axiom-x-ledger store/resume tests
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target x86_64-unknown-none && cd ..
rm -f evidence/ledger.img                     # fresh chain
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 60      # boot 1 (formats)
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 60      # boot 2 (verifies + resumes)
# tamper: change one byte of record 500 (sector 1 + 500/4, slot 500%4, +48 = result field)
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 60      # boot 3 (must refuse)
```

## Files

- `persist-boot1-serial-2026-10-17.log`: boot 1 (blank disk)
- `persist-boot2-serial-2026-10-17.log`: boot 2 (resume)
- `persist-boot3-tampered-serial-2026-10-17.log`: boot 3 (one byte changed on disk)
- `serial-mb2.log` / `qemu-mb2.log`: boot 3 with the `-d int` CPU trace

The disk image itself is not committed (`evidence/*.img` is ignored).

## Observed

Boot 1:
```text
[ledger] blank disk (8192 sectors) formatted: new chain from genesis (boot 1)
[audit] chain intact: 99 records ... ledger audit: PASS
[ledger] persisted 266 new records to disk
[audit] chain intact: 365 records ... ledger audit: PASS
[ledger] persisted 665 new records to disk
[kernel] ledger: 931 records, head 4ec5afda77ba4361...
```

Boot 2, same disk:
```text
[ledger] boot 2: verified 931 persisted records from genesis; resuming chain at seq 931 (head 4ec5afda77ba4361...)
[audit] pid 12: verifying ledger records 630..1030 (of 1030)    <- 630..930 read from disk (written by boot 1)
[audit] chain intact: 400 records, head a93298125b764072... ; ledger audit: PASS
[ledger] persisted 718 new records to disk
...
[kernel] ledger: 2365 records, head 8f3cdfada59303ce...
```

The resumed head equals boot 1's final head. Boot 2's first audit window
spans the reboot boundary at record 931, so its links include the hop from
boot 1's last record to boot 2's BOOT record.

Boot 3: byte at image offset 64560 (record 500, `result` field) changed from `0x f4` to `0x24`:
```text
[ledger] REFUSED disk ledger: persisted chain broken at record 500; disk left untouched, evidence is memory-only
[audit] chain intact: 99 records ... ledger audit: PASS      <- new in-memory chain from genesis
[init] process-lifecycle check: PASS
[kernel] reclamation check: PASS (frames in use after each round: 281)
disk sha256 before boot 3: 637ce7215a9523b2...  after: 637ce7215a9523b2...
```

All three boots: lifecycle PASS (2/2), audit PASS (2/2), reclamation PASS, and no
kernel-mode CPU exceptions. The 4 user-mode faults are the intended `probe` and
`elf-crash` faults.

## What was added

- `axiom-x-ledger/src/store.rs` (host-tested):
  - superblock layout: magic `AXLEDGR1`, version, record count, boot count, head,
    and a SHA-256 of those fields;
  - decoding tells **Blank** (safe to format) apart from **Foreign** and
    **Corrupt** (never format over them);
  - 128-byte record slots, 4 per sector;
  - tests: layout, round-trip, corruption detection, and a simulated two-boot
    resume with a flipped byte detected at the right record.
- `Ledger::resume(total, head)`: continue an existing chain without holding its old
  records in memory (`oldest()` respects the resume point).
- `axiom-x-arch/src/ata.rs`: ATA PIO driver for the primary master, LBA28. Drive
  interrupts are off (nIEN), polls are bounded, and every command runs under one
  lock with interrupts disabled.
- `governance.rs`:
  - `persist_init` (format / verify-from-genesis-and-resume / refuse, plus a BOOT
    record of kind 100);
  - `persist_flush` (read-modify-write of partly filled sectors, then the
    superblock, then a cache flush);
  - `ledger_get_any`, which reads from disk when a record is no longer in memory.
- `AX_GET_EVIDENCE` serves disk-resident records, so `elf-audit` verifies across
  boots unchanged.
- Kernel init attaches the disk before this boot appends anything and flushes after
  each round. `qemu-boot.sh` attaches `evidence/ledger.img` (created if missing;
  override with `LEDGER_DISK`).

## Known gaps

- No signatures or external anchoring: the chain proves internal consistency, not
  origin. Someone who can write the whole disk could replace it with a different
  self-consistent chain.
- Flushes happen at round boundaries. Records appended after the last flush are lost
  on power-off. There is no write-ahead journal and no torn-sector protection.
- The BOOT record kind (100) is kernel-local; `axiom-x-sys::EvidenceType` does not
  list it.
- Capacity is 32,764 records on the 4 MiB image; when it is full, persistence stops
  with a message (records are not overwritten).
