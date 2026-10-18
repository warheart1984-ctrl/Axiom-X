# Axiom-X crash-safe ledger + checkpoint archive — 2026-10-17

**Claim:** power loss at any of four points inside a ledger save leaves a
disk that the next boot recovers on its own. Recovery means replaying the
write-ahead journal or falling back to the older superblock copy, then
re-verifying the chain from genesis together with the checkpoint signature,
and continuing. Every signed checkpoint is archived, and the off-machine
verifier checks all of them: each must be signed by the trusted key and be a
prefix of the current chain.

**Status:** `partial`. Demonstrated, with power loss simulated by fault
injection under QEMU:
- crash after the journal commit (AfterJournal);
- a torn in-place write over persisted records (TornTarget);
- a crash before the superblock (BeforeSuperblock);
- a torn superblock write (TornSuperblock).

Not demonstrated:
- real power loss or real-disk reordering (QEMU `cache=writethrough`
  serializes writes; real drives need FUA/barriers, and the driver only
  issues FLUSH CACHE);
- crashes inside the journal write itself (handled by the checksum, and
  unit-tested only);
- records of the crashed boot that were not yet saved; they are lost, as
  expected.

## Disk format v3

| Sectors | Content |
|---------|---------|
| 0, 1 | superblock copies A/B; generation g is written to sector g % 2, so a save never overwrites the current copy |
| 2, 3 | journal header (target sector, SHA-256 of data) and journal data (full new sector image) |
| 4–259 | checkpoint archive: one signed checkpoint per sector, written once, never rewritten |
| 260– | record slots, 4 per sector |

Save protocol:
1. Sectors holding only new records are written directly; no superblock
   references them yet.
2. The one sector that already holds persisted records (the partly filled
   last one) goes through the journal: data, header, flush, then the
   in-place write.
3. Archive the signed checkpoint into a fresh sector.
4. Write the *other* superblock copy and flush.
5. Clear the journal.

Boot recovery:
1. Replay a complete journal, or discard a torn one (its target was never
   touched).
2. Pick the newest valid superblock copy.
3. Check the signature, verify the chain from genesis, and resume.

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, 4 MiB IDE disk, `cache=writethrough` |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16) |
| kernel.elf | sha256 `f3026bbdd0720dd2f01faa4f223444594e1a98db5c7c015b2a9c82fc9262a40e` (all crash runs below) |
| Signing key (public) | `5b82c607bffbf55da01a58b242584edb208cb412e030244ddfc7b7c579705f8a` |

## Reproduce

```bash
cargo test                                          # 56 host tests
cargo build --release -p axiom-x-ledger-tool
# kernel + user programs as in qemu-boot.sh; then, in WSL:
rm -f evidence/ledger.img && sh ./qemu-boot.sh 60 && sh ./qemu-boot.sh 60   # baseline
cp evidence/ledger.img evidence/base.img
sh ./crash-test.sh torn-target evidence/base.img    # also: after-journal, before-superblock, torn-superblock
target/release/ledger-tool verify evidence/crash-torn-target-crashed.img <pubkey> --raw   # damage without journal
target/release/ledger-tool verify evidence/crash-torn-target.img <pubkey>                 # after recovery
```

Each crash case starts from the same baseline: 2,362 records over two signed
boots and 6 archived checkpoints. 2,362 is not a multiple of 4, so the next
save must rewrite sector 850 through the journal.

## Results (all on the kernel above)

| Crash point | Crash boot | Off-machine, crashed image | Recovery boot | Off-machine, after |
|-------------|-----------|----------------------------|---------------|--------------------|
| after-journal | halts after journal commit | PASS (journal applied) | `replayed complete journal into sector 850`, resumes at 2362 | PASS, 3797 records, 10 checkpoints |
| torn-target | target half garbage over records 2360–2361 | **`--raw`: chain broken at record 2360**; with journal: PASS | journal replayed into sector 850, resumes at 2362 | PASS, 3796 records, 10 checkpoints |
| before-superblock | records written, no superblock | PASS (old superblock, 2362) | resumes at 2362 (new records ignored) | PASS, 3795 records, 10 checkpoints |
| torn-superblock | new copy half garbage (crash in the boot-time save) | PASS (copy A, generation 6) | `newer superblock copy damaged; using the older one`, resumes at 2362 | PASS, 3795 records, 9 checkpoints |

In every recovery boot: lifecycle 2/2, audit 2/2, reclamation PASS, and no
kernel-mode exceptions.

The torn-target `--raw` row shows the damage was real. Without the journal,
the torn write destroyed already-persisted record 2360. The persistence-only
and signed versions before this would have refused that disk permanently.

## Bugs found by these tests (fixed)

1. **Torn superblock bricked the ledger.**
   - A tear can garble the magic bytes, so the damaged copy decoded as
     *Foreign*, and `pick_superblock` refused any disk with a foreign copy
     even though the other copy was intact.
   - Fix: any valid copy wins, whatever the other copy's state. "Foreign"
     blocks only when no copy is valid.
   - A unit test reproduces the exact torn pattern.
2. **My first torn-write simulation was too gentle.**
   - It garbled only the not-yet-committed second half of the sector, so
     `--raw` passed and proved nothing.
   - It now damages the front of the sector, where persisted slots live.

## Signature regression under v3

- `ledger-tool forge` rebuilds a self-consistent chain and writes a newer
  superblock copy that keeps the old signature. The verifier's result:
  "hash chain: internally consistent", "signature: Invalid", FAIL.
- The kernel refuses the forged disk, an attacker's key, and a missing key.
  The disk is unchanged in all three.

## Archive verification

`store::verify_archive` and `ledger-tool verify` check each archived
checkpoint:
- valid signature by the trusted key;
- record count never decreasing;
- signed head equal to the chain's digest at that record count, i.e. the
  attested chain is a prefix of the current one.

Unit tests cover a fork that the key holder validly signed (rejected as
`NotAPrefix`) and a rollback in the archive order (`NotMonotonic`).

## What changed

- `axiom-x-ledger/src/store.rs`: format v3 (A/B superblocks with generation
  and archive count, `pick_superblock`, `JournalHeader`, `Checkpoint` with
  archive encoding, `verify_archive`), with 7 store tests including the
  torn-superblock regression.
- `governance.rs`:
  - journaled save, boot recovery (`Recovery` report), checkpoint
    archiving, and A/B superblock writes;
  - fault injection (`CrashPoint`, set only from the kernel command line
    `axiom.crash=`).
- Boot: keeps the multiboot2 command line, arms `axiom.crash=`, and reports
  recovery actions and the archive count.
- `ledger-tool`: v3 support, virtual journal replay (`--raw` to skip it),
  and archive verification.
- `qemu-boot.sh` takes `KERNEL_CMDLINE`. `crash-test.sh` (new) runs crash +
  recovery.

## Known gaps

- Rollback: an attacker with disk write access can damage the newest
  superblock copy to make the kernel use the previous one (a one-save
  rollback), or restore an older genuine image. Signatures do not prevent
  this; an external monotonic anchor would.
- On real hardware, ordering needs FUA or flushes around each step. The
  driver flushes after the journal and after the superblock, but has not
  been tested against a real drive's write cache.
- The 256-entry archive stops growing when full (the superblock keeps
  advancing).
