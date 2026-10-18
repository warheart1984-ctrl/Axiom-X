# AXFS file system — evidence (2026-10-18)

**Status: `partial`** — runs in QEMU (TCG) on an IDE disk; whole-file
operations only; flat namespace (names may contain `/`); at most 64 files of
up to 256 KiB each; no space reclamation; one writer. Not yet run on Hyper-V
(`hyperv-run.ps1` does not attach a second disk yet).

## What is claimed, and where it is enforced

| Claim | Mechanism | Tag | Evidence |
|-------|-----------|-----|----------|
| A change is atomic: a crash leaves the old or the new version, never a mix | Copy-on-write log. The A/B superblock write is the commit point (`axiom-x-fs`) | enforced (host) | `crash_at_any_point_leaves_old_or_new_state` host test. Not crash-tested in QEMU |
| Every read is checked against the file's SHA-256 | `Fs::read` re-hashes the whole file | enforced | boot 3: `cat log.txt` → `EIO` |
| The file table matches the root hash in the superblock | `Fs::mount` → `TableCorrupt` | enforced (host) | `tampered_table_fails_mount_and_damage_never_formats` host test |
| Every FS change is recorded in the signed ledger | `FS_COMMIT` record carries the new root (kernel `fsys`) | enforced | `fs-verify`: 6 FS_COMMIT |
| A disk changed or rolled back outside the kernel is detected and mounted read-only | At mount, the newest ledger anchor must equal the disk root, otherwise `FS_MOUNT` DENY and read-only | enforced | boot 4 (rollback), boot 3 (corrupt file) |
| File syscalls are rights-checked | 530/531/535 need READ, 532/533/534 need WRITE; spawning from `/path` needs READ | enforced | `elf-noperm`: all 7 calls `EPERM` |
| The signing key cannot be copied into the FS | `module_bytes_hook` refuses `ledger.key` | enforced | boot 1: `install ledger.key /k` → `ENOENT` |
| A disk can be verified off the machine | `ledger-tool fs-verify` | enforced | `fs-verify-2026-10-18.txt` |

## Design

- **Disk:** the IDE primary slave. The ledger is on the master. ATA PIO, LBA28, polled.
- **Layout:**
  - sectors 0 and 1 hold the superblock copies; generation *g* is written to sector *g* % 2;
  - from sector 2 there is an append-only log of file data and file-table versions.
  - Each table entry stores the file's name, size, extent, version and SHA-256.
- **Root hash:** the SHA-256 of the file table. The kernel puts it in `FS_COMMIT` / `FS_MOUNT` ledger records, split over `nr`, `arg`, `rights` and `result`.
- **The ledger as an anchor:** a valid disk is not enough on its own, because its root must also be the newest root the ledger signed.
  - This catches edits behind the kernel's back.
  - It also catches a rollback to an older, fully self-consistent image.
  - An attacker without the ledger key cannot forge the anchor, as shown in `SIGNED-LEDGER-EVIDENCE-2026-10-17.md`.
- **Read-only state:** a mismatch or a corrupt file never causes reformatting or repair. Reads still work; writes return `EROFS`.

## Syscalls

| Nr | Call | Right |
|----|------|-------|
| 530 | `ax_fs_list(buf, max)` — 96-byte entries | READ |
| 531 | `ax_fs_read(name, len, buf, buflen)` → full size | READ |
| 532 | `ax_fs_write(name, len, data, datalen)` | WRITE |
| 533 | `ax_fs_delete(name, len)` | WRITE |
| 534 | `ax_fs_install(module, len, path, len)` | WRITE |
| 535 | `ax_fs_info(buf)` — root, generation, files, writable, free | READ |
| 520 | `ax_spawn_module("/path", …)` — runs an ELF stored in the FS | SPAWN + READ |

Shell (`elf-shell`, now holds READ and WRITE): `ls`, `cat`, `write`, `rm`, `install`, `df`, `run /path`.

## QEMU runs

Five boots used one scratch ledger (`fsl-final.img`) and one scratch FS image. The canonical `evidence/ledger.img` was not touched. All five boots used `axiom.selftest=off`.

| Boot | Disk state | Result | Log |
|------|------------|--------|-----|
| 1 | blank | formatted. Session: write, replace (v2), cat, install `elf-hello` → `/bin/hello`, `run /bin/hello` (exit 0), rm, then `cat` → ENOENT. `install ledger.key` → ENOENT | `fs-boot1-2026-10-18.log` |
| 2 | as left by boot 1 | `matches ledger anchor #283; read-write`. Ran `/bin/hello` from disk; `elf-noperm -send` exit 0; wrote `log.txt` | `fs-boot2-2026-10-18.log` |
| 3 | boot 2's disk with one byte of `log.txt` flipped | `file 'log.txt' fails its hash check: mounted READ-ONLY`. `cat log.txt` → EIO. `/bin/hello` still runs. write/rm → EROFS | `fs-boot3-tamper-2026-10-18.log` |
| 4 | boot 1's disk (rollback, internally valid) | `DOES NOT MATCH ledger anchor #508 (changed outside the kernel); READ-ONLY`. write → EROFS | `fs-boot4-rollback-2026-10-18.log` |
| 5 | boot 2's disk restored | `matches ledger anchor #508; read-write`. `log.txt` reads back; wrote `final.txt`; shell `ledger` verified | `fs-boot5-restored-2026-10-18.log` |
| self-test | fresh ledger and FS | full boot suite: lifecycle, audit and reclamation PASS with the FS disk attached | `fs-selftest-2026-10-18.log` |

The inputs are in `fs-input-1.txt` … `fs-input-5.txt`.

## Off-machine verification (`fs-verify-2026-10-18.txt`)

- **Final images:** `PASS`.
  - The ledger has 1041 records, 5 BOOT records and 12 archived signed checkpoints.
  - The FS table matches its root, and all 3 files match their SHA-256.
  - The root `a021901a…` is the newest anchor (record #787).
  - The anchors are 6 FS_COMMIT, 3 FS_MOUNT allowed and 2 FS_MOUNT refused: boots 3 and 4.
- **Boot 1 image against the final ledger (rollback):** `FAIL … changed or rolled back`, exit 1.
- **Final image with one bit flipped in `final.txt`:** `FAIL: file 'final.txt' does not match its SHA-256`, exit 1.

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG |
| kernel.elf | sha256 `14bad2ce86946cd3905a91954dda5b233a160cb643931eee9e8b4f3a8ed5d22f` (same build for all runs) |
| elf-shell | sha256 `e1667065d67ea7282e0b183f461ebefb5fcd2f07b60cbfc86876a09bd2625af0` (self-test run). Boots 1–5 used earlier builds that differed only in help/`rights`/`df` wording |
| Host tests | `cargo test`: 66 pass, including 8 `axiom-x-fs` tests |

## Reproduce

```bash
# in WSL, after building the kernel and user programs (see qemu-boot.sh)
KERNEL_CMDLINE=axiom.selftest=off LEDGER_DISK=evidence/tmp/l.img FS_DISK=evidence/tmp/fs.img \
  SHELL_INPUT=evidence/fs-input-1.txt sh ./qemu-boot.sh 40
target/release/ledger-tool fs-verify evidence/tmp/fs.img evidence/tmp/l.img "$(target/release/ledger-tool pubkey evidence/ledger.key)"
```

## Known gaps (not claimed)

- No crash injection in QEMU for the FS; crash safety is shown by the host test only.
- No directories, permissions per file, partial reads/writes, or space reclamation.
- The FS lock is held with interrupts off for a whole file operation (up to 256 KiB of PIO).
- Hyper-V: needs a second VHD on IDE 0:1 in `hyperv-run.ps1`.
