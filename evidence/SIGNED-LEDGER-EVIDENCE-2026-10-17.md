# Axiom-X signed evidence ledger — 2026-10-17

**Claim:** the persisted evidence chain carries an Ed25519-signed checkpoint
(a signed tree head over record count, boot count, chain head and signer
key). Anyone holding only the operator's public key can verify, off the
machine, that a disk image holds exactly the history the key holder
attested. At boot the kernel refuses three kinds of disk:

- a disk forged into a *self-consistent* chain (records rewritten, every link
  and the superblock checksum rebuilt);
- a disk signed by a different key;
- a signed disk booted without its key.

In every refused case the disk is left byte-for-byte unchanged.

**Status:** `partial`. Demonstrated:
- Ed25519 and SHA-512 in `no_std` (RFC 8032 and FIPS 180-4 vectors, checked
  independently against OpenSSL and a separate big-integer implementation);
- signed checkpoints on every flush, and verification at boot;
- refusal of forged, wrong-key and key-stripped disks;
- a host-side verifier that needs only the public key.

Not demonstrated:
- hardware-backed keys: the seed is a boot-image module, so whoever can read
  the boot media can sign;
- external anchoring of checkpoints (e.g. a transparency log), so a key
  holder could fork history, and rollback to an *older genuine* signed disk
  is not detected;
- side-channel hardening beyond TweetNaCl's constant-time structure;
- crash-consistent flushes.

## Trust model, stated plainly

| Party | Can | Cannot |
|-------|-----|--------|
| Verifier with the public key | verify any disk image off-machine (`ledger-tool verify`) | — |
| Attacker with disk write access, no seed | read, delete, or roll the disk back to an older genuine image | produce a disk that verifies: changes break the signature (attack A), and a re-signed disk is the wrong key (attack B) |
| Holder of the seed (boot media) | sign anything | — (the seed **is** the authority; protect it like a private key) |

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, `-m 256M`, 4 MiB IDE disk (`cache=writethrough`) |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16) |
| kernel.elf | sha256 `7e052519eef94be3dc0dcfd1476d097af960bd00fcb5768037319e4afeda8d9b` |
| Test signing key (public) | `5b82c607bffbf55da01a58b242584edb208cb412e030244ddfc7b7c579705f8a` |
| Attacker test key (public) | `c59ee0b8a3baa90477dcb5a73b22436992f25cc286aeb0ffadc6784e7f688b7d` |

The seeds are not committed (`*.key` and `evidence/*.img` are git-ignored).

## Reproduce

```bash
cargo test                                         # 55 host tests
cargo build --release -p axiom-x-ledger-tool        # off-machine verifier
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target x86_64-unknown-none && cd ..
rm -f evidence/ledger.img evidence/ledger.key
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 60           # boot 1: generates key, formats, signs
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 60           # boot 2: verifies chain + signature, resumes
target/release/ledger-tool verify evidence/ledger.img $(target/release/ledger-tool pubkey evidence/ledger.key)
```

## Crypto verification (independent of this code)

- `cargo test -p axiom-x-ledger`: SHA-512 FIPS 180-4 vectors; Ed25519 RFC 8032
  §7.1 tests 1–3 (public keys and signatures byte-exact). It also checks that a
  modified message, signature or key is rejected, and that non-canonical
  `S + L` is rejected.
- The same three vectors were reproduced with:
  - **OpenSSL 3.0.13**: public keys for all three; signatures for tests 2 and 3.
    OpenSSL's `pkeyutl` refuses empty input, so it cannot sign test 1's empty
    message.
  - **An independent Python big-integer Ed25519** (RFC 8032 §5.1, `hashlib`
    SHA-512): all three public keys and signatures.
- Curve and SHA-512 constants were derived from their definitions, and match
  the published TweetNaCl and FIPS tables.

## Observed

Boot 1 (fresh disk, fresh key):
```text
[ledger] signing key provisioned; public key 5b82c607...5f8a
[ledger] blank disk (8192 sectors) formatted: new chain from genesis (boot 1, signed checkpoint)
[ledger] persisted 266 new records to disk
[ledger] persisted 663 new records to disk
```

Boot 2:
```text
[ledger] boot 2: verified 929 persisted records from genesis and the checkpoint signature; resuming chain at seq 929 (head 9b0443cb31f9ea1d...); signing new checkpoints
```

Off-machine, on the Windows host, with only the public key:
```text
superblock: 2363 records, 2 boots, head 4562dfc9...a9bb
hash chain: internally consistent from genesis, matches superblock head
checkpoint signature: Valid
PASS: 2363 records verified from genesis (2 BOOT records, 20 denies); head matches the checkpoint signed by 5b82c607...5f8a
```

Attack A: forge record 500 without the key (`ledger-tool forge`):
```text
forged record 500; rebuilt 1863 links and the superblock (new head ca089cca...), old signature kept
hash chain: internally consistent from genesis, matches superblock head     <- the persistence-only kernel would have accepted this
checkpoint signature: Invalid
FAIL: checkpoint not signed by the trusted key
[kernel] REFUSED disk ledger: checkpoint signature does not verify; disk left untouched
```

Attack B: genuine disk, attacker's key:
```text
[kernel] REFUSED disk ledger: checkpoint was signed by a different key; disk left untouched
```

Attack C: genuine disk, no key (signature stripping):
```text
[kernel] REFUSED disk ledger: ledger is signed but no signing key is provisioned; disk left untouched
```

Disk hashes were unchanged across every refused boot. In all five boots,
lifecycle, audit and reclamation passed; in boots 1–2 there were no
kernel-mode exceptions.

## What was added

- `axiom-x-ledger/src/sha512.rs` and `ed25519.rs`:
  - TweetNaCl-style field and group arithmetic (16×16-bit limbs, branch-free
    ladder), `Keypair::from_seed`, `sign`, and `verify`;
  - `verify` is stricter than TweetNaCl: it requires `S < L` and that the
    public key decodes;
  - the secret parts of a key pair are wiped on drop.
- Superblock v2 adds the signer key, a signature over the domain-separated
  `AXIOM-X-LEDGER-CHECKPOINT-V1 || total || boots || head || public key`, and a
  checksum over the first 160 bytes. v1 disks are treated as foreign.
  `SignatureStatus` is Unsigned / Valid / WrongKey / Invalid.
- Kernel:
  - takes the 32-byte seed from the `ledger.key` boot module and wipes the
    module's memory; the module is unspawnable (`-ENOENT`);
  - signs the checkpoint at format time and on every flush;
  - at boot, refuses wrong-key, invalid-signature and key-missing disks
    before verifying the chain;
  - the BOOT record's `nr` holds the first 8 bytes of the signer's public key.
- `axiom-x-ledger-tool` (host, std):
  - `pubkey <seed>`;
  - `verify <image> <pubkey>`, which reports chain consistency and signature
    status separately;
  - `forge <image> <seq>`, test only, which simulates an attacker who has no key.
- `qemu-boot.sh` generates and attaches the key module (`LEDGER_KEY`,
  `LEDGER_KEY=none`).
- The ledger crate is built with `opt-level = 3` even in dev builds; signature
  arithmetic is too slow unoptimized under TCG.

## Known gaps

- Key custody: the seed travels on the boot media, unprotected by a TPM,
  sealing or measured boot.
- Rollback: swapping in an *older genuine* signed image is not detected.
  Detecting it needs an external, monotonic anchor (a published checkpoint log,
  or a counter in secure hardware).
- Only the latest checkpoint is kept. Intermediate signed heads are not
  archived, so a verifier can attest only the most recent state.
- Flushes still happen at round boundaries, with no journal.
