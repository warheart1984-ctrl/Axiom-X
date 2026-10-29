# Axiom-X egress response attestation — 2026-10-29

**Claim:** after a governed `AX_EGRESS` petition, the kernel SHA-256s the
response bytes it actually read from the host proxy (the unframed payload,
not the `RESP` + u64le header) and (a) logs

```text
[egress] pid N response sha256 <16 hex>.. (<len>B)
```

and (b) appends that digest to the evidence ledger as `EGRESS_RESPONSE`
(kind 103), immediately after the petition's `CONTRACT_ENFORCE` record.

**Tag: `enforced`.** Host tests cover the hash and the record layout. A
QEMU boot against a local stub upstream shows the kernel line, the proxy
line, and the persisted ledger record carrying the same prefix and length.
This capture did **not** use a live llm-gateway. That comparison is still
for Jon; the kernel path is the same one.

## What is hashed

Both sides hash the payload only.

| Direction | Frame | Bytes hashed |
|-----------|--------|----------------|
| guest → proxy | `AXEG` + u64le length + payload | payload |
| proxy → guest | `RESP` + u64le length + payload | payload |

`tools/egress-proxy.py` already hashed `forward()`'s body, which is what
it then frames. No proxy hash change was required. A comment on
`sha256_hex` records the rule. The kernel used to stop reading at the
caller's buffer and would have hashed a shorter string (and left the rest
of the frame on COM2) if the response outgrew that buffer. It now reads
the whole payload, up to the proxy's 64 KiB cap, hashes all of it, and
copies what fits.

The existing `CONTRACT_ENFORCE` record cannot hold a 32-byte digest (its
fields are the syscall number, argument, and result). Kind 103 stores the
digest the same way an FS root does: little-endian across `nr`, `arg`,
`rights`, and `result`. `subject` is the payload length. `pid` is the
petitioner.

## Environment

| Item | Value |
|------|--------|
| Emulator | QEMU 8.2.2 (TCG), `-m 256M` |
| Toolchain | rustc 1.101.0-nightly (92ffebece 2026-10-28), `x86_64-unknown-none` |
| Upstream | `tools/egress-stub.py` on 127.0.0.1:8081, no `EGRESS_GATEWAY_KEY` |
| Disks | scratch only: `evidence/tmp/egress-stub-ledger.img`, `evidence/tmp/egress-stub-fs.img` |
| Signing seed | `evidence/tmp/egress-stub-ledger.key` (not committed) |
| Public key | `0b3dcb49e8cba87d6d785031bbc94082ce1b56475873d78034e2b9cf544157ae` |
| Knobs | defaults: burst 4, workload 25, probes 8, rounds 3 |

`evidence/ledger.key` was not created.

## Reproduce

```bash
cargo test
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel \
    --no-default-features --features freestanding
(cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false \
    cargo build --release --target x86_64-unknown-none)
LEDGER_KEY=evidence/tmp/egress-stub-ledger.key \
LEDGER_DISK=evidence/tmp/egress-stub-ledger.img \
FS_DISK=evidence/tmp/egress-stub-fs.img \
EGRESS_STUB=1 sh ./qemu-boot.sh 240
```

Host tests added in `axiom-x-ledger`: command-line defaults, the 10/10
knobs, unframed-vs-framed SHA-256, and the response record linking into
the chain. `cargo test` — 70 tests passed.

## Observed

Stub body is `{"stub":"axiom-x-egress","echo":true}\n` (38 bytes).
SHA-256 prefix `e8332cfb5642e5e1`.

```text
[egress] burst 4 rate 2/s; workload petitions 25; egress probes 8; rounds 3
[egress] pid 10 petition sha256 d1bba6bee60f1d77..
[egress] pid 10 response sha256 e8332cfb5642e5e1.. (38B)
[syscall] pid=10 ax_egress(nr=537, a0=0x80000023d6) -> 38
[elf-egress] petition 0 -> 38 bytes
[elf-egress] 4 allowed, 4 rate-limited
[elf-egress] host says: {"stub":"axiom-x-egress","echo":true}
[workload] done: petitions=25 allowed=25 rate_limited_retries=19 failed=0
[init] process-lifecycle check: PASS
[kernel] reclamation check: PASS (frames in use after each round: 283)
```

Proxy, same boot (`evidence/proxy-egress-stub-20261029.log`):

```text
[egress-proxy] petition sha256 d1bba6bee60f1d77.. -> 38B response sha256 e8332cfb5642e5e1..
[egress-proxy] petition sha256 198f50b381283918.. -> 38B response sha256 e8332cfb5642e5e1..
```

87 kernel response lines, 87 proxy lines, pairwise equal (hash and
length), including the request hashes. Three rounds × (4 probes the
bucket allowed + 25 workload petitions) = 87. The four rate-limit
refusals (`-EAGAIN`) never reached the proxy and have no response record.

`ledger-tool verify` on the scratch ledger (public key above):

```text
PASS: 2495 records verified from genesis (1 BOOT records, 30 denies, 87 egress responses); latest and 11 archived checkpoints signed by 0b3dcb49…
```

Every `EGRESS_RESPONSE` is `38B sha256 e8332cfb5642e5e1..`. Record 121 is
the petition (`CONTRACT_ENFORCE`, nr 537, pid 10, result 38). Record 122
is the response (kind 103, same pid, subject 38). All 87 response records
sit immediately after that petition's syscall record.

Logs: `serial-egress-stub-20261029.log`, `proxy-egress-stub-20261029.log`.

## Live gateway (still for Jon)

Ten chat petitions, none refused, one round. `elf-egress` stays quiet
(`EGRESS_PROBES=0`); the self-test's other two rounds stay off
(`EGRESS_ROUNDS=1`). Without those, a boot is 3 × (25 chats + the probes
the bucket allows).

```bash
EGRESS_PROXY=1 EGRESS_GATEWAY_KEY='<key>' PROXY_UPSTREAM='http://<llm-gateway>' EGRESS_BURST=10 EGRESS_PETITIONS=10 EGRESS_PROBES=0 EGRESS_ROUNDS=1 sh ./qemu-boot.sh 180
```

Compare `[egress] pid N response sha256` in `evidence/serial-mb2.log` with
`response sha256` in the `evidence/proxy-*.log` from that boot. Do not
commit `evidence/ledger.key`.
