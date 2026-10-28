#!/bin/sh
# Boot the Axiom-X kernel in QEMU via a GRUB multiboot2 ISO and capture the
# serial console as evidence. Run inside WSL (Ubuntu) after building:
#   cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel \
#       --no-default-features --features freestanding
#   (cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false \
#       cargo build --release --target x86_64-unknown-none)
# (LTO is off for user programs: .cargo/config.toml's code-model=large
# conflicts with the prebuilt core's bitcode.)
# Requires: qemu-system-x86, grub-pc-bin, grub-common, xorriso, mtools.
#
# Usage: ./qemu-boot.sh [seconds]   (default 15)
# Output: evidence/serial-mb2.log, evidence/qemu-mb2.log (int + cpu_reset trace)
set -eu
cd "$(dirname "$0")"
SECS="${1:-15}"
ulimit -c 0
mkdir -p evidence/tmp evidence/iso/boot/grub
export TMPDIR="$PWD/evidence/tmp"

cp target/x86_64-unknown-none/debug/kernel evidence/iso/boot/kernel.elf

# User programs (built separately in axiom-x-user, see its Cargo.toml) are
# passed to the kernel as multiboot2 modules named after the binary.
USER_BIN=axiom-x-user/target/x86_64-unknown-none/release
rm -f evidence/iso/boot/elf-*
MODULES=""
for f in "$USER_BIN"/elf-*; do
    case "$f" in *.d) continue ;; esac
    [ -f "$f" ] || continue
    name=$(basename "$f")
    cp "$f" "evidence/iso/boot/$name"
    MODULES="$MODULES    module2 /boot/$name $name
"
done

# Negative fixture: elf-hello with its first program header (the text
# PT_LOAD at e_phoff = 64) patched to RWX (p_flags at 64 + 4 = 7). The
# loader must reject it (W^X) without creating a process.
if [ -f "$USER_BIN/elf-hello" ]; then
    cp "$USER_BIN/elf-hello" evidence/iso/boot/elf-bad-wx
    printf '\007' | dd of=evidence/iso/boot/elf-bad-wx bs=1 seek=68 conv=notrunc 2>/dev/null
    MODULES="$MODULES    module2 /boot/elf-bad-wx elf-bad-wx
"
fi

# Ledger signing key: a 32-byte Ed25519 seed passed as the `ledger.key`
# module (the kernel copies it, then wipes the module's memory). Generated
# on first use; LEDGER_KEY=none boots without a key (unsigned checkpoints).
# Publish the public key (`ledger-tool pubkey <key>`), never the seed.
LEDGER_KEY="${LEDGER_KEY:-evidence/ledger.key}"
rm -f evidence/iso/boot/ledger.key
if [ "$LEDGER_KEY" != "none" ]; then
    [ -f "$LEDGER_KEY" ] || head -c 32 /dev/urandom > "$LEDGER_KEY"
    cp "$LEDGER_KEY" evidence/iso/boot/ledger.key
    MODULES="$MODULES    module2 /boot/ledger.key ledger.key
"
fi

cat > evidence/iso/boot/grub/grub.cfg <<EOF
set timeout=0
set default=0
menuentry "Axiom-X" {
    multiboot2 /boot/kernel.elf ${KERNEL_CMDLINE:-}
${MODULES}    boot
}
EOF
echo "=== grub.cfg ==="
cat evidence/iso/boot/grub/grub.cfg
grub-file --is-x86-multiboot2 evidence/iso/boot/kernel.elf
ISO="${ISO_OUT:-evidence/axiom-x-dbg.iso}"
grub-mkrescue -o "$ISO" evidence/iso >/dev/null 2>&1

# ISO_ONLY=1: just build the ISO (e.g. ISO_OUT=evidence/axiom-x-hyperv.iso
# for hyperv-run.ps1, with its own KERNEL_CMDLINE baked into grub.cfg).
if [ "${ISO_ONLY:-0}" = 1 ]; then
    echo "built $ISO (kernel command line: '${KERNEL_CMDLINE:-}')"
    exit 0
fi

# Persistent evidence ledger: a raw disk on the primary IDE master (the
# kernel's ATA driver). Reused across boots so the chain continues; delete
# the image (or set LEDGER_DISK) to start a fresh chain.
LEDGER_DISK="${LEDGER_DISK:-evidence/ledger.img}"
[ -f "$LEDGER_DISK" ] || truncate -s 4M "$LEDGER_DISK"

# File system (AXFS): a raw disk on the primary IDE slave. A blank image is
# formatted on first boot; its root hash is anchored in the ledger above,
# so keep each FS image with the ledger it was used with.
FS_DISK="${FS_DISK:-evidence/fs.img}"
[ -f "$FS_DISK" ] || truncate -s 16M "$FS_DISK"

# SHELL_INPUT=<file>: scripted session. The file is fed to COM1 (the
# shell's console), output goes to evidence/serial-mb2.log, and a QEMU
# monitor socket (/tmp/axiomx-mon.sock: Unix sockets cannot live on the
# Windows drive under WSL) lets vm-keys.py press keys on the
# PS/2 keyboard and screenshot the VGA screen. Runs for $SECS seconds.
if [ -n "${SHELL_INPUT:-}" ]; then
    rm -f /tmp/axiomx-mon.sock
    timeout "$SECS" qemu-system-x86_64 -cdrom "$ISO" -boot d \
        -drive "file=$LEDGER_DISK,format=raw,if=ide,index=0,media=disk,cache=writethrough" \
        -drive "file=$FS_DISK,format=raw,if=ide,index=1,media=disk,cache=writethrough" \
        -serial stdio -serial tcp:127.0.0.1:4445,server,nowait -display none -no-reboot -m 256M \
        -monitor unix:/tmp/axiomx-mon.sock,server,nowait \
        < "$SHELL_INPUT" > evidence/serial-mb2.log 2>evidence/tmp/qemu-stderr.log || true
    exit 0
fi

# LIVE=1: show the kernel's serial console on this terminal as it boots
# (no interrupt trace, no log file). Runs until Ctrl-C: under `timeout`
# QEMU either stops on SIGTTIN (it reads the terminal for -serial stdio)
# or, with --foreground, was not reliably ended once it owned the tty.
if [ "${LIVE:-0}" = 1 ]; then
    echo "=== booting Axiom-X (live serial console; press Ctrl-C to stop the VM) ==="
    qemu-system-x86_64 -cdrom "$ISO" -boot d \
        -drive "file=$LEDGER_DISK,format=raw,if=ide,index=0,media=disk,cache=writethrough" \
        -drive "file=$FS_DISK,format=raw,if=ide,index=1,media=disk,cache=writethrough" \
        -serial stdio -display none -no-reboot -m 256M || true
    echo
    echo "=== VM stopped ==="
    exit 0
fi

# Preserve the previous boot's evidence instead of clobbering it.
if [ -f evidence/serial-mb2.log ]; then
    mv evidence/serial-mb2.log "evidence/serial-mb2-$(date +%Y%m%d-%H%M%S).log"
fi

timeout "$SECS" qemu-system-x86_64 -cdrom "$ISO" -boot d \
    -drive "file=$LEDGER_DISK,format=raw,if=ide,index=0,media=disk,cache=writethrough" \
    -drive "file=$FS_DISK,format=raw,if=ide,index=1,media=disk,cache=writethrough" \
    -serial file:evidence/serial-mb2.log -serial tcp:127.0.0.1:4445,server,nowait -display none -no-reboot \
    -d int,cpu_reset -D evidence/qemu-mb2.log -m 256M || true

echo "=== serial ==="
tr -d '\r' < evidence/serial-mb2.log
echo
echo "=== first CPU exceptions ==="
grep -n 'check_exception\|Triple' -A1 evidence/qemu-mb2.log | grep -v 'v=[2-9a-f][0-9a-f] ' | head -8 || true
