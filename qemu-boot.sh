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

cat > evidence/iso/boot/grub/grub.cfg <<EOF
set timeout=0
set default=0
menuentry "Axiom-X" {
    multiboot2 /boot/kernel.elf
${MODULES}    boot
}
EOF
echo "=== grub.cfg ==="
cat evidence/iso/boot/grub/grub.cfg
grub-file --is-x86-multiboot2 evidence/iso/boot/kernel.elf
grub-mkrescue -o evidence/axiom-x-dbg.iso evidence/iso >/dev/null 2>&1

# Persistent evidence ledger: a raw disk on the primary IDE master (the
# kernel's ATA driver). Reused across boots so the chain continues; delete
# the image (or set LEDGER_DISK) to start a fresh chain.
LEDGER_DISK="${LEDGER_DISK:-evidence/ledger.img}"
[ -f "$LEDGER_DISK" ] || truncate -s 4M "$LEDGER_DISK"

timeout "$SECS" qemu-system-x86_64 -cdrom evidence/axiom-x-dbg.iso -boot d \
    -drive "file=$LEDGER_DISK,format=raw,if=ide,index=0,media=disk,cache=writethrough" \
    -serial file:evidence/serial-mb2.log -display none -no-reboot \
    -d int,cpu_reset -D evidence/qemu-mb2.log -m 256M || true

echo "=== serial ==="
tr -d '\r' < evidence/serial-mb2.log
echo
echo "=== first CPU exceptions ==="
grep -n 'check_exception\|Triple' -A1 evidence/qemu-mb2.log | grep -v 'v=[2-9a-f][0-9a-f] ' | head -8 || true
