#!/bin/sh
# Boot the Axiom-X kernel in QEMU via a GRUB multiboot2 ISO and capture the
# serial console as evidence. Run inside WSL (Ubuntu) after building:
#   cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel \
#       --no-default-features --features freestanding
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
cat > evidence/iso/boot/grub/grub.cfg <<'EOF'
set timeout=0
set default=0
menuentry "Axiom-X" {
    multiboot2 /boot/kernel.elf
    boot
}
EOF
grub-file --is-x86-multiboot2 evidence/iso/boot/kernel.elf
grub-mkrescue -o evidence/axiom-x-dbg.iso evidence/iso >/dev/null 2>&1

timeout "$SECS" qemu-system-x86_64 -cdrom evidence/axiom-x-dbg.iso \
    -serial file:evidence/serial-mb2.log -display none -no-reboot \
    -d int,cpu_reset -D evidence/qemu-mb2.log -m 256M || true

echo "=== serial ==="
tr -d '\r' < evidence/serial-mb2.log
echo
echo "=== first CPU exceptions ==="
grep -n 'check_exception\|Triple' -A1 evidence/qemu-mb2.log | grep -v 'v=[2-9a-f][0-9a-f] ' | head -8 || true
