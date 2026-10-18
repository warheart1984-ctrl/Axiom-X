#!/bin/sh
# Crash-consistency test for the persistent ledger. Run inside WSL (Ubuntu)
# after building the kernel, user programs and ledger key (see qemu-boot.sh):
#
#   ./crash-test.sh <crash-point> <base-image>
#
# Copies <base-image>, boots it with axiom.crash=<crash-point> (the kernel
# halts mid-save, simulating power loss), then boots the same image
# normally and shows what recovery did. Logs go to evidence/ as
# journal-crash-<point>-{crash,recovery}-serial-2026-10-17.log; the crashed
# and recovered image is evidence/crash-<point>.img (git-ignored).
# Crash points: after-journal, torn-target, before-superblock, torn-superblock.
set -eu
cd "$(dirname "$0")"
P="$1"
BASE="$2"
IMG="evidence/crash-$P.img"
cp "$BASE" "$IMG"
cp "$IMG" "evidence/crash-$P-before-recovery.img.tmp"

KERNEL_CMDLINE="axiom.crash=$P" LEDGER_DISK="$IMG" sh ./qemu-boot.sh 45 >/dev/null 2>&1 || true
cp evidence/serial-mb2.log "evidence/journal-crash-$P-crash-serial-2026-10-17.log"
echo "===== CRASH BOOT ($P)"
grep -E '\[ledger\] (TEST|CRASH|persisted|boot)' evidence/serial-mb2.log | tr -d '\r'
cp "$IMG" "evidence/crash-$P-crashed.img"

LEDGER_DISK="$IMG" sh ./qemu-boot.sh 60 >/dev/null 2>&1 || true
cp evidence/serial-mb2.log "evidence/journal-crash-$P-recovery-serial-2026-10-17.log"
echo "===== RECOVERY BOOT ($P)"
grep -E '\[ledger\]|ledger audit|lifecycle check|reclamation' evidence/serial-mb2.log | tr -d '\r'
echo "kernel_exc=$(grep 'check_exception' -A1 evidence/qemu-mb2.log | grep ' v=' | grep -vc 'cpl=3' || true)"
rm -f "evidence/crash-$P-before-recovery.img.tmp"
