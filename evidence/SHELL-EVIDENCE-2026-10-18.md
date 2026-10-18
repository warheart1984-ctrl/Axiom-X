# Axiom-X clock, console and shell — 2026-10-18

**Claim:** Axiom-X has a usable interactive shell:
- a user-space program (`elf-shell`) that reads the console through a
  governed `read` syscall, from the serial port or the PS/2 keyboard;
- output on serial and on the VM's VGA text screen;
- it starts, observes and reaps programs, under the same rights checks and
  evidence ledger as everything else.

The kernel also keeps real time: the CMOS RTC is the wall clock, and the
TSC, calibrated against RTC second edges, is the monotonic clock.

**Status:** `partial`. Demonstrated in QEMU:
- serial and PS/2 keyboard input, and the VGA screen;
- every shell command, including a rights denial and least-privilege runs;
- the shell restarting after `exit`;
- the self-tests still passing before the shell starts;
- the RTC and TSC clocks, plus a PIT vs TSC vs RTC comparison.

Not demonstrated:
- the shell on Hyper-V (the clock-less kernel was the one tested there);
- a kernel line discipline, Ctrl-C or job control;
- killing processes;
- a file system (programs still come from boot modules).

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG |
| kernel.elf | sha256 `52f95d5f091e0f9982a56a552ffa8ad00568269d91346b6df83cd539598e3ac4` |
| elf-shell | sha256 `3c8dd872b6f7b57eaf365330ac0c6ba7834304ad0619ae3af11eafe4c4570406` |

## Reproduce

```bash
# scripted session: commands over serial, then PS/2 keys + VGA screenshot
KERNEL_CMDLINE=axiom.selftest=off SHELL_INPUT=evidence/shell-session-input.txt sh ./qemu-boot.sh 75 &
python3 vm-keys.py /tmp/axiomx-mon.sock 45 'ps' evidence/shell-screen-2026-10-18.png
# interactive, in your own terminal (Ctrl-C to stop):
LIVE=1 KERNEL_CMDLINE=axiom.selftest=off sh ./qemu-boot.sh
```

## Shell session (`shell-session-serial-2026-10-18.log`, input `shell-session-input.txt`)

```text
axiom> date
2026-10-18 04:27:36 (RTC time, no time zone)
axiom> uptime
up 0h 00m 04.587s
axiom> rights
pid 2: rights SRPDE (0x210580)  S=send R=recv P=spawn D=delegate E=evidence
axiom> ps
  PID PARENT STATE    RIGHTS NAME
    1      0 ready    all    kernel-init
    2      0 running  SRPDE  elf-shell
axiom> run elf-crash
[pid 4 'elf-crash' killed by signal 11]
axiom> run elf-noperm -send          <- started with no rights at all
[pid 5 'elf-noperm' exited with code 0]   (both of its calls refused)
axiom> run elf-audit                 <- SEND only
[audit] cannot read the ledger: -1 (EPERM)
axiom> run elf-audit +evidence
[audit] ledger audit: PASS
axiom> run elf-bad-wx
run elf-bad-wx: -8 (ENOEXEC)
axiom> ledger
ledger: 6150 records; newest 200 verified; head 79973c2a9d686e81...
axiom> exit
bye
[kernel] shell exited; starting a new one
axiom> ps                            <- typed on the emulated PS/2 keyboard
    8      0 running  SRPDE  elf-shell
```

`shell-screen-2026-10-18.png` is QEMU's `screendump` of the VM's VGA text
screen at the end of that session. It shows the same text, scrolled, as a
VM window displays it.

## Clock

- The RTC matched the host's UTC time. The TSC calibrated at 4005 MHz on the
  4.0 GHz FX-8350 in an untraced run.
- In an untraced 88 s QEMU run, the PIT showed 82.4 s, the TSC 81.4 s and
  the RTC 81 s since the time origin. The ~6.5 s before the origin is BIOS,
  GRUB and calibration, and the three agree within about 1%.
- With QEMU's `-d int` tracing the emulator stalls: the PIT then loses about
  25% of its ticks and calibration reads ~3704 MHz. This is a tracing
  artifact. Traced logs therefore show skewed TSC rates.
- BOOT records now carry the boot's RTC time (`rights` field), and
  `ledger-tool` lists them:

```text
BOOT record #3797: boot 4, 2026-10-18 04:13:43 (RTC, no time zone), resumed 3797 records
BOOT record #5232: boot 6, 2026-10-18 04:27:32 (RTC, no time zone), resumed 5232 records
BOOT record #6403: boot 7, 2026-10-18 04:29:19 (RTC, no time zone), resumed 6403 records
PASS: 7842 records verified from genesis (6 BOOT records, 55 denies); latest and 27 archived checkpoints signed by 5b82c607...5f8a
```

## Bugs found by the first session (fixed)

1. **First input byte lost** (`help` arrived as `elp`). The boot UART setup
   reset the receive FIFO and discarded a byte that was already received.
   That byte is now queued first.
2. **Persistence stopped under load.** One audit appended more than 1024
   records within the 5 s save interval, so records left the in-memory ring
   unsaved, and persistence switched itself off as designed (fail-stop).
   - Saves now also trigger when 256 records are waiting, in the shell loop
     and the self-test loop. The ring grew to 4096.
   - **That boot (5) lost its activity**, and the ledger above shows the gap:
     boot 4 is followed by boot 6. The chain itself stayed valid.
3. **No way to run a program without rights.** `run` always granted SEND.
   `-send` now removes it.

## Known limitations

- When the shell exits, input already queued after the `exit` line is
  discarded (typeahead).
- Kernel messages ("loaded ELF ...") interleave with shell output. The
  per-syscall trace is off once the shell runs (`axiom.trace=on` keeps it).
- US keyboard layout only. No Ctrl or Alt combinations, arrow keys or
  history.
